#include "FileMonitor.hpp"
#include "ConfigManager.hpp"
#include "FileScanner.hpp"
#include "IntegrityChecker.hpp"
#include "Support.hpp"
#include <array>
#include <chrono>
#include <csignal>
#include <iostream>
#include <poll.h>
#include <set>
#include <sys/inotify.h>

namespace audit {
namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
class Signals {
    struct sigaction oldInt_{}, oldTerm_{};
public:
    Signals() {
        stopping = 0;
        struct sigaction action{};
        action.sa_handler = stop;
        ::sigemptyset(&action.sa_mask);
        ::sigaction(SIGINT, &action, &oldInt_);
        ::sigaction(SIGTERM, &action, &oldTerm_);
    }
    ~Signals() { ::sigaction(SIGINT, &oldInt_, nullptr); ::sigaction(SIGTERM, &oldTerm_, nullptr); }
};
void print(const std::vector<Event>& events) {
    for (const auto& event : events)
        std::cout << '[' << event.type << "] " << displayPath(event.path) << ' ' << event.detail << '\n';
    std::cout.flush();
}
void append(const fs::path& state, const std::vector<Event>& events) {
    if (events.empty()) return;
    // Keep the batch in memory until cooperating commands release the lock.
    // Retry interrupted acquisition even during shutdown, so this batch is saved.
    StateLock lock(state, "lock", true);
    AuditLogger(state / "audit.log").append(events);
    print(events);
}
void refreshWatches(int fd, const fs::path& root, std::map<int, std::string>& watches) {
    std::set<int> live;
    const auto add = [&](const fs::path& path, const std::string& relative) {
        const int wd = ::inotify_add_watch(fd, path.c_str(), IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
            IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW);
        if (wd < 0) throw systemError("Watch directory " + displayPath(path.string()));
        live.insert(wd);
        watches[wd] = relative;
    };
    add(root, "");
    for (const auto& entry : fs::recursive_directory_iterator(root))
        if (fs::is_directory(entry.symlink_status())) add(entry.path(), entry.path().lexically_relative(root).generic_string());
    for (auto it = watches.begin(); it != watches.end();) {
        if (!live.count(it->first)) { ::inotify_rm_watch(fd, it->first); it = watches.erase(it); }
        else ++it;
    }
}
struct Move { std::string from, to; bool directory = false; };
bool atOrBelow(const std::string& path, const std::string& parent) {
    return path == parent || path.rfind(parent + '/', 0) == 0;
}
}
void FileMonitor::run(const Baseline& baseline, const fs::path& state, int durationSeconds) {
    StateLock singleMonitor(state, "monitor.lock");
    Signals signals;
    Fd inotify(::inotify_init1(IN_NONBLOCK | IN_CLOEXEC));
    if (inotify.get() < 0) throw systemError("Initialize inotify");
    std::map<int, std::string> watches;
    refreshWatches(inotify.get(), baseline.root, watches);
    Snapshot previous = FileScanner().scan(baseline.root);
    auto initial = IntegrityChecker::compare(baseline.files, previous);
    initial.insert(initial.begin(), Event{"MONITOR_START", baseline.root.string(), "-", "-", "recursive inotify; periodic reconciliation=2s"});
    append(state, initial);
    std::cout << "Monitoring " << displayPath(baseline.root.string()) << "; press Ctrl+C to stop.\n" << std::flush;
    const auto started = std::chrono::steady_clock::now();
    auto lastScan = started;
    bool dirty = false;
    while (!stopping) {
        auto now = std::chrono::steady_clock::now();
        if (durationSeconds && now - started >= std::chrono::seconds(durationSeconds)) break;
        pollfd descriptor{inotify.get(), POLLIN, 0};
        const auto ready = ::poll(&descriptor, 1, 200);
        if (ready < 0) { if (errno == EINTR) continue; throw systemError("Poll inotify"); }
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) throw std::runtime_error("Inotify descriptor failed");
        std::map<std::uint32_t, Move> pendingMoves;
        std::vector<Move> moves; // Completion order, not numerical cookie order.
        bool topology = false;
        bool overflow = false;
        if (ready > 0) {
            // Allow the two halves of an ordinary rename to enter the queue.
            ::poll(nullptr, 0, 40);
            alignas(inotify_event) std::array<char, 65536> buffer{};
            std::size_t consumed = 0;
            while (consumed < 4 * 1024 * 1024) {
                const auto bytes = ::read(inotify.get(), buffer.data(), buffer.size());
                if (bytes < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN) break;
                    throw systemError("Read inotify events");
                }
                if (bytes == 0) break;
                consumed += static_cast<std::size_t>(bytes);
                for (std::size_t offset = 0; offset < static_cast<std::size_t>(bytes);) {
                    const auto* event = reinterpret_cast<const inotify_event*>(buffer.data() + offset);
                    offset += sizeof(inotify_event) + event->len;
                    if (event->mask & IN_Q_OVERFLOW) { overflow = true; dirty = true; topology = true; continue; }
                    const auto found = watches.find(event->wd);
                    if (found == watches.end()) continue;
                    if (event->mask & IN_IGNORED) { watches.erase(found); topology = true; dirty = true; continue; }
                    if (found->second.empty() && (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT)))
                        throw std::runtime_error("Protected root was moved, removed, or unmounted");
                    std::string path = found->second;
                    bool uncertainPath = false;
                    for (const auto& [cookie, pending] : pendingMoves) {
                        (void)cookie;
                        if (pending.directory && atOrBelow(path, pending.from)) uncertainPath = true;
                    }
                    if (event->len && event->name[0]) { if (!path.empty()) path += '/'; path += event->name; }
                    dirty = true;
                    if (event->mask & (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF)) topology = true;
                    // A directory between FROM and TO has no reliable watched path.
                    // Snapshot reconciliation still accounts for its final contents.
                    if (uncertainPath) continue;
                    if (event->cookie && (event->mask & (IN_MOVED_FROM | IN_MOVED_TO))) {
                        if (event->mask & IN_MOVED_FROM) {
                            pendingMoves[event->cookie] = {path, "", (event->mask & IN_ISDIR) != 0};
                        } else {
                            const auto pending = pendingMoves.find(event->cookie);
                            if (pending == pendingMoves.end()) continue;
                            Move move = pending->second;
                            pendingMoves.erase(pending);
                            move.to = path;
                            if (move.directory) {
                                // Later child events in this same read use the new path.
                                for (auto& [wd, watchedPath] : watches) {
                                    (void)wd;
                                    if (atOrBelow(watchedPath, move.from))
                                        watchedPath = move.to + watchedPath.substr(move.from.size());
                                }
                            }
                            moves.push_back(std::move(move));
                        }
                    }
                }
            }
        }
        now = std::chrono::steady_clock::now();
        if (!dirty && now - lastScan < std::chrono::seconds(2)) continue;
        std::vector<Event> events;
        if (overflow) append(state, {{"QUEUE_OVERFLOW", baseline.root.string(), "-", "-", "Events lost; rebuilding watches and rescanning"}});
        Snapshot current;
        try {
            // Periodic refresh also discovers directories whose creation event was lost.
            if (topology || now - lastScan >= std::chrono::seconds(2)) refreshWatches(inotify.get(), baseline.root, watches);
            current = FileScanner().scan(baseline.root);
        } catch (const std::exception& error) {
            append(state, {{"SCAN_ERROR", baseline.root.string(), "-", "-", error.what()}});
            dirty = true;
            lastScan = now;
            if (!fs::is_directory(baseline.root)) throw;
            continue;
        }
        Snapshot adjusted = previous;
        if (!overflow) for (std::size_t i = 0; i < moves.size(); ++i) {
            const auto& move = moves[i];
            const auto old = adjusted.find(move.from), next = current.find(move.to);
            bool finalDestination = true;
            for (std::size_t j = i + 1; j < moves.size(); ++j) {
                if (atOrBelow(move.to, moves[j].from) || atOrBelow(move.to, moves[j].to) ||
                    atOrBelow(moves[j].from, move.to) || atOrBelow(moves[j].to, move.to))
                    finalDestination = false;
            }
            std::string detail = "from=" + displayPath(move.from);
            const auto replaced = adjusted.find(move.to);
            if (replaced != adjusted.end()) detail += " replaced_hash=" + replaced->second.hash;
            events.push_back({"MOVE", move.to, old == adjusted.end() ? "-" : old->second.hash,
                !finalDestination || next == current.end() ? "-" : next->second.hash, detail});
            std::vector<std::pair<std::string, FileRecord>> relocated;
            for (auto it = adjusted.begin(); it != adjusted.end();) {
                if (it->first == move.from || (move.directory && it->first.rfind(move.from + '/', 0) == 0)) {
                    relocated.emplace_back(move.to + it->first.substr(move.from.size()), it->second);
                    it = adjusted.erase(it);
                } else ++it;
            }
            for (const auto& [path, record] : relocated) adjusted.insert_or_assign(path, record);
        }
        auto differences = IntegrityChecker::compare(adjusted, current);
        events.insert(events.end(), differences.begin(), differences.end());
        append(state, events);
        previous = std::move(current);
        dirty = false;
        lastScan = now;
    }
    append(state, {{"MONITOR_STOP", baseline.root.string(), "-", "-", "orderly shutdown"}});
}
}
