// Black-box Linux tests. No application implementation is linked into this harness.
#include <openssl/evp.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
std::string binary;
void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
void systemCheck(bool ok, const std::string& action) {
    if (!ok) throw std::runtime_error(action + ": " + std::strerror(errno));
}
void contains(const std::string& text, const std::string& part) {
    require(text.find(part) != std::string::npos, "Missing [" + part + "] in:\n" + text);
}
class Fd {
    int fd_;
public:
    explicit Fd(int fd) : fd_(fd) { systemCheck(fd >= 0, "Open descriptor"); }
    ~Fd() { ::close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
};
std::string readFile(const fs::path& path) {
    Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    std::string bytes;
    char buffer[65536];
    for (;;) {
        const auto n = ::read(fd.get(), buffer, sizeof buffer);
        if (n < 0 && errno == EINTR) continue;
        systemCheck(n >= 0, "Read " + path.string());
        if (!n) return bytes;
        bytes.append(buffer, static_cast<std::size_t>(n));
    }
}
void writeFile(const fs::path& path, const std::string& bytes) {
    Fd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto n = ::write(fd.get(), bytes.data() + offset, bytes.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        systemCheck(n > 0, "Write " + path.string());
        offset += static_cast<std::size_t>(n);
    }
}
void mode(const fs::path& path, mode_t value) {
    systemCheck(::chmod(path.c_str(), value) == 0, "chmod " + path.string());
}
struct stat info(const fs::path& path) {
    struct stat result{};
    systemCheck(::stat(path.c_str(), &result) == 0, "stat " + path.string());
    return result;
}
void removeFile(const fs::path& path) {
    systemCheck(::unlink(path.c_str()) == 0, "unlink " + path.string());
}
void moveFile(const fs::path& from, const fs::path& to) {
    systemCheck(::rename(from.c_str(), to.c_str()) == 0, "rename " + from.string());
}
std::vector<std::string> split(const std::string& bytes, char delimiter) {
    std::vector<std::string> result;
    std::size_t start = 0;
    for (;;) {
        const auto end = bytes.find(delimiter, start);
        result.push_back(bytes.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) return result;
        start = end + 1;
    }
}
std::string hex(const std::string& bytes) {
    const char* digits = "0123456789abcdef";
    std::string result;
    for (unsigned char c : bytes) { result += digits[c >> 4]; result += digits[c & 15]; }
    return result;
}
std::string unhex(const std::string& bytes) {
    require(bytes.size() % 2 == 0, "Odd hex length");
    auto nibble = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("Invalid hex digit");
    };
    std::string result;
    for (std::size_t i = 0; i < bytes.size(); i += 2)
        result += static_cast<char>((nibble(bytes[i]) << 4) | nibble(bytes[i + 1]));
    return result;
}
// Independent expectation helper: never calls audit::HashManager.
std::string sha256(const std::string& bytes) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    require(ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx.get(), bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx.get(), digest, &length) == 1, "Expected SHA-256 calculation failed");
    return hex(std::string(reinterpret_cast<char*>(digest), length));
}
std::string replace(std::string bytes, const std::string& old, const std::string& value,
                    bool all = true) {
    std::size_t at = 0;
    while ((at = bytes.find(old, at)) != std::string::npos) {
        bytes.replace(at, old.size(), value);
        if (!all) break;
        at += value.size();
    }
    return bytes;
}

// Owns and always reaps its child, including when a test throws.
class Child {
    pid_t pid_ = -1;
    std::optional<int> status_;
public:
    Child(const std::vector<std::string>& arguments, int output, int error) {
        std::vector<char*> argv;
        for (const auto& arg : arguments) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        pid_ = ::fork();
        systemCheck(pid_ >= 0, "fork");
        if (pid_ == 0) {
            if (::dup2(output, STDOUT_FILENO) < 0 || ::dup2(error, STDERR_FILENO) < 0) _exit(126);
            ::execv(argv[0], argv.data());
            const char message[] = "execv audit failed\n";
            const auto written = ::write(STDERR_FILENO, message, sizeof(message) - 1);
            if (written != static_cast<ssize_t>(sizeof(message) - 1)) _exit(127);
            _exit(127);
        }
    }
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    ~Child() {
        if (!status_) {
            ::kill(pid_, SIGCONT);
            ::kill(pid_, SIGKILL);
            int status;
            while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        }
    }
    pid_t pid() const { return pid_; }
    bool running() {
        if (status_) return false;
        int status;
        pid_t result;
        do { result = ::waitpid(pid_, &status, WNOHANG); } while (result < 0 && errno == EINTR);
        systemCheck(result >= 0, "waitpid");
        if (result == pid_) status_ = status;
        return !status_;
    }
    void signal(int value) { systemCheck(::kill(pid_, value) == 0, "Signal child"); }
    int wait(std::chrono::seconds timeout) {
        const auto deadline = Clock::now() + timeout;
        while (running()) {
            require(Clock::now() < deadline, "Child process timed out");
            std::this_thread::sleep_for(10ms);
        }
        return WIFEXITED(*status_) ? WEXITSTATUS(*status_) : -WTERMSIG(*status_);
    }
};
struct Result { int code; std::string out, err; };
Result run(const std::vector<std::string>& args) {
    int outPipe[2], errPipe[2];
    systemCheck(::pipe2(outPipe, O_CLOEXEC) == 0, "stdout pipe");
    Fd outRead(outPipe[0]), outWrite(outPipe[1]);
    systemCheck(::pipe2(errPipe, O_CLOEXEC) == 0, "stderr pipe");
    Fd errRead(errPipe[0]), errWrite(errPipe[1]);
    Child child(args, outWrite.get(), errWrite.get());
    // Parent write ends stay open until this function returns; drain available
    // bytes rather than waiting for EOF, and drain once more after child exit.
    for (int fd : {outRead.get(), errRead.get()})
        systemCheck(::fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "Nonblocking capture");
    Result result{};
    auto drain = [](int fd, std::string& bytes) {
        char buffer[65536];
        for (;;) {
            const auto n = ::read(fd, buffer, sizeof buffer);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            systemCheck(n >= 0, "Read captured output");
            if (!n) return;
            bytes.append(buffer, static_cast<std::size_t>(n));
        }
    };
    const auto deadline = Clock::now() + 15s;
    for (;;) {
        drain(outRead.get(), result.out);
        drain(errRead.get(), result.err);
        if (!child.running()) break;
        require(Clock::now() < deadline, "CLI timed out after 15 seconds\n" + result.out + result.err);
        pollfd descriptors[] = {{outRead.get(), POLLIN, 0}, {errRead.get(), POLLIN, 0}};
        const int ready = ::poll(descriptors, 2, 20);
        systemCheck(ready >= 0 || errno == EINTR, "poll capture");
    }
    drain(outRead.get(), result.out);
    drain(errRead.get(), result.err);
    result.code = child.wait(0s);
    return result;
}
struct Event { std::string type, path, oldHash, newHash, detail; };
class Fixture {
public:
    fs::path base, root, state;
    Fixture() {
        char pattern[] = "/tmp/fia-test-XXXXXX";
        const char* directory = ::mkdtemp(pattern);
        systemCheck(directory != nullptr, "mkdtemp");
        base = directory;
        root = base / "protected files";
        state = base / "state";
        try { fs::create_directory(root); writeFile(root / "alpha.txt", "original\n"); }
        catch (...) { std::error_code error; fs::remove_all(base, error); throw; }
    }
    ~Fixture() { std::error_code error; fs::remove_all(base, error); }
    std::string cli(std::vector<std::string> args, int code = 0, fs::path alternate = {}) {
        args.insert(args.begin(), binary);
        args.insert(args.end(), {"--state", (alternate.empty() ? state : alternate).string()});
        const auto result = run(args);
        require(result.code == code, "Expected exit " + std::to_string(code) + ", got " +
                std::to_string(result.code) + "\n" + result.out + result.err);
        return result.out + result.err;
    }
    std::string init() { return cli({"init", root.string()}); }
    std::vector<Event> records() const {
        auto lines = split(readFile(state / "audit.log"), '\n');
        std::vector<Event> result;
        for (std::size_t i = 1; i < lines.size(); ++i) {
            auto fields = split(lines[i], '\t');
            if (fields.size() == 10) result.push_back({fields[2], unhex(fields[3]),
                fields[4], fields[5], unhex(fields[6])});
        }
        return result;
    }
    void waitEvent(const std::string& type, std::optional<std::string> path = std::nullopt) const {
        const auto deadline = Clock::now() + 8s;
        while (Clock::now() < deadline) {
            for (const auto& event : records())
                if (event.type == type && (!path || event.path == *path)) return;
            std::this_thread::sleep_for(50ms);
        }
        throw std::runtime_error("Timed out waiting for " + type + " " + path.value_or("(any path)"));
    }
};
class Monitor {
    Fixture& fixture_;
    fs::path output_;
    Fd outputFd_;
public:
    Child child;
    explicit Monitor(Fixture& fixture) : fixture_(fixture), output_(fixture.base / "monitor.out"),
        outputFd_(::open(output_.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600)),
        child({binary, "monitor", "--state", fixture.state.string()}, outputFd_.get(), outputFd_.get()) {
        fixture_.waitEvent("MONITOR_START");
    }
    ~Monitor() {
        try { if (child.running()) { child.signal(SIGCONT); child.signal(SIGTERM); child.wait(8s); } }
        catch (...) {} // Child destructor provides the final kill/reap fallback.
    }
    void stop() {
        if (child.running()) { child.signal(SIGCONT); child.signal(SIGTERM); }
        require(child.wait(8s) == 0, "Monitor failed:\n" + readFile(output_));
    }
};
class Pause {
    Child& child_;
public:
    explicit Pause(Child& child) : child_(child) {
        child_.signal(SIGSTOP);
        int status;
        pid_t result;
        do { result = ::waitpid(child_.pid(), &status, WUNTRACED); } while (result < 0 && errno == EINTR);
        systemCheck(result == child_.pid(), "Wait for SIGSTOP");
        require(WIFSTOPPED(status), "Monitor did not stop");
    }
    ~Pause() { ::kill(child_.pid(), SIGCONT); }
};
class Lock {
    Fd fd_;
public:
    explicit Lock(const fs::path& path, bool nonblocking = false) :
        fd_(::open(path.c_str(), O_RDWR | O_CLOEXEC)) {
        int result;
        do { result = ::flock(fd_.get(), LOCK_EX | (nonblocking ? LOCK_NB : 0)); }
        while (result < 0 && errno == EINTR);
        systemCheck(result == 0, "flock");
    }
};
class RestoreMode {
    fs::path path_;
    mode_t mode_;
public:
    RestoreMode(fs::path path, mode_t value) : path_(std::move(path)), mode_(value) {}
    ~RestoreMode() { ::chmod(path_.c_str(), mode_); }
};
void waitStateLock(Child& child) {
    const auto deadline = Clock::now() + 5s;
    while (Clock::now() < deadline) {
        require(child.running(), "Monitor exited while waiting for state lock");
        if (readFile("/proc/" + std::to_string(child.pid()) + "/wchan").find("lock") != std::string::npos) return;
        std::this_thread::sleep_for(20ms);
    }
    throw std::runtime_error("Monitor did not block on the held state lock");
}
std::vector<Event> only(const std::vector<Event>& records, const std::string& type) {
    std::vector<Event> result;
    for (const auto& event : records) if (event.type == type) result.push_back(event);
    return result;
}
void noNewDeleted(const std::vector<Event>& records) {
    for (const auto& event : records)
        require(event.type != "NEW" && event.type != "DELETED", "Unexpected NEW/DELETED record");
}
// Continue all subcases even when one fails, as unittest.subTest does.
template<class Values, class Function>
void subcases(const Values& values, Function function) {
    std::string failures;
    for (const auto& value : values) {
        try { function(value); }
        catch (const std::exception& error) { failures += std::string(error.what()) + '\n'; }
    }
    require(failures.empty(), failures);
}

void test_scan_and_metadata(Fixture& f) {
    writeFile(f.root / "gone", "delete me");
    writeFile(f.root / "mode", "permission");
    writeFile(f.root / "touch", "mtime");
    f.init();
    contains(f.cli({"scan", "--all"}), "UNCHANGED");
    writeFile(f.root / "alpha.txt", "modified\n");
    removeFile(f.root / "gone");
    writeFile(f.root / "new\tline\nfile", std::string("\0\xff" "binary", 8));
    mode(f.root / "mode", 0400);
    auto metadata = info(f.root / "touch");
    timespec times[] = {metadata.st_atim, metadata.st_mtim};
    ++times[1].tv_sec;
    systemCheck(::utimensat(AT_FDCWD, (f.root / "touch").c_str(), times, 0) == 0, "utimensat");
    auto output = f.cli({"scan"}, 2);
    for (const auto* event : {"MODIFIED", "DELETED", "NEW", "PERMISSION_CHANGE", "METADATA_CHANGE"})
        contains(output, "[" + std::string(event) + "]");
    auto report = f.cli({"report"});
    contains(report, sha256("modified\n"));
    contains(report, "new\\x09line\\x0afile");
    f.cli({"verify-log"});
    contains(f.cli({"status"}), "Baseline files: 4");
    f.cli({"scan"}, 2);
}
void test_symlinks_special_files_and_binary_hash(Fixture& f) {
    systemCheck(::symlink("/etc/passwd", (f.root / "external").c_str()) == 0, "External symlink");
    systemCheck(::symlink(f.root.c_str(), (f.root / "loop").c_str()) == 0, "Loop symlink");
    systemCheck(::mkfifo((f.root / "fifo").c_str(), 0666) == 0, "mkfifo");
    std::string payload;
    for (int repeat = 0; repeat < 800; ++repeat)
        for (int byte = 0; byte < 256; ++byte) payload += static_cast<char>(byte);
    writeFile(f.root / "binary", payload);
    contains(f.init(), "2 files");
    contains(f.cli({"scan", "--all"}), sha256(payload));
}
void test_log_tampering_and_checkpoint(Fixture& f) {
    f.init(); f.cli({"scan"});
    auto log = f.state / "audit.log";
    auto original = readFile(log);
    auto output = f.cli({"verify-log"});
    const auto start = output.find("Log head: ");
    require(start != std::string::npos, "Missing log head");
    auto head = output.substr(start + 10);
    head.erase(head.find_last_not_of(" \r\n\t") + 1);
    f.cli({"verify-log", "--expect-head", head});
    auto edited = replace(original, "SCAN", "SCAM", false);
    writeFile(log, edited);
    contains(f.cli({"verify-log"}, 1), "invalid");
    f.cli({"scan"}, 1);
    require(readFile(log) == edited, "Broken log was changed by scan");
    writeFile(log, original.substr(0, original.size() - 1));
    f.cli({"verify-log"}, 1);
    const auto lastRecord = original.rfind('\n', original.size() - 2);
    writeFile(log, original.substr(0, lastRecord + 1));
    f.cli({"verify-log"});
    contains(f.cli({"verify-log", "--expect-head", head}, 1), "checkpoint");
    writeFile(log, original);
    auto lines = split(original, '\n');
    require(lines.size() == 4, "Unexpected original log record count");
    writeFile(log, lines[0] + '\n' + lines[2] + '\n' + lines[1] + '\n');
    f.cli({"verify-log"}, 1);
}
void test_baseline_corruption_and_binding(Fixture& f) {
    f.init();
    auto file = f.state / "baseline.dat";
    auto original = readFile(file);
    writeFile(file, replace(original, "FIA_BASELINE", "BAD_BASELINE"));
    contains(f.cli({"scan"}, 1), "checksum");
    auto payload = original.substr(0, original.rfind("CHECKSUM\t"));
    payload = replace(payload, sha256("original\n"), std::string(64, '0'));
    writeFile(file, payload + "CHECKSUM\t" + sha256(payload) + '\n');
    contains(f.cli({"scan"}, 1), "INIT");
}
void test_validation_and_locking(Fixture& f) {
    f.cli({"init", f.root.string()}, 1, f.root / "state");
    require(!fs::exists(f.root / "state"), "Nested state was created");
    f.init();
    auto original = readFile(f.state / "baseline.dat");
    f.cli({"init", f.root.string()}, 1);
    require(readFile(f.state / "baseline.dat") == original, "Re-init changed baseline");
    fs::create_directory(f.base / "other");
    f.cli({"scan", (f.base / "other").string()}, 1);
    f.cli({"scan", "--duration", "1"}, 1);
    f.cli({"monitor", "--duration", "0"}, 1);
    { Lock lock(f.state / "lock", true); contains(f.cli({"scan"}, 1), "busy"); }
    removeFile(f.state / "audit.log");
    f.cli({"verify-log"}, 1);
}
void test_empty_tree(Fixture& f) {
    removeFile(f.root / "alpha.txt");
    contains(f.init(), "0 files"); f.cli({"scan"});
}
void test_rapid_file_rename_chain(Fixture& f) {
    writeFile(f.root / "a", "AAA"); writeFile(f.root / "b", "BBB"); f.init();
    Monitor monitor(f);
    { Pause pause(monitor.child); moveFile(f.root / "a", f.root / "b"); moveFile(f.root / "b", f.root / "c"); }
    f.waitEvent("MOVE", "c"); monitor.stop();
    auto moves = only(f.records(), "MOVE");
    require(moves.size() == 2 && moves[0].path == "b" && moves[1].path == "c", "Wrong MOVE order");
    auto hash = sha256("AAA");
    require(moves[0].oldHash == hash && moves[1].oldHash == hash, "Wrong old MOVE hashes");
    require(moves[0].newHash == "-" && moves[1].newHash == hash, "Wrong new MOVE hashes");
    contains(moves[0].detail, "replaced_hash=" + sha256("BBB")); f.cli({"verify-log"});
}
void test_rapid_directory_then_child_rename(Fixture& f) {
    fs::create_directory(f.root / "d"); writeFile(f.root / "d/f", "child"); f.init();
    Monitor monitor(f);
    { Pause pause(monitor.child); moveFile(f.root / "d", f.root / "e"); moveFile(f.root / "e/f", f.root / "e/g"); }
    f.waitEvent("MOVE", "e/g");
    writeFile(f.root / "e/g", "still monitored"); f.waitEvent("MODIFIED", "e/g"); monitor.stop();
    auto records = f.records(); auto moves = only(records, "MOVE");
    require(moves.size() == 2 && moves[0].path == "e" && moves[1].path == "e/g", "Wrong directory/child MOVE order");
    require(moves[1].detail == "from=\"e/f\"", "Obsolete child source path");
    require(moves[1].oldHash == sha256("child") && moves[1].newHash == sha256("child"), "Wrong child hashes");
    noNewDeleted(records); f.cli({"verify-log"});
}
void test_single_file_rename_hashes(Fixture& f) {
    f.init(); Monitor monitor(f);
    moveFile(f.root / "alpha.txt", f.root / "renamed.txt");
    f.waitEvent("MOVE", "renamed.txt"); monitor.stop();
    auto moves = only(f.records(), "MOVE"); auto hash = sha256("original\n");
    require(moves.size() == 1, "Expected one MOVE");
    require(moves[0].path == "renamed.txt" && moves[0].detail == "from=\"alpha.txt\"" &&
        moves[0].oldHash == hash && moves[0].newHash == hash, "Wrong single-file MOVE fields");
}
void test_single_directory_rename_keeps_watch(Fixture& f) {
    fs::create_directory(f.root / "d"); writeFile(f.root / "d/f", "child"); f.init(); Monitor monitor(f);
    moveFile(f.root / "d", f.root / "e"); f.waitEvent("MOVE", "e");
    writeFile(f.root / "e/f", "updated"); f.waitEvent("MODIFIED", "e/f"); monitor.stop();
    auto records = f.records(); auto moves = only(records, "MOVE");
    require(moves.size() == 1, "Expected one directory MOVE");
    require(moves[0].path == "e" && moves[0].detail == "from=\"d\"", "Wrong directory MOVE fields");
    noNewDeleted(records);
}
void test_monitor_waits_for_state_lock(Fixture& f) {
    f.init(); Monitor monitor(f);
    { Lock lock(f.state / "lock"); writeFile(f.root / "alpha.txt", "change while state is busy");
      waitStateLock(monitor.child); require(only(f.records(), "MODIFIED").empty(), "Appended while lock held"); }
    f.waitEvent("MODIFIED", "alpha.txt"); require(monitor.child.running(), "Monitor exited after lock release");
    monitor.stop(); auto records = f.records(); auto modified = only(records, "MODIFIED");
    require(modified.size() == 1, "Expected exactly one modification");
    require(modified[0].newHash == sha256("change while state is busy"), "Wrong pending hash");
    require(records.back().type == "MONITOR_STOP", "Missing final MONITOR_STOP"); f.cli({"verify-log"});
}
void test_monitor_preserves_pending_append_on_signal(Fixture& f) {
    f.init(); Monitor monitor(f);
    { Lock lock(f.state / "lock"); writeFile(f.root / "alpha.txt", "pending at shutdown");
      waitStateLock(monitor.child); monitor.child.signal(SIGTERM); std::this_thread::sleep_for(100ms);
      require(monitor.child.running(), "Pending append was abandoned on SIGTERM"); }
    require(monitor.child.wait(5s) == 0, "Monitor failed during pending shutdown"); monitor.stop();
    auto records = f.records(); std::vector<std::string> types;
    for (const auto& event : records) types.push_back(event.type);
    require(types == std::vector<std::string>{"INIT", "MONITOR_START", "MODIFIED", "MONITOR_STOP"}, "Wrong shutdown event order");
    require(records[2].newHash == sha256("pending at shutdown"), "Wrong shutdown modification hash");
    f.cli({"verify-log"});
}
void test_unsafe_existing_state_permissions(Fixture& f) {
    fs::create_directory(f.state);
    subcases(std::vector<mode_t>{0777, 0770, 0755}, [&](mode_t value) {
        mode(f.state, value);
        contains(f.cli({"init", f.root.string()}, 1), "private permissions 0700");
        require((info(f.state).st_mode & 0777) == value, "Unsafe state mode was changed: " + std::to_string(value));
        require(fs::is_empty(f.state), "Unsafe state is no longer empty");
    });
}
void test_valid_private_existing_state(Fixture& f) {
    systemCheck(::mkdir(f.state.c_str(), 0700) == 0, "mkdir private state");
    f.init(); f.cli({"scan"}); f.cli({"status"}); auto stateInfo = info(f.state);
    require(stateInfo.st_uid == ::geteuid(), "Wrong state owner");
    require((stateInfo.st_mode & 0777) == 0700, "Wrong private state mode");
}
void test_state_permissions_rechecked(Fixture& f) {
    f.init(); auto original = readFile(f.state / "audit.log");
    RestoreMode restore(f.state, 0700); mode(f.state, 0755);
    subcases(std::vector<std::string>{"status", "scan", "report", "verify-log", "monitor"}, [&](const std::string& command) {
        contains(f.cli({command}, 1), "private permissions 0700");
    });
    require(readFile(f.state / "audit.log") == original, "Permission rejection changed log");
}
struct Skip : std::runtime_error { using std::runtime_error::runtime_error; };
void test_foreign_owned_state_rejected(Fixture& f) {
    if (::geteuid() == info("/").st_uid) throw Skip("Requires a directory owned by another user");
    contains(f.cli({"status"}, 1, "/"), "owned by the effective user");
}
void test_recursive_monitor_and_moves(Fixture& f) {
    f.init(); Monitor monitor(f); f.cli({"status"});
    writeFile(f.root / "alpha.txt", "changed by monitor test"); f.waitEvent("MODIFIED");
    fs::create_directory(f.root / "nested"); writeFile(f.root / "nested/child", "nested data");
    f.waitEvent("NEW", "nested/child");
    moveFile(f.root / "nested/child", f.root / "nested/renamed"); f.waitEvent("MOVE", "nested/renamed");
    moveFile(f.root / "nested", f.root / "moved-directory"); f.waitEvent("MOVE", "moved-directory");
    writeFile(f.root / "moved-directory/renamed", "still watched"); f.waitEvent("MODIFIED", "moved-directory/renamed");
    mode(f.root / "alpha.txt", 0400); f.waitEvent("PERMISSION_CHANGE");
    removeFile(f.root / "alpha.txt"); f.waitEvent("DELETED", "alpha.txt");
    f.cli({"monitor", "--duration", "1"}, 1); monitor.stop();
    contains(f.cli({"report"}), "MONITOR_STOP");
}
void test_monitor_duration(Fixture& f) {
    f.init(); contains(f.cli({"monitor", "--duration", "1"}), "MONITOR_STOP");
}
void test_unreadable_file_fails_without_partial_state(Fixture& f) {
    if (::geteuid() == 0) throw Skip("Permission denial requires a non-root user");
    RestoreMode restore(f.root / "alpha.txt", 0600); mode(f.root / "alpha.txt", 0);
    f.cli({"init", f.root.string()}, 1);
    require(!fs::exists(f.state / "baseline.dat"), "Partial baseline was created");
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) { std::cerr << "Usage: integration_tests /path/to/audit\n"; return 1; }
    try { binary = fs::canonical(argv[1]).string(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    struct Test { const char* name; void (*function)(Fixture&); };
#define CASE(name) {#name, name}
    const Test tests[] = {
        CASE(test_scan_and_metadata), CASE(test_symlinks_special_files_and_binary_hash),
        CASE(test_log_tampering_and_checkpoint), CASE(test_baseline_corruption_and_binding),
        CASE(test_validation_and_locking), CASE(test_empty_tree), CASE(test_rapid_file_rename_chain),
        CASE(test_rapid_directory_then_child_rename), CASE(test_single_file_rename_hashes),
        CASE(test_single_directory_rename_keeps_watch), CASE(test_monitor_waits_for_state_lock),
        CASE(test_monitor_preserves_pending_append_on_signal), CASE(test_unsafe_existing_state_permissions),
        CASE(test_valid_private_existing_state), CASE(test_state_permissions_rechecked),
        CASE(test_foreign_owned_state_rejected), CASE(test_recursive_monitor_and_moves),
        CASE(test_monitor_duration), CASE(test_unreadable_file_fails_without_partial_state)
    };
#undef CASE
    int passed = 0, failed = 0, skipped = 0;
    for (const auto& test : tests) {
        try {
            Fixture fixture; test.function(fixture); ++passed;
            std::cout << "PASS " << test.name << std::endl;
        } catch (const Skip& reason) {
            ++skipped; std::cout << "SKIP " << test.name << ": " << reason.what() << std::endl;
        } catch (const std::exception& error) {
            ++failed; std::cerr << "FAIL " << test.name << ": " << error.what() << std::endl;
        }
    }
    std::cout << "19 tests: " << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
    return failed ? 1 : 0;
}
