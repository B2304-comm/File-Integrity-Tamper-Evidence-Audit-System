#include "AuditLogger.hpp"
#include "ConfigManager.hpp"
#include "FileMonitor.hpp"
#include "FileScanner.hpp"
#include "HashManager.hpp"
#include "IntegrityChecker.hpp"
#include "Support.hpp"
#include <iostream>
#include <limits>
#include <memory>
#include <set>

namespace {
void help() {
    std::cout << R"(File Integrity & Tamper-Evidence Audit System
Usage: audit <command> [directory] [options]

  init <directory>       Create an immutable regular-file baseline
  scan [directory]       Compare against baseline and record differences
  status                 Show protected root, baseline count, and log head
  monitor [directory]    Watch recursively with Linux inotify; Ctrl+C stops
  report                 Verify and display the audit events
  verify-log             Verify the SHA-256 audit chain
  help                   Show this help

Options:
  --state PATH           State directory (default: .audit in current directory)
  --all                  Also list unchanged files (scan only)
  --duration SECONDS     Stop monitoring after this many seconds (monitor only)
  --expect-head HASH     Compare log head to an externally saved hash (verify-log)

State must be outside the protected tree. Symlinks and special files are skipped.
Exit codes: 0 success/clean, 1 operational or verification error, 2 scan differences.
)";
}
}
int main(int argc, char** argv) {
    using namespace audit;
    try {
        if (argc == 1) { help(); return 0; }
        const std::string command = argv[1];
        if (command == "help" || command == "--help" || command == "-h") { help(); return 0; }
        const std::set<std::string> commands{"init", "scan", "status", "monitor", "report", "verify-log"};
        if (!commands.count(command)) throw std::runtime_error("Unknown command: " + command + "; use audit help");
        fs::path state = ".audit";
        fs::path directory;
        bool all = false;
        int duration = 0;
        std::string expected;
        std::set<std::string> seen;
        for (int i = 2; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg.rfind("--", 0) == 0) {
                if (!seen.insert(arg).second) throw std::runtime_error("Duplicate option: " + arg);
                if (arg == "--all" && command == "scan") { all = true; continue; }
                if (arg != "--state" && !(arg == "--duration" && command == "monitor") &&
                    !(arg == "--expect-head" && command == "verify-log")) throw std::runtime_error("Invalid option for command: " + arg);
                if (++i == argc || std::string(argv[i]).empty()) throw std::runtime_error("Missing option value: " + arg);
                if (arg == "--state") state = argv[i];
                if (arg == "--expect-head") {
                    expected = argv[i];
                    if (!validHash(expected)) throw std::runtime_error("Expected head must be 64 lowercase hex characters");
                }
                if (arg == "--duration") {
                    const auto value = parseUnsigned(argv[i]);
                    if (!value || value > static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
                        throw std::runtime_error("Duration must be a positive integer");
                    duration = static_cast<int>(value);
                }
            } else {
                if (!directory.empty() || (command != "init" && command != "scan" && command != "monitor"))
                    throw std::runtime_error("Unexpected argument: " + arg);
                directory = arg;
            }
        }
        if (command == "init" && directory.empty()) throw std::runtime_error("init requires a directory");
        // Validate separation before init creates any state inside the protected tree.
        if (command == "init") ConfigManager::validateRoot(directory, fs::weakly_canonical(fs::absolute(state)));
        state = ConfigManager::prepareState(state, command == "init");
        auto lock = std::make_unique<StateLock>(state, "lock", command == "monitor");
        AuditLogger logger(state / "audit.log");
        if (command == "init") {
            if (fs::exists(fs::symlink_status(state / "baseline.dat")) || fs::exists(fs::symlink_status(state / "audit.log")))
                throw std::runtime_error("State already initialized or incomplete; choose a new --state directory");
            Baseline baseline{ConfigManager::validateRoot(directory, state), {}};
            baseline.files = FileScanner().scan(baseline.root);
            ConfigManager::saveBaseline(state / "baseline.dat", baseline);
            logger.create();
            const auto head = logger.append({{"INIT", baseline.root.string(), "-",
                HashManager::text(readFile(state / "baseline.dat")), "files=" + std::to_string(baseline.files.size())}});
            std::cout << "Baseline created: " << baseline.files.size() << " files\nRoot: " << displayPath(baseline.root.string())
                      << "\nState: " << displayPath(state.string()) << "\nLog head: " << head.head << '\n';
            return 0;
        }
        if (command == "verify-log" || command == "report") {
            std::vector<std::string> report;
            const auto verified = logger.verify(command == "report" ? &report : nullptr);
            if (!expected.empty() && expected != verified.head) throw std::runtime_error("Log head differs from the externally supplied checkpoint");
            for (const auto& line : report) std::cout << line << '\n';
            std::cout << "VALID chain: " << verified.count << " records\nLog head: " << verified.head << '\n';
            return 0;
        }
        const auto baseline = ConfigManager::loadBaseline(state / "baseline.dat");
        const auto verified = logger.verify();
        // Bind the baseline to the first audit record, in addition to its own checksum.
        const auto logBytes = readFile(state / "audit.log");
        const auto firstStart = logBytes.find('\n') + 1;
        const auto first = split(logBytes.substr(firstStart, logBytes.find('\n', firstStart) - firstStart), '\t');
        if (first.size() != 10 || first[2] != "INIT" || hexDecode(first[3]) != baseline.root.string() ||
            first[5] != HashManager::text(readFile(state / "baseline.dat")))
            throw std::runtime_error("Baseline does not match the INIT audit record");
        if (command == "status") {
            std::cout << "Root: " << displayPath(baseline.root.string()) << "\nBaseline files: " << baseline.files.size()
                      << "\nAudit records: " << verified.count << "\nLog head: " << verified.head << '\n';
            return 0;
        }
        const auto root = ConfigManager::validateRoot(directory.empty() ? baseline.root : directory, state);
        if (root != baseline.root) throw std::runtime_error("Directory differs from the initialized protected root");
        if (command == "monitor") {
            lock.reset();
            FileMonitor().run(baseline, state, duration);
            return 0;
        }
        const auto current = FileScanner().scan(root);
        const auto events = IntegrityChecker::compare(baseline.files, current, all);
        std::vector<Event> changes;
        for (const auto& event : events) {
            std::cout << '[' << event.type << "] " << displayPath(event.path) << " old=" << event.oldHash
                      << " new=" << event.newHash << ' ' << event.detail << '\n';
            if (event.type != "UNCHANGED") changes.push_back(event);
        }
        const auto count = changes.size();
        changes.push_back({"SCAN", root.string(), "-", "-", "files=" + std::to_string(current.size()) + ";changes=" + std::to_string(count)});
        logger.append(changes);
        std::cout << "Scan complete: " << current.size() << " files, " << count << " change events\n";
        return count ? 2 : 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
