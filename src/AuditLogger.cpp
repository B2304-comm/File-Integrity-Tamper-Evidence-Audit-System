#include "AuditLogger.hpp"
#include "HashManager.hpp"
#include "Support.hpp"
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>

namespace audit {
namespace {
constexpr const char* header = "FIA_LOG_V1\n";
}
void AuditLogger::create() {
    if (fs::exists(fs::symlink_status(file_))) throw std::runtime_error("Audit log already exists");
    atomicWrite(file_, header);
}
Verification AuditLogger::verify(std::vector<std::string>* report) const {
    const auto bytes = readFile(file_);
    if (bytes.rfind(header, 0) != 0 || bytes.back() != '\n')
        throw std::runtime_error("Audit log header or final record is damaged");
    std::istringstream input(bytes.substr(std::strlen(header)));
    Verification result;
    std::string line;
    while (std::getline(input, line)) {
        const auto fields = split(line, '\t');
        const auto expected = result.count + 1;
        if (fields.size() != 10 || fields[0] != std::to_string(expected) ||
            fields[8] != result.head || !validHash(fields[9]) ||
            HashManager::text(line.substr(0, line.rfind('\t'))) != fields[9])
            throw std::runtime_error("Audit chain invalid at record " + std::to_string(expected));
        if (fields[1].empty() || fields[2].empty() ||
            (fields[4] != "-" && !validHash(fields[4])) || (fields[5] != "-" && !validHash(fields[5])) ||
            fields[7] != "v1") throw std::runtime_error("Malformed audit event");
        const auto path = hexDecode(fields[3]);
        const auto detail = hexDecode(fields[6]);
        if (report) report->push_back(fields[0] + " " + fields[1] + " [" + fields[2] + "] " +
            displayPath(path) + " old=" + fields[4] + " new=" + fields[5] + " detail=" + displayPath(detail));
        result.count = expected;
        result.head = fields[9];
    }
    return result;
}
Verification AuditLogger::append(const std::vector<Event>& events) {
    auto result = verify(); // Refuse to extend a broken chain.
    if (events.empty()) return result;
    std::string batch;
    for (const auto& event : events) {
        if (event.type.empty() || event.type.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != std::string::npos ||
            (event.oldHash != "-" && !validHash(event.oldHash)) ||
            (event.newHash != "-" && !validHash(event.newHash))) throw std::runtime_error("Invalid audit event");
        std::string payload = std::to_string(++result.count) + '\t' + utcNow() + '\t' + event.type + '\t' +
            hexEncode(event.path) + '\t' + event.oldHash + '\t' + event.newHash + '\t' + hexEncode(event.detail) +
            "\tv1\t" + result.head;
        result.head = HashManager::text(payload);
        batch += payload + '\t' + result.head + '\n';
    }
    Fd fd(::open(file_.c_str(), O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (fd.get() < 0) throw systemError("Open audit log for append");
    struct stat info{};
    if (::fstat(fd.get(), &info) != 0 || !S_ISREG(info.st_mode)) throw std::runtime_error("Invalid log file");
    writeAll(fd.get(), batch);
    if (::fsync(fd.get()) != 0) throw systemError("Sync audit log");
    return result;
}
}
