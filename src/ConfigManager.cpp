#include "ConfigManager.hpp"
#include "HashManager.hpp"
#include "Support.hpp"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>

namespace audit {
std::string hexEncode(const std::string& value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char c : value) { result += digits[c >> 4]; result += digits[c & 15]; }
    return result;
}
std::string hexDecode(const std::string& value) {
    if (value.size() % 2) throw std::runtime_error("Invalid hex encoding");
    const auto nibble = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        throw std::runtime_error("Invalid hex encoding");
    };
    std::string result;
    for (std::size_t i = 0; i < value.size(); i += 2)
        result += static_cast<char>((nibble(value[i]) << 4) | nibble(value[i+1]));
    return result;
}
std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
        auto end = value.find(delimiter, start);
        fields.push_back(value.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) return fields;
        start = end + 1;
    }
}
std::uint64_t parseUnsigned(const std::string& value) {
    std::uint64_t result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw std::runtime_error("Invalid unsigned integer");
    return result;
}
bool validHash(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
std::string readFile(const fs::path& path) {
    Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (fd.get() < 0) throw systemError("Open " + path.string());
    struct stat info{};
    if (::fstat(fd.get(), &info) != 0) throw systemError("Inspect state file");
    if (!S_ISREG(info.st_mode)) throw std::runtime_error("State file must be a regular file");
    std::string result;
    char buffer[65536];
    for (;;) {
        auto count = ::read(fd.get(), buffer, sizeof(buffer));
        if (count < 0) { if (errno == EINTR) continue; throw systemError("Read state file"); }
        if (count == 0) return result;
        result.append(buffer, static_cast<std::size_t>(count));
    }
}
void writeAll(int fd, const std::string& bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0) { if (errno == EINTR) continue; throw systemError("Write state file"); }
        if (count == 0) throw std::runtime_error("Zero-length write");
        offset += static_cast<std::size_t>(count);
    }
}
void atomicWrite(const fs::path& path, const std::string& bytes) {
    std::string pattern = path.string() + ".tmp.XXXXXX";
    std::vector<char> name(pattern.begin(), pattern.end()); name.push_back('\0');
    Fd fd(::mkstemp(name.data()));
    if (fd.get() < 0) throw systemError("Create temporary state file");
    try {
        writeAll(fd.get(), bytes);
        if (::fsync(fd.get()) != 0) throw systemError("Sync state file");
        if (::rename(name.data(), path.c_str()) != 0) throw systemError("Publish state file");
        Fd directory(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (directory.get() < 0 || ::fsync(directory.get()) != 0) throw systemError("Sync state directory");
    } catch (...) { ::unlink(name.data()); throw; }
}
std::string utcNow() {
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm time{};
    ::gmtime_r(&seconds, &time);
    std::ostringstream out;
    out << std::put_time(&time, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}
std::string displayPath(const std::string& path) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : path) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 32 || c >= 127) out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        else out << static_cast<char>(c);
    }
    return out.str() + '"';
}
StateLock::StateLock(const fs::path& state, const std::string& name, bool wait) {
    fd_ = ::open((state / name).c_str(), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd_ < 0) throw systemError("Open state lock");
    struct stat info{};
    if (::fstat(fd_, &info) != 0 || !S_ISREG(info.st_mode)) {
        ::close(fd_); fd_ = -1; throw std::runtime_error("Invalid state lock");
    }
    while (::flock(fd_, LOCK_EX | (wait ? 0 : LOCK_NB)) != 0) {
        if (errno == EINTR) continue;
        const int error = errno;
        ::close(fd_); fd_ = -1;
        if (error == EWOULDBLOCK)
            throw std::runtime_error("State is busy; another command is using it. Try again shortly.");
        errno = error;
        throw systemError("Acquire state lock");
    }
}
StateLock::~StateLock() { if (fd_ >= 0) ::close(fd_); }
namespace {
bool inside(const fs::path& child, const fs::path& parent) {
    auto c = child.begin();
    for (auto p = parent.begin(); p != parent.end(); ++p, ++c)
        if (c == child.end() || *c != *p) return false;
    return true;
}
}
fs::path ConfigManager::prepareState(const fs::path& state, bool create) {
    auto absolute = fs::absolute(state).lexically_normal();
    if (fs::is_symlink(fs::symlink_status(absolute))) throw std::runtime_error("State directory cannot be a symlink");
    if (create && !fs::exists(absolute)) {
        fs::create_directories(absolute);
        fs::permissions(absolute, fs::perms::owner_all, fs::perm_options::replace);
    }
    if (!fs::is_directory(absolute)) throw std::runtime_error("State directory is missing; run init first");
    struct stat info{};
    if (::lstat(absolute.c_str(), &info) != 0) throw systemError("Inspect state directory");
    if (!S_ISDIR(info.st_mode)) throw std::runtime_error("State path must be a directory, not a symlink");
    if (info.st_uid != ::geteuid())
        throw std::runtime_error("State directory must be owned by the effective user");
    if ((info.st_mode & 0777) != 0700)
        throw std::runtime_error("State directory must have private permissions 0700; use a trusted Linux filesystem location");
    return fs::canonical(absolute);
}
fs::path ConfigManager::validateRoot(const fs::path& root, const fs::path& state) {
    const auto canonical = fs::canonical(root);
    if (!fs::is_directory(canonical)) throw std::runtime_error("Protected path must be a directory");
    if (inside(state, canonical) || inside(canonical, state))
        throw std::runtime_error("State and protected directories must be separate, non-nested trees; use --state PATH");
    return canonical;
}
void ConfigManager::saveBaseline(const fs::path& file, const Baseline& baseline) {
    std::ostringstream payload;
    payload << "FIA_BASELINE_V1\n" << hexEncode(baseline.root.string()) << '\n';
    for (const auto& [path, record] : baseline.files)
        payload << hexEncode(path) << '\t' << record.hash << '\t' << record.size << '\t'
                << record.mode << '\t' << record.mtimeNs << '\n';
    const auto bytes = payload.str();
    atomicWrite(file, bytes + "CHECKSUM\t" + HashManager::text(bytes) + "\n");
}
Baseline ConfigManager::loadBaseline(const fs::path& file) {
    const auto bytes = readFile(file);
    const auto checksum = bytes.rfind("CHECKSUM\t");
    if (checksum == std::string::npos || bytes.substr(checksum) !=
        "CHECKSUM\t" + HashManager::text(bytes.substr(0, checksum)) + "\n")
        throw std::runtime_error("Baseline checksum mismatch or malformed baseline");
    std::istringstream input(bytes.substr(0, checksum));
    std::string line;
    if (!std::getline(input, line) || line != "FIA_BASELINE_V1") throw std::runtime_error("Unsupported baseline format");
    if (!std::getline(input, line)) throw std::runtime_error("Missing baseline root");
    Baseline baseline{hexDecode(line), {}};
    if (!baseline.root.is_absolute() || baseline.root.string().find('\0') != std::string::npos)
        throw std::runtime_error("Invalid baseline root");
    while (std::getline(input, line)) {
        const auto fields = split(line, '\t');
        if (fields.size() != 5 || !validHash(fields[1])) throw std::runtime_error("Malformed baseline record");
        const auto path = hexDecode(fields[0]);
        const fs::path relative(path);
        if (path.empty() || path.find('\0') != std::string::npos || relative.is_absolute() ||
            relative.lexically_normal().generic_string() != path)
            throw std::runtime_error("Invalid baseline path");
        for (const auto& part : relative) if (part == ".." || part == ".") throw std::runtime_error("Invalid baseline path");
        const auto mode = parseUnsigned(fields[3]);
        if (mode > 07777) throw std::runtime_error("Invalid permission mode");
        std::int64_t mtime{};
        const auto parsed = std::from_chars(fields[4].data(), fields[4].data() + fields[4].size(), mtime);
        if (fields[4].empty() || parsed.ec != std::errc{} || parsed.ptr != fields[4].data() + fields[4].size())
            throw std::runtime_error("Invalid baseline timestamp");
        if (!baseline.files.emplace(path, FileRecord{fields[1], parseUnsigned(fields[2]),
                static_cast<std::uint32_t>(mode), mtime}).second)
            throw std::runtime_error("Duplicate baseline path");
    }
    return baseline;
}
}
