#pragma once
#include "Types.hpp"
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

namespace audit {
inline std::runtime_error systemError(const std::string& action) {
    return std::runtime_error(action + ": " + std::strerror(errno));
}
class Fd {
    int fd_;
public:
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
};
std::string hexEncode(const std::string& value);
std::string hexDecode(const std::string& value);
std::vector<std::string> split(const std::string& value, char delimiter);
std::uint64_t parseUnsigned(const std::string& value);
bool validHash(const std::string& value);
std::string readFile(const fs::path& path);
void atomicWrite(const fs::path& path, const std::string& bytes);
void writeAll(int fd, const std::string& bytes);
std::string utcNow();
std::string displayPath(const std::string& path);
}
