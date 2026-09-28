#include "FileScanner.hpp"
#include "HashManager.hpp"
#include "Support.hpp"
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>

namespace audit {
namespace {
bool stable(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
           a.st_mode == b.st_mode && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
           a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
           a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
struct CloseDirectory { void operator()(DIR* dir) const { ::closedir(dir); } };
void walk(int fd, const std::string& prefix, Snapshot& result) {
    int copy = ::dup(fd);
    if (copy < 0) throw systemError("Duplicate directory handle");
    std::unique_ptr<DIR, CloseDirectory> directory(::fdopendir(copy));
    if (!directory) { ::close(copy); throw systemError("Read directory"); }
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (!entry) { if (errno) throw systemError("Enumerate directory"); break; }
        const std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        const std::string relative = prefix + name;
        struct stat info{};
        if (::fstatat(fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0)
            throw systemError("Inspect " + displayPath(relative));
        if (S_ISDIR(info.st_mode)) {
            Fd child(::openat(fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (child.get() < 0) throw systemError("Open directory " + displayPath(relative));
            walk(child.get(), relative + "/", result);
        } else if (S_ISREG(info.st_mode)) {
            Fd file(::openat(fd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
            if (file.get() < 0) throw systemError("Open file " + displayPath(relative));
            struct stat before{}, after{}, named{};
            if (::fstat(file.get(), &before) != 0) throw systemError("Inspect open file");
            if (!S_ISREG(before.st_mode) || !stable(info, before))
                throw std::runtime_error("File changed during scan: " + displayPath(relative));
            const auto hash = HashManager::descriptor(file.get());
            if (::fstat(file.get(), &after) != 0 ||
                ::fstatat(fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0)
                throw systemError("Recheck " + displayPath(relative));
            if (!stable(before, after) || !stable(after, named))
                throw std::runtime_error("File changed during scan: " + displayPath(relative));
            result.emplace(relative, FileRecord{hash, static_cast<std::uint64_t>(after.st_size),
                static_cast<std::uint32_t>(after.st_mode & 07777),
                static_cast<std::int64_t>(after.st_mtim.tv_sec) * 1000000000LL + after.st_mtim.tv_nsec});
        }
        // Symlinks, sockets, devices and FIFOs are outside the regular-file scope.
    }
}
}
Snapshot FileScanner::scan(const fs::path& root) const {
    Fd directory(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory.get() < 0) throw systemError("Open protected root");
    Snapshot result;
    walk(directory.get(), "", result);
    return result;
}
}
