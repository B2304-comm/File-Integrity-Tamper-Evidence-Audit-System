#pragma once
#include "Types.hpp"
namespace audit {
class StateLock {
    int fd_ = -1;
public:
    explicit StateLock(const fs::path& state, const std::string& name = "lock", bool wait = false);
    ~StateLock();
    StateLock(const StateLock&) = delete;
    StateLock& operator=(const StateLock&) = delete;
};
class ConfigManager {
public:
    static fs::path prepareState(const fs::path& state, bool create);
    static fs::path validateRoot(const fs::path& root, const fs::path& state);
    static void saveBaseline(const fs::path& file, const Baseline& baseline);
    static Baseline loadBaseline(const fs::path& file);
};
}
