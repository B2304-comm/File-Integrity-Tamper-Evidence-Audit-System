#pragma once
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace audit {
namespace fs = std::filesystem;
struct FileRecord {
    std::string hash;
    std::uint64_t size{};
    std::uint32_t mode{};
    std::int64_t mtimeNs{};
};
using Snapshot = std::map<std::string, FileRecord>;
struct Baseline { fs::path root; Snapshot files; };
struct Event {
    std::string type;
    std::string path;
    std::string oldHash = "-";
    std::string newHash = "-";
    std::string detail;
};
struct Verification { std::uint64_t count{}; std::string head = std::string(64, '0'); };
}
