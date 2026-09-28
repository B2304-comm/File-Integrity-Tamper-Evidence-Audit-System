#pragma once
#include "Types.hpp"
namespace audit {
class FileScanner {
public:
    Snapshot scan(const fs::path& root) const;
};
}
