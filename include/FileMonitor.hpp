#pragma once
#include "AuditLogger.hpp"
#include "Types.hpp"
namespace audit {
class FileMonitor {
public:
    void run(const Baseline& baseline, const fs::path& state, int durationSeconds = 0);
};
}
