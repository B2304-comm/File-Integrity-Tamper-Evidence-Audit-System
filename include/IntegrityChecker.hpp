#pragma once
#include "Types.hpp"
namespace audit {
class IntegrityChecker {
public:
    static std::vector<Event> compare(const Snapshot& baseline, const Snapshot& current,
                                      bool includeUnchanged = false);
};
}
