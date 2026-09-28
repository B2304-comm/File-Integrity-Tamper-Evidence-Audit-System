#include "IntegrityChecker.hpp"
#include <sstream>

namespace audit {
std::vector<Event> IntegrityChecker::compare(const Snapshot& baseline, const Snapshot& current,
                                            bool includeUnchanged) {
    std::vector<Event> events;
    for (const auto& [path, old] : baseline) {
        const auto found = current.find(path);
        if (found == current.end()) {
            events.push_back({"DELETED", path, old.hash, "-", ""});
            continue;
        }
        const auto& now = found->second;
        bool changed = false;
        if (old.hash != now.hash || old.size != now.size) {
            events.push_back({"MODIFIED", path, old.hash, now.hash, "size=" +
                std::to_string(old.size) + "->" + std::to_string(now.size)});
            changed = true;
        }
        if (old.mode != now.mode) {
            std::ostringstream modes;
            modes << "mode=" << std::oct << old.mode << "->" << now.mode;
            events.push_back({"PERMISSION_CHANGE", path, old.hash, now.hash, modes.str()});
            changed = true;
        }
        if (!changed && old.mtimeNs != now.mtimeNs) {
            events.push_back({"METADATA_CHANGE", path, old.hash, now.hash, "mtime_ns=" +
                std::to_string(old.mtimeNs) + "->" + std::to_string(now.mtimeNs)});
            changed = true;
        }
        if (!changed && includeUnchanged) events.push_back({"UNCHANGED", path, old.hash, now.hash, ""});
    }
    for (const auto& [path, now] : current)
        if (baseline.count(path) == 0) events.push_back({"NEW", path, "-", now.hash, ""});
    return events;
}
}
