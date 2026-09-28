#pragma once
#include "Types.hpp"
namespace audit {
class AuditLogger {
    fs::path file_;
public:
    explicit AuditLogger(fs::path file) : file_(std::move(file)) {}
    Verification verify(std::vector<std::string>* report = nullptr) const;
    Verification append(const std::vector<Event>& events);
    void create();
};
}
