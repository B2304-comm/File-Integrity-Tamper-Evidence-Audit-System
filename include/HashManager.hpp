#pragma once
#include <string>
namespace audit {
class HashManager {
public:
    static std::string text(const std::string& bytes);
    static std::string descriptor(int fd);
};
}
