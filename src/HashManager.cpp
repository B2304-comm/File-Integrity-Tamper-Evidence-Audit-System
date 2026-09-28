#include "HashManager.hpp"
#include "Support.hpp"
#include <array>
#include <memory>
#include <openssl/evp.h>

namespace audit {
namespace {
class Digest {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Digest() {
        if (!ctx_ || EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("Cannot initialize SHA-256");
    }
    void update(const void* data, std::size_t length) {
        if (EVP_DigestUpdate(ctx_.get(), data, length) != 1)
            throw std::runtime_error("SHA-256 update failed");
    }
    std::string finish() {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), result, &length) != 1)
            throw std::runtime_error("SHA-256 finalization failed");
        return hexEncode(std::string(reinterpret_cast<char*>(result), length));
    }
};
}
std::string HashManager::text(const std::string& bytes) {
    Digest digest;
    digest.update(bytes.data(), bytes.size());
    return digest.finish();
}
std::string HashManager::descriptor(int fd) {
    Digest digest;
    std::array<char, 65536> buffer{};
    for (;;) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) { if (errno == EINTR) continue; throw systemError("Read file"); }
        if (count == 0) break;
        digest.update(buffer.data(), static_cast<std::size_t>(count));
    }
    return digest.finish();
}
}
