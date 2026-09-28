#include "HashManager.hpp"
#include "IntegrityChecker.hpp"
#include "Support.hpp"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}
int main() {
    using namespace audit;
    try {
        require(HashManager::text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty vector");
        require(HashManager::text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 abc vector");
        require(HashManager::text(std::string(1000000, 'a')) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 multi-block vector");
        const std::string binary("a\0\n\t\xff", 5);
        require(hexDecode(hexEncode(binary)) == binary, "Binary encoding roundtrip");
        for (const auto& malformed : {"a", "zz", "FF"}) {
            bool rejected = false;
            try { hexDecode(malformed); } catch (const std::exception&) { rejected = true; }
            require(rejected, "Reject malformed hex");
        }
        const auto hash = HashManager::text("original");
        Snapshot before{{"same", {hash, 8, 0644, 1}}, {"deleted", {hash, 8, 0644, 1}},
            {"modified", {hash, 8, 0644, 1}}, {"permission", {hash, 8, 0644, 1}}, {"metadata", {hash, 8, 0644, 1}}};
        Snapshot after = before;
        after.erase("deleted");
        after["modified"].hash = HashManager::text("replaced");
        after["permission"].mode = 0600;
        after["metadata"].mtimeNs = 2;
        after["new"] = {hash, 8, 0644, 1};
        auto events = IntegrityChecker::compare(before, after, true);
        std::map<std::string, std::string> types;
        for (const auto& event : events) types[event.path] = event.type;
        require(events.size() == 6 && types["same"] == "UNCHANGED" && types["deleted"] == "DELETED" &&
            types["modified"] == "MODIFIED" && types["permission"] == "PERMISSION_CHANGE" &&
            types["metadata"] == "METADATA_CHANGE" && types["new"] == "NEW", "Classify integrity differences");
        require(IntegrityChecker::compare(before, before).empty(), "No duplicate unchanged events");
        std::cout << "Unit tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
