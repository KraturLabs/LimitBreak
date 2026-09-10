#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace limitbreak::discovery {
using Reader = std::function<bool(uint32_t, void*, size_t)>;
struct Match {
    std::map<std::string, uint32_t> addresses; // Validated module-relative addresses.
    std::array<uint32_t, 2> caps{};
    std::array<uint32_t, 5> globals{}, wrappers{};
    std::vector<unsigned char> patchBytes; // Validated query-return through initializer end.
    uint32_t cap = 0;
    bool uninitialized = false;
    std::string layout;
    std::vector<std::string> passed;
};
struct Result {
    bool valid = false;
    uint32_t candidates = 0, validated = 0;
    double milliseconds = 0;
    Match match;
    std::vector<std::string> failures;
};
Result Discover(uint32_t base, const Reader& reader);
std::string Json(const Result& result);
}
