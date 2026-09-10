#include "patch.h"
#include "discovery.h"
#include <bcrypt.h>
#include <cstring>
#include <vector>
#include <limits>

namespace limitbreak {
LayoutResult VerifyLayout(const PoolLayout& pools) {
    // Exact-build layout, shared with tools/boundaries.py. End points at the
    // 32-byte terminal sentinel; each arena budget includes 144 bytes overhead.
    constexpr uint32_t spans[] = { ExpectedSpan, 10u * 1048576u - 144u,
        16u * 1048576u - 144u, 4096u - 144u, 4096u - 144u };
    const uint64_t firstSpan = uint64_t(pools[0].end) - pools[0].head;
    const bool fallback = firstSpan == 64u * 1048576u - 144u;
    for (size_t i = 0; i < pools.size(); ++i) {
        const auto& pool = pools[i];
        const uint32_t expected = i == 0 && fallback ? 64u * 1048576u - 144u : spans[i];
        if (pool.head < 0x10000u || pool.end <= pool.head
            || pool.head % 16 || pool.end % 16
            || uint64_t(pool.end) + 32 > 0x100000000ull
            || uint64_t(pool.end) - pool.head != expected)
            return LayoutResult::Unexpected;
    }
    constexpr size_t order[] = { 0, 1, 3, 2, 4 };
    for (size_t i = 1; i < std::size(order); ++i) {
        if (uint64_t(pools[order[i - 1]].end) + 144 != pools[order[i]].head)
            return LayoutResult::Unexpected;
    }
    return fallback ? LayoutResult::AllocationFallback : LayoutResult::Expanded;
}

bool Read(const void* address, void* output, size_t size) {
    SIZE_T done = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, output, size, &done) && done == size;
}
bool Hash(const void* data, size_t size, Digest& result) {
    if (size > std::numeric_limits<ULONG>::max()) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const auto status = BCryptHash(alg, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(size),
        result.data(), static_cast<ULONG>(result.size()));
    BCryptCloseAlgorithmProvider(alg, 0);
    return status >= 0;
}
bool HashFile(const wchar_t* path, Digest& result) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, returned = 0;
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0;
    if (ok) ok = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0) >= 0;
    std::vector<unsigned char> object(objectSize);
    if (ok) ok = BCryptCreateHash(alg, &hash, object.data(), objectSize, nullptr, 0, 0) >= 0;
    unsigned char buffer[65536];
    while (ok) {
        DWORD count = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) { ok = false; break; }
        if (count == 0) break;
        ok = BCryptHashData(hash, buffer, count, 0) >= 0;
    }
    if (ok) ok = BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    return ok;
}
std::string Hex(const Digest& value) {
    const char* digits = "0123456789abcdef";
    std::string text;
    for (auto byte : value) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text;
}
PatchResult Patch(void* code, const std::vector<unsigned char>& expected,
    const std::array<size_t, 2>& operands) {
    const size_t size = expected.size();
    if (size < 8 || size > 4096 || operands[0] > size - 4 || operands[1] > size - 4
        || (operands[0] < operands[1] + 4 && operands[1] < operands[0] + 4))
        return PatchResult::Mismatch;
    std::vector<unsigned char> original(size), changed(size), check(size);
    if (!Read(code, original.data(), size)) return PatchResult::Unreadable;
    if (original != expected) return PatchResult::Mismatch;
    uint32_t compare = 0, store = 0;
    memcpy(&compare, original.data() + operands[0], sizeof(compare));
    memcpy(&store, original.data() + operands[1], sizeof(store));
    if (compare != OriginalCap || store != OriginalCap) return PatchResult::Mismatch;
    changed = original;
    memcpy(changed.data() + operands[0], &NewCap, sizeof(NewCap));
    memcpy(changed.data() + operands[1], &NewCap, sizeof(NewCap));
    // Preserve each original protection when the discovered span crosses a page boundary.
    struct Region { void* address; size_t size; DWORD protection; };
    std::vector<Region> regions;
    const auto start = reinterpret_cast<uintptr_t>(code);
    const uint64_t end = uint64_t(start) + size;
    if (end > 0x100000000ull) return PatchResult::Mismatch;
    for (uint64_t at = start; at < end;) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(reinterpret_cast<void*>(static_cast<uintptr_t>(at)), &info, sizeof(info)))
            return PatchResult::ProtectionFailed;
        const auto next = (std::min)(end, uint64_t(reinterpret_cast<uintptr_t>(info.BaseAddress)) + info.RegionSize);
        if (next <= at || info.State != MEM_COMMIT) return PatchResult::ProtectionFailed;
        regions.push_back({reinterpret_cast<void*>(static_cast<uintptr_t>(at)), static_cast<size_t>(next - at), info.Protect});
        at = next;
    }
    const auto restore = [&regions](size_t count) {
        bool ok = true; DWORD unused = 0;
        for (size_t i = 0; i < count; ++i)
            ok = (VirtualProtect(regions[i].address, regions[i].size, regions[i].protection, &unused) != FALSE) && ok;
        return ok;
    };
    for (size_t i = 0; i < regions.size(); ++i) {
        DWORD old = 0;
        if (!VirtualProtect(regions[i].address, regions[i].size, PAGE_EXECUTE_READWRITE, &old))
            return restore(i) ? PatchResult::ProtectionFailed : PatchResult::RollbackFailed;
    }
    SIZE_T written = 0;
    bool ok = WriteProcessMemory(GetCurrentProcess(), code, changed.data(), changed.size(), &written)
        && written == changed.size();
    ok = ok && Read(code, check.data(), check.size()) && check == changed;
    ok = ok && FlushInstructionCache(GetCurrentProcess(), code, size);
    if (ok && restore(regions.size())) return PatchResult::Applied;
    DWORD unused = 0;
    for (const auto& region : regions)
        VirtualProtect(region.address, region.size, PAGE_EXECUTE_READWRITE, &unused);
    // The caller has not returned to this code yet. Restore the entire checked span on any error.
    const bool restored = WriteProcessMemory(GetCurrentProcess(), code, original.data(), original.size(), &written)
        && written == original.size() && Read(code, check.data(), check.size()) && check == original;
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), code, size) != FALSE;
    const bool protectedAgain = restore(regions.size());
    return restored && flushed && protectedAgain ? PatchResult::WriteFailed : PatchResult::RollbackFailed;
}
PatchResult PatchDiscovered(uintptr_t base, uintptr_t caller, uint32_t physicalMiB,
    const discovery::Result& result) {
    const auto query = result.match.addresses.find("query_return");
    if (!result.valid || result.validated != 1 || !result.match.uninitialized
        || result.match.cap != OriginalCap || physicalMiB < NewCap
        || query == result.match.addresses.end() || uint64_t(base) + query->second != caller)
        return PatchResult::Mismatch;
    for (const auto global : result.match.globals) {
        PoolBounds bounds{};
        if (uint64_t(base) + global + sizeof(bounds) > 0x100000000ull
            || !Read(reinterpret_cast<void*>(base + global), &bounds, sizeof(bounds)))
            return PatchResult::Unreadable;
        if (bounds.head || bounds.end) return PatchResult::Mismatch;
    }
    return Patch(reinterpret_cast<void*>(caller), result.match.patchBytes,
        {size_t(result.match.caps[0]) - query->second, size_t(result.match.caps[1]) - query->second});
}
const char* Name(PatchResult result) {
    switch (result) {
    case PatchResult::Applied: return "applied";
    case PatchResult::Unreadable: return "unreadable";
    case PatchResult::Mismatch: return "signature_mismatch";
    case PatchResult::ProtectionFailed: return "protection_failed";
    case PatchResult::WriteFailed: return "write_failed_rolled_back";
    default: return "rollback_failed";
    }
}
}
