#include "patch.h"
#include "discovery.h"
#include <cstring>
#include <vector>

namespace limitbreak {
LayoutResult VerifyLayout(const PoolLayout& pools) {
    // End points at the 32-byte terminal sentinel; each arena budget includes
    // 144 bytes of allocator overhead.
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
    // On x86, only the low byte differs between the two supported imm32 values.
    static_assert((OriginalCap ^ NewCap) == 0x80);
    if (uint64_t(reinterpret_cast<uintptr_t>(code)) + size > 0x100000000ull)
        return PatchResult::Mismatch;
    auto* bytes = static_cast<unsigned char*>(code);
    std::array<DWORD, 2> protections{};
    const auto restore = [&](size_t count) {
        bool ok = true; DWORD unused = 0;
        // Reverse order also restores correctly when both operands share a page.
        while (count > 0) {
            --count;
            ok = (VirtualProtect(bytes + operands[count], 1, protections[count], &unused) != FALSE) && ok;
        }
        return ok;
    };
    for (size_t i = 0; i < operands.size(); ++i) {
        if (!VirtualProtect(bytes + operands[i], 1, PAGE_EXECUTE_READWRITE, &protections[i]))
            return restore(i) ? PatchResult::ProtectionFailed : PatchResult::RollbackFailed;
    }
    const auto writeOperands = [&](const std::vector<unsigned char>& values) {
        bool ok = true;
        for (const auto offset : operands) {
            SIZE_T written = 0;
            ok = (WriteProcessMemory(GetCurrentProcess(), bytes + offset, values.data() + offset, 1, &written)
                && written == 1) && ok;
        }
        return ok;
    };
    bool ok = writeOperands(changed);
    ok = ok && Read(code, check.data(), check.size()) && check == changed;
    ok = ok && FlushInstructionCache(GetCurrentProcess(), code, size);
    if (ok && restore(operands.size())) return PatchResult::Applied;
    DWORD unused = 0;
    for (const auto offset : operands)
        VirtualProtect(bytes + offset, 1, PAGE_EXECUTE_READWRITE, &unused);
    // Restore only our two bytes, then verify the entire checked span.
    const bool restored = writeOperands(original) && Read(code, check.data(), check.size()) && check == original;
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), code, size) != FALSE;
    const bool protectedAgain = restore(operands.size());
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
