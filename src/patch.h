#pragma once
#include <windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace limitbreak::discovery { struct Result; }

namespace limitbreak {
using Digest = std::array<unsigned char, 32>;
constexpr uint32_t OriginalCap = 256;
constexpr uint32_t NewCap = 384; // pool = 64 + (cap - 128) = 320 MiB
constexpr uint32_t ExpectedSpan = 320u * 1024u * 1024u - 144u;
struct PoolBounds { uint32_t head, end; };
using PoolLayout = std::array<PoolBounds, 5>;
static_assert(sizeof(PoolLayout) == 40);
enum class LayoutResult { Expanded, AllocationFallback, Unexpected };
LayoutResult VerifyLayout(const PoolLayout& pools);
bool Read(const void* address, void* output, size_t size);
bool Hash(const void* data, size_t size, Digest& result);
bool HashFile(const wchar_t* path, Digest& result);
std::string Hex(const Digest& value);
enum class PatchResult { Applied, Unreadable, Mismatch, ProtectionFailed, WriteFailed, RollbackFailed };
PatchResult Patch(void* code, const std::vector<unsigned char>& expected,
    const std::array<size_t, 2>& operands);
PatchResult PatchDiscovered(uintptr_t base, uintptr_t caller, uint32_t physicalMiB,
    const discovery::Result& result);
const char* Name(PatchResult result);
}
