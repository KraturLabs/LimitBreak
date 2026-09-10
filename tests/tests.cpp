#include "patch.h"
#include "discovery.h"
#include <Ashita.h>
#include <MinHook.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace limitbreak;
static unsigned checks = 0;
constexpr size_t CodeSize = 214, CompareImmediate = 32, StoreImmediate = 48;
const std::array<size_t, 2> Operands{CompareImmediate, StoreImmediate};
static void Check(bool condition, const char* name) {
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); exit(1); }
    ++checks;
}
static uint32_t PoolMiB(uint32_t physicalMiB, uint32_t cap) {
    return physicalMiB <= 128 ? 64 : 64 + ((physicalMiB > cap ? cap : physicalMiB) - 128);
}
using Query = void (WINAPI*)(LPMEMORYSTATUS);
static Query queryNext = nullptr;
static volatile LONG hits = 0;
static void WINAPI QueryHook(LPMEMORYSTATUS data) { InterlockedIncrement(&hits); queryNext(data); }

static PoolLayout LayoutFixture(uint32_t capacityMiB, uint32_t head = 0x10000000u) {
    // Literal offsets in global-table order, independently specifying the
    // physical order 0,1,3,2,4 and the full arena budgets.
    const uint32_t first = capacityMiB * 1048576u;
    return {{ {head, head + first - 144u},
        {head + first, head + first + 0xa00000u - 144u},
        {head + first + 0xa01000u, head + first + 0x1a01000u - 144u},
        {head + first + 0xa00000u, head + first + 0xa01000u - 144u},
        {head + first + 0x1a01000u, head + first + 0x1a02000u - 144u} }};
}
static void CheckLayouts() {
    for (const uint32_t capacity : {64u, 320u}) {
        const auto expected = capacity == 320 ? LayoutResult::Expanded : LayoutResult::AllocationFallback;
        const auto valid = LayoutFixture(capacity);
        Check(VerifyLayout(valid) == expected, "complete expanded/64 MiB fallback layout classified");
        Check(VerifyLayout(LayoutFixture(capacity, 0x60000000u)) == expected, "relocated layout accepted");
        for (size_t i = 0; i < valid.size(); ++i) {
            auto bad = valid; bad[i].end -= 16;
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "wrong span in every pool rejected");
            bad = valid; bad[i] = {};
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "missing pool rejected");
            bad = valid; bad[i].end = bad[i].head;
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "empty pool rejected");
            bad = valid; bad[i].end = bad[i].head - 16;
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "reversed pool rejected");
            bad = valid; ++bad[i].head; ++bad[i].end;
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "unaligned pool rejected");
            bad = valid; bad[i].head += 16; bad[i].end += 16;
            Check(VerifyLayout(bad) == LayoutResult::Unexpected, "correct span at incorrect sibling offset rejected");
        }
        auto bad = valid; std::swap(bad[3], bad[4]);
        Check(VerifyLayout(bad) == LayoutResult::Unexpected, "equal-size pools in wrong table slots rejected");
        bad = valid; bad[4] = bad[3];
        Check(VerifyLayout(bad) == LayoutResult::Unexpected, "overlapping sibling rejected");
        Check(VerifyLayout(LayoutFixture(capacity, 0x10u)) == LayoutResult::Unexpected, "low address rejected");
        Check(VerifyLayout(LayoutFixture(capacity, 0xfe000000u)) == LayoutResult::Unexpected, "wrapped addresses rejected");
        // Last sentinel would cross the x86 address ceiling even though all
        // heads/ends, spans and sibling spacing otherwise match.
        const uint32_t high = 0xfffffff0u - (capacity * 1048576u + 0x1a02000u - 144u);
        Check(VerifyLayout(LayoutFixture(capacity, high)) == LayoutResult::Unexpected, "sentinel overflow rejected");
    }
    Check(VerifyLayout(PoolLayout{}) == LayoutResult::Unexpected, "uninitialized layout rejected");
    Check(VerifyLayout(LayoutFixture(256)) == LayoutResult::Unexpected, "unsupported capacity rejected");
    Check(VerifyLayout(LayoutFixture(192)) == LayoutResult::Unexpected, "192 MiB stock layout rejected after patch");
    Check(VerifyLayout(LayoutFixture(384)) == LayoutResult::Unexpected, "retired 384 MiB layout rejected");
    auto mixed = LayoutFixture(320);
    mixed[0].end = LayoutFixture(64)[0].end;
    Check(VerifyLayout(mixed) == LayoutResult::Unexpected, "64 MiB first pool with expanded siblings is not fallback");
    mixed = LayoutFixture(64);
    mixed[0].end = LayoutFixture(320)[0].end;
    Check(VerifyLayout(mixed) == LayoutResult::Unexpected, "expanded first pool overlapping fallback siblings rejected");
}

int main(int argc, char** argv) {
    Check(argc == 2, "DLL argument");
    Check(sizeof(void*) == 4, "x86");
    CheckLayouts();
    Check(PoolMiB(65536, OriginalCap) == 192, "stock cap reproduces dump capacity");
    Check(PoolMiB(65536, NewCap) == 320, "new cap produces requested capacity");
    Check(PoolMiB(128, NewCap) == 64, "low-memory original branch");
    Check((0x05a02000u + ((NewCap - 128u) << 20)) == 0x15a02000u,
        "backing allocation grows by same 128 MiB and retains sibling pool space");
    auto* page = static_cast<unsigned char*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Check(page != nullptr, "allocate test page");
    std::vector<unsigned char> fixture(CodeSize, 0x90);
    memcpy(fixture.data() + CompareImmediate, &OriginalCap, 4);
    memcpy(fixture.data() + StoreImmediate, &OriginalCap, 4);
    Digest digest{}; Check(Hash(fixture.data(), fixture.size(), digest), "hash fixture");
    auto wrong = fixture; wrong[0] ^= 1;
    memcpy(page, fixture.data(), fixture.size());
    Check(Patch(page, wrong, Operands) == PatchResult::Mismatch, "wrong build rejected");
    Check(memcmp(page, fixture.data(), fixture.size()) == 0, "rejection is non-mutating");
    DWORD old = 0;
    Check(VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old) != FALSE, "set executable protection");
    Check(Patch(page, fixture, Operands) == PatchResult::Applied, "patch protected page");
    auto expected = fixture;
    memcpy(expected.data() + CompareImmediate, &NewCap, 4);
    memcpy(expected.data() + StoreImmediate, &NewCap, 4);
    Check(memcmp(page, expected.data(), expected.size()) == 0, "only two cap immediates changed");
    MEMORY_BASIC_INFORMATION info{};
    Check(VirtualQuery(page, &info, sizeof(info)) && info.Protect == PAGE_EXECUTE_READ, "page protection restored");
    Check(Patch(page, fixture, Operands) == PatchResult::Mismatch, "repeated patch rejected");
    Check(Patch(nullptr, fixture, Operands) == PatchResult::Unreadable, "invalid address refused");
    Check(VirtualProtect(page, 4096, PAGE_READWRITE, &old) != FALSE, "restore fixture access");
    fixture[StoreImmediate] = 1;
    Check(Hash(fixture.data(), fixture.size(), digest), "hash incompatible fixture");
    memcpy(page, fixture.data(), fixture.size());
    Check(Patch(page, fixture, Operands) == PatchResult::Mismatch, "cap mismatch rejected even with matching digest");
    // Discovered offsets may move independently of the first synthetic fixture positions.
    fixture.assign(173, 0x90);
    const std::array<size_t, 2> moved{51, 107};
    memcpy(fixture.data() + moved[0], &OriginalCap, 4);
    memcpy(fixture.data() + moved[1], &OriginalCap, 4);
    memcpy(page, fixture.data(), fixture.size());
    Check(Patch(page, fixture, {51, 52}) == PatchResult::Mismatch, "overlapping operands refused");
    Check(Patch(page, fixture, {51, 171}) == PatchResult::Mismatch, "out of range operand refused");
    Check(memcmp(page, fixture.data(), fixture.size()) == 0, "bad operands leave bytes unchanged");
    discovery::Result discovered;
    discovered.valid = true; discovered.validated = 1;
    discovered.match.uninitialized = true; discovered.match.cap = OriginalCap;
    discovered.match.addresses["query_return"] = 0;
    discovered.match.caps = {51, 107}; discovered.match.patchBytes = fixture;
    discovered.match.globals = {512, 520, 528, 536, 544};
    const auto base = reinterpret_cast<uintptr_t>(page);
    Check(PatchDiscovered(base, base + 1, 4096, discovered) == PatchResult::Mismatch, "wrong caller refuses without write");
    Check(PatchDiscovered(base, base, 383, discovered) == PatchResult::Mismatch, "insufficient memory refuses");
    discovered.validated = 2;
    Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "ambiguous discovery refuses");
    discovered.validated = 0;
    Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "missing discovery refuses");
    discovered.validated = 1; discovered.valid = false;
    Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "invalid discovery refuses");
    discovered.valid = true; discovered.match.uninitialized = false;
    Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "late discovery refuses");
    discovered.match.uninitialized = true;
    for (const auto global : discovered.match.globals) {
        page[global] = 1;
        Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "each newly initialized pool refuses");
        page[global] = 0;
    }
    Check(memcmp(page, fixture.data(), fixture.size()) == 0, "all startup refusals leave code unchanged");
    page[8] ^= 1;
    Check(PatchDiscovered(base, base, 4096, discovered) == PatchResult::Mismatch, "post-discovery code drift refuses");
    page[8] ^= 1;
    Check(PatchDiscovered(base, base, 384, discovered) == PatchResult::Applied, "discovered moved operands patched");
    memcpy(fixture.data() + moved[0], &NewCap, 4);
    memcpy(fixture.data() + moved[1], &NewCap, 4);
    Check(memcmp(page, fixture.data(), fixture.size()) == 0, "discovered patch changes only derived operands");
    memcpy(page + 4096 - 80, discovered.match.patchBytes.data(), discovered.match.patchBytes.size());
    Check(VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old) != FALSE, "first page executable");
    Check(VirtualProtect(page + 4096, 4096, PAGE_READONLY, &old) != FALSE, "second page different protection");
    Check(Patch(page + 4096 - 80, discovered.match.patchBytes, moved) == PatchResult::Applied, "cross-region discovered patch");
    Check(VirtualQuery(page, &info, sizeof(info)) && info.Protect == PAGE_EXECUTE_READ, "first region restored");
    Check(VirtualQuery(page + 4096, &info, sizeof(info)) && info.Protect == PAGE_READONLY, "second region restored independently");
    VirtualFree(page, 0, MEM_RELEASE);

    Check(MH_Initialize() == MH_OK, "MinHook init");
    void* target = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GlobalMemoryStatus"));
    Check(MH_CreateHook(target, &QueryHook, reinterpret_cast<void**>(&queryNext)) == MH_OK, "prepare real memory API hook");
    MEMORYSTATUS before{}; before.dwLength = sizeof(before); GlobalMemoryStatus(&before);
    Check(MH_EnableHook(target) == MH_OK, "enable hook");
    MEMORYSTATUS after{}; after.dwLength = sizeof(after); GlobalMemoryStatus(&after);
    Check(hits > 0 && after.dwTotalPhys == before.dwTotalPhys && after.dwLength == before.dwLength,
        "real query intercepted with physical memory preserved");
    Check(MH_DisableHook(target) == MH_OK, "disable test hook");
    Check(MH_Uninitialize() == MH_OK, "release test hook");

    HMODULE dll = LoadLibraryA(argv[1]); Check(dll != nullptr, "load built DLL");
    auto version = reinterpret_cast<double (__stdcall*)()>(GetProcAddress(dll, "expGetInterfaceVersion"));
    auto create = reinterpret_cast<IPolPlugin* (__stdcall*)(const char*)>(GetProcAddress(dll, "expCreatePolPlugin"));
    auto destroy = reinterpret_cast<void (__stdcall*)(void*)>(GetProcAddress(dll, "expDestroyPlugin"));
    Check(version && create && destroy && version() == 4.30, "undecorated POL exports and ABI");
    auto* instance = create("320");
    Check(instance && strcmp(instance->GetName(), "LimitBreak") == 0, "construct POL interface");
    Check(instance->GetFlags() == (static_cast<uint32_t>(Ashita::PluginFlags::UseDirect3D)
        | static_cast<uint32_t>(Ashita::PluginFlags::UseCommands)), "only required event flags");
    Check(!instance->Initialize(nullptr, nullptr, 0), "missing core rejected");
    destroy(instance); FreeLibrary(dll);
    printf("PASS: %u native checks\n", checks);
}
