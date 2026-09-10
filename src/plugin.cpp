#include "patch.h"
#include "discovery.h"
#include <Ashita.h>
#include <MinHook.h>
#include <intrin.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>

namespace {
using namespace limitbreak;
using Query = void (WINAPI*)(LPMEMORYSTATUS);
Query originalQuery = nullptr;
HANDLE logFile = INVALID_HANDLE_VALUE;
SRWLOCK logLock = SRWLOCK_INIT;
SRWLOCK patchLock = SRWLOCK_INIT;
std::atomic<int> state{0}; // 0 inert, 1 armed, 2 patched, 3 verified, -1 refused/failure, 4 released, 5 allocation fallback
uintptr_t gameBase = 0;
std::array<uint32_t, 5> poolGlobals{};
bool patchRequested = false;
unsigned logBytes = 0;
ULONGLONG armedAt = 0;
bool missedReported = false;
constexpr int DryArmed = 10, DryRunning = 11, DryValidated = 12;

void Log(const char* event, const char* details) {
    AcquireSRWLockExclusive(&logLock);
    if (logFile != INVALID_HANDLE_VALUE && logBytes < 1024u * 1024u) {
        SYSTEMTIME now{}; GetSystemTime(&now);
        char line[1400];
        const int count = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "%04u-%02u-%02uT%02u:%02u:%02uZ %s %s\r\n", now.wYear, now.wMonth,
            now.wDay, now.wHour, now.wMinute, now.wSecond, event, details);
        if (count > 0) {
            DWORD wrote = 0;
            if (WriteFile(logFile, line, static_cast<DWORD>(count), &wrote, nullptr)) logBytes += wrote;
            FlushFileBuffers(logFile);
        }
    }
    ReleaseSRWLockExclusive(&logLock);
}
void Refuse(const char* reason) { state.store(-1); Log("REFUSED", reason); }

void DiscoverStartup(uintptr_t caller, HMODULE module, LPMEMORYSTATUS memory) {
    // The cheap return-site prefilter selects the same known initializer shape
    // as the prototype; no module-relative address participates in this path.
    // tests/test_startup_prefilter.py checks these bytes against INITIALIZER.
    constexpr unsigned char prefix[]{0x8b,0x44,0x24,0x10,0xb9,0x00,0x20,0xa0,0x05};
    unsigned char actual[sizeof(prefix)]{};
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(caller), &owner) || owner != module
        || !Read(reinterpret_cast<void*>(caller), actual, sizeof(actual))
        || memcmp(actual, prefix, sizeof(prefix)) != 0) return;
    int expected = patchRequested ? 1 : DryArmed;
    if (!state.compare_exchange_strong(expected, DryRunning)) return;
    AcquireSRWLockExclusive(&patchLock);
    struct Unlock { ~Unlock() { ReleaseSRWLockExclusive(&patchLock); } } unlock;
    if (state.load() != DryRunning) return;
    try {
        const auto base = reinterpret_cast<uintptr_t>(module);
        const auto result = discovery::Discover(static_cast<uint32_t>(base),
            [base](uint32_t rva, void* output, size_t bytes) {
                return Read(reinterpret_cast<void*>(base + rva), output, bytes);
            });
        char text[320];
        _snprintf_s(text, sizeof(text), _TRUNCATE, "candidates=%u validated=%u elapsed_ms=%.3f caller_rva=%08x",
            result.candidates, result.validated, result.milliseconds, static_cast<unsigned>(caller - base));
        Log(patchRequested ? "DISCOVERY" : "DRYRUN_DISCOVERY", text);
        for (const auto& failure : result.failures) Log(patchRequested ? "DISCOVERY_REJECTION" : "DRYRUN_REJECTION", failure.c_str());
        if (!result.valid || result.validated != 1) { Refuse("startup discovery did not produce one stable validated match"); return; }
        for (const auto& [name, rva] : result.match.addresses) {
            _snprintf_s(text, sizeof(text), _TRUNCATE, "%s=%08x", name.c_str(), rva); Log(patchRequested ? "DISCOVERY_RVA" : "DRYRUN_RVA", text);
        }
        _snprintf_s(text, sizeof(text), _TRUNCATE, "compare_operand=%08x store_operand=%08x cap_mib=%u",
            result.match.caps[0], result.match.caps[1], result.match.cap); Log(patchRequested ? "DISCOVERY_CAPS" : "DRYRUN_CAPS", text);
        for (size_t i = 0; i < 5; ++i) {
            _snprintf_s(text, sizeof(text), _TRUNCATE, "pool=%u head_global=%08x end_global=%08x wrapper=%08x",
                static_cast<unsigned>(i), result.match.globals[i], result.match.globals[i]+4, result.match.wrappers[i]);
            Log(patchRequested ? "DISCOVERY_POOL" : "DRYRUN_POOL", text);
        }
        for (const auto& check : result.match.passed) Log(patchRequested ? "DISCOVERY_CHECK" : "DRYRUN_CHECK", check.c_str());
        const bool callerMatches = caller == base + result.match.addresses.at("query_return");
        _snprintf_s(text, sizeof(text), _TRUNCATE, "caller_matches=%u pools_uninitialized=%u armed_to_query_ms=%llu",
            callerMatches ? 1u : 0u, result.match.uninitialized ? 1u : 0u, GetTickCount64() - armedAt);
        Log(patchRequested ? "DISCOVERY_TIMING" : "DRYRUN_TIMING", text);
        if (!callerMatches || !result.match.uninitialized) {
            Refuse("startup structures valid but startup timing not established"); return;
        }
        if (patchRequested) {
            if (!memory || memory->dwLength != sizeof(MEMORYSTATUS)
                || memory->dwTotalPhys / 1048576u < NewCap || result.match.cap != OriginalCap) {
                Refuse("insufficient physical memory or cap is not stock"); return;
            }
            const auto patched = PatchDiscovered(base, caller, memory->dwTotalPhys / 1048576u, result);
            if (patched == PatchResult::Applied) {
                gameBase = base;
                poolGlobals = result.match.globals;
                state.store(2);
                Log("PATCHED", "discovered physical-memory cap 256->384 MiB; target pool 320 MiB; capacity not yet verified");
            } else {
                Refuse(Name(patched));
                if (patched == PatchResult::RollbackFailed) {
                    Log("FATAL", "could not restore verified code; terminating to avoid executing a partial patch");
                    TerminateProcess(GetCurrentProcess(), 0xE0530001u);
                }
            }
            return;
        }
        state.store(DryValidated);
        Log(patchRequested ? "DISCOVERY_VALIDATED" : "DRYRUN_VALIDATED", "unique discovery at initializer query return before pool construction; FFXiMain and memory-query result unchanged; no patch");
    } catch (...) { Refuse("startup discovery exception"); }
}

void WINAPI MemoryQuery(LPMEMORYSTATUS memory) {
    const auto caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    originalQuery(memory);
    const DWORD savedError = GetLastError();
    if (state.load() == DryArmed || state.load() == 1) {
        const auto module = GetModuleHandleW(L"FFXiMain.dll");
        if (module) DiscoverStartup(caller, module, memory);
    }
    SetLastError(savedError);
}

class LimitBreak final : public IPolPlugin {
    friend struct StartupTestAccess;
    bool explicitTarget;
    bool dryRun;
    IChatManager* chat = nullptr;
    void WarnCapacity(bool structural) const {
        if (!chat) return;
        chat->Write(123, false, structural
            ? "[LimitBreak] CRITICAL: CAPACITY_STRUCTURAL_FAILURE - Startup pool layout is unexpected or unverified (320 MiB target). Restart without LimitBreak."
            : "[LimitBreak] WARNING: CAPACITY_FALLBACK - FFXI fell back to the known 64 MiB pool layout. LimitBreak did not achieve expanded capacity (320 MiB target).");
    }
public:
    explicit LimitBreak(const char* args) : explicitTarget(args && strcmp(args, "320") == 0),
        dryRun(args && strcmp(args, "discover") == 0) {}
    const char* GetName() const override { return "LimitBreak"; }
    const char* GetAuthor() const override { return "KraturLabs"; }
    const char* GetDescription() const override { return "Startup-only 320 MiB FFXI resource-pool expansion"; }
    const char* GetLink() const override { return ""; }
    double GetVersion() const override { return 1.0; }
    uint32_t GetFlags() const override {
        return static_cast<uint32_t>(Ashita::PluginFlags::UseDirect3D)
            | static_cast<uint32_t>(Ashita::PluginFlags::UseCommands);
    }
    bool Initialize(IAshitaCore* core, ILogManager*, uint32_t) override {
        if (!core || state.load() != 0) return false;
        chat = core->GetChatManager();
        try {
            const char* install = core->GetInstallPath();
            if (!install) return false;
            const std::u8string utf8(install, install + strlen(install));
            const auto root = std::filesystem::path(utf8);
            const auto directory = root / "logs" / "limitbreak";
            std::filesystem::create_directories(directory);
            wchar_t name[80];
            swprintf_s(name, L"limitbreak-%lu-%llu.log", GetCurrentProcessId(), GetTickCount64());
            logFile = CreateFileW((directory / name).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (logFile == INVALID_HANDLE_VALUE) return false;
            Log("START", "LimitBreak 1.0 Ashita 4.30 x86; startup-only resource-pool expansion; no on-disk game patch");
            if (!explicitTarget && !dryRun) { Refuse("requires explicit POL argument 320 or discover"); return false; }
            if (dryRun) Log(patchRequested ? "DISCOVERY_START" : "DRYRUN_START", "read-only native discovery; kernel32 memory-query interception only; no FFXiMain writes or hash/RVA compatibility gate");
            patchRequested = explicitTarget;
            HMODULE pinned = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&MemoryQuery), &pinned)) {
                Refuse("could not pin callback module"); return false;
            }
            const auto initialized = MH_Initialize();
            if (initialized != MH_OK) { Refuse("MinHook initialization failed"); return false; }
            const auto target = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GlobalMemoryStatus"));
            if (!target || MH_CreateHook(target, &MemoryQuery, reinterpret_cast<void**>(&originalQuery)) != MH_OK) {
                Refuse("could not prepare GlobalMemoryStatus hook"); return false;
            }
            armedAt = GetTickCount64();
            state.store(dryRun ? DryArmed : 1);
            if (MH_EnableHook(target) != MH_OK) { Refuse("could not enable GlobalMemoryStatus hook"); return false; }
            Log("ARMED", dryRun ? "waiting for structurally recognized initializer query; one discovery pass; no patch"
                : "waiting for uniquely validated pool-initializer call; other memory queries pass through unchanged");
            return true;
        } catch (...) { Refuse("initialization exception"); return false; }
    }
    void Direct3DPresent(const RECT*, const RECT*, HWND, const RGNDATA*) override {
        if (dryRun) {
            if (state.load() == DryArmed) Refuse("dry-run missed initializer query before first render; startup timing unverified");
            return;
        }
        if (state.load() == 1 && !missedReported && GetTickCount64() - armedAt > 30000) {
            missedReported = true;
            Refuse("startup query not intercepted before rendering; pool not enlarged");
        }
        if (state.load() != 2) return;
        // One snapshot at the first post-patch present, after startup pool creation.
        // Every outcome leaves state 2; this is not ongoing integrity monitoring.
        PoolLayout pools{};
        bool readable = true;
        for (size_t i = 0; i < pools.size(); ++i)
            readable = Read(reinterpret_cast<void*>(gameBase + poolGlobals[i]), &pools[i], sizeof(pools[i])) && readable;
        if (!readable) {
            state.store(-1);
            Log("CAPACITY_STRUCTURAL_FAILURE", "five-pool startup bounds unreadable; layout could not be verified");
            WarnCapacity(true);
            return;
        }
        const auto result = VerifyLayout(pools);
        char message[320];
        _snprintf_s(message, sizeof(message), _TRUNCATE,
            "target=320 pools=%08x:%08x,%08x:%08x,%08x:%08x,%08x:%08x,%08x:%08x",
            pools[0].head, pools[0].end, pools[1].head, pools[1].end,
            pools[2].head, pools[2].end, pools[3].head, pools[3].end, pools[4].head, pools[4].end);
        if (result == LayoutResult::Expanded) {
            state.store(3); Log("CAPACITY_VERIFIED", message);
        } else if (result == LayoutResult::AllocationFallback) {
            state.store(5); Log("CAPACITY_FALLBACK", message);
            WarnCapacity(false);
        } else {
            state.store(-1); Log("CAPACITY_STRUCTURAL_FAILURE", message);
            WarnCapacity(true);
        }
    }
    bool HandleCommand(int32_t, const char* command, bool) override {
        if (!command || _stricmp(command, "/limitbreak status") != 0) return false;
        char message[160];
        if (dryRun) _snprintf_s(message, sizeof(message), _TRUNCATE, "state=%d (10 discovery armed,11 running,12 dry-run validated,-1 refused); no patch; see logs/limitbreak", state.load());
        else _snprintf_s(message, sizeof(message), _TRUNCATE, "state=%d (1 armed,2 patched,3 verified,5 allocation 64 MiB fallback,-1 refused/structural failure); see logs/limitbreak", state.load());
        Log("STATUS", message);
        return true;
    }
    void Release() override {
        AcquireSRWLockExclusive(&patchLock);
        state.store(4);
        chat = nullptr;
        ReleaseSRWLockExclusive(&patchLock);
        Log("RELEASE", dryRun ? "dry-run released; memory-query hook remains passthrough; no FFXiMain changes"
            : "memory-query hook now passthrough; pool/cap are not shrunk. Restart without plugin for rollback.");
        // A foreign hook may retain our callback/trampoline. Keep both pinned until process exit.
        // The single log handle and MinHook storage are also retained; no instance pointer is used by the hook.
    }
};
}
extern "C" IPolPlugin* __stdcall expCreatePolPlugin(const char* args) { return new LimitBreak(args); }
extern "C" void __stdcall expDestroyPlugin(void* instance) { delete static_cast<LimitBreak*>(instance); }
extern "C" double __stdcall expGetInterfaceVersion() { return ASHITA_INTERFACE_VERSION; }
