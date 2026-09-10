// Exercise the actual present callback without loading Ashita or a game client.
#include "../src/plugin.cpp"
#include <cstdlib>
#include <string>
#include <vector>

namespace {
struct StartupTestAccess {
    static void SetChat(LimitBreak& plugin, IChatManager* value) { plugin.chat = value; }
    static bool Target(const LimitBreak& plugin) { return plugin.explicitTarget; }
    static bool DryRun(const LimitBreak& plugin) { return plugin.dryRun; }
};
struct Chat final : IChatManager {
    std::vector<std::string> messages;
    std::vector<int32_t> modes;
    void Write(int32_t mode, bool, const char* message) override { modes.push_back(mode); messages.emplace_back(message); }
    void ParseCommand(int32_t, const char*) override {}
    void QueueCommand(int32_t, const char*) override {}
    void Writef(int32_t, bool, const char*, ...) override {}
    void AddChatMessage(int32_t, bool, const char*) override {}
    int32_t ParseAutoTranslate(const char*, char*, int32_t, bool) const override { return 0; }
    void ExecuteScript(const char*, const char*, bool) override {}
    void ExecuteScriptString(const char*, const char*, bool) override {}
    const char* GetInputTextRaw() const override { return ""; }
    void SetInputTextRaw(const char*, uint32_t) const override {}
    uint32_t GetInputTextRawLength() const override { return 0; }
    uint32_t GetInputTextRawCaretPosition() const override { return 0; }
    const char* GetInputTextParsed() const override { return ""; }
    void SetInputTextParsed(const char*) const override {}
    uint32_t GetInputTextParsedLength() const override { return 0; }
    uint32_t GetInputTextParsedLengthMax() const override { return 0; }
    const char* GetInputTextDisplay() const override { return ""; }
    void SetInputTextDisplay(const char*) const override {}
    void SetInputText(const char*) const override {}
    uint8_t IsInputOpen() const override { return 0; }
    bool GetSilentAliases() const override { return false; }
    void SetSilentAliases(bool) override {}
};
unsigned checks = 0;
void Check(bool value, const char* message) {
    if (!value) { fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
    ++checks;
}
PoolLayout Layout(uint32_t capacity) {
    const uint32_t head = 0x10000000, first = capacity * 1048576;
    return {{{head, head + first - 144},
        {head + first, head + first + 0xa00000 - 144},
        {head + first + 0xa01000, head + first + 0x1a01000 - 144},
        {head + first + 0xa00000, head + first + 0xa01000 - 144},
        {head + first + 0x1a01000, head + first + 0x1a02000 - 144}}};
}
void Run(uint32_t capacity, bool malformed, bool unreadable, bool haveChat = true) {
    LimitBreak plugin("320");
    Chat chat;
    StartupTestAccess::SetChat(plugin, haveChat ? &chat : nullptr);
    auto pools = Layout(capacity);
    if (malformed) pools[4].end -= 16;
    gameBase = unreadable ? 0 : reinterpret_cast<uintptr_t>(pools.data());
    for (size_t i = 0; i < poolGlobals.size(); ++i) poolGlobals[i] = static_cast<uint32_t>(i * sizeof(PoolBounds));
    state.store(2);
    logBytes = 0;
    Check(SetFilePointer(logFile, 0, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER && SetEndOfFile(logFile), "reset private test log");
    plugin.Direct3DPresent(nullptr, nullptr, nullptr, nullptr);
    const bool structural = malformed || unreadable || (capacity != 64 && capacity != 320);
    const int expected = structural ? -1 : capacity == 64 ? 5 : 3;
    Check(state.load() == expected, "startup outcome state preserved");
    Check(chat.messages.size() == (haveChat && expected != 3 ? 1u : 0u), "exactly one warning for each failure only");
    if (!chat.messages.empty()) {
        const auto& message = chat.messages[0];
        Check(chat.modes[0] == 123, "warning uses visible error chat mode");
        Check(message.find(structural ? "CRITICAL: CAPACITY_STRUCTURAL_FAILURE" : "WARNING: CAPACITY_FALLBACK") != std::string::npos, "visible outcome and severity");
        Check(message.find(structural ? "Restart without LimitBreak" : "known 64 MiB pool layout") != std::string::npos, "visible recovery or known fallback");
        Check(message.find(structural ? "unexpected or unverified" : "did not achieve expanded capacity") != std::string::npos, "visible limitation");
        Check(message.find("320 MiB target") != std::string::npos, "warning names canonical target");
    }
    const auto count = chat.messages.size();
    const auto bytes = logBytes;
    pools = {}; // A later changed/unreadable layout must not trigger another snapshot.
    gameBase = 0;
    plugin.Direct3DPresent(nullptr, nullptr, nullptr, nullptr);
    Check(state.load() == expected && chat.messages.size() == count && logBytes == bytes, "no repeated verification, warnings or logs");
    SetFilePointer(logFile, 0, nullptr, FILE_BEGIN);
    char contents[1400]{}; DWORD read = 0;
    Check(ReadFile(logFile, contents, sizeof(contents) - 1, &read, nullptr) != FALSE, "read private test log");
    const std::string logged(contents, read);
    Check(logged.find(structural ? "CAPACITY_STRUCTURAL_FAILURE" : capacity == 64 ? "CAPACITY_FALLBACK" : "CAPACITY_VERIFIED") != std::string::npos, "private outcome log preserved");
    Check(logged.find(unreadable ? "five-pool startup bounds unreadable; layout could not be verified" : "target=320 pools=") != std::string::npos, "private detail log preserved");
}
}
int main() {
    wchar_t directory[MAX_PATH]{}, path[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH, directory) != 0 && GetTempFileNameW(directory, L"lbt", 0, path) != 0, "create temporary log path");
    logFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    Check(logFile != INVALID_HANDLE_VALUE, "open disposable log");
    Check(StartupTestAccess::Target(LimitBreak("320")), "320 is the supported startup target");
    Check(!StartupTestAccess::Target(LimitBreak("384")), "retired 384 startup target refused");
    Check(!StartupTestAccess::Target(LimitBreak(nullptr)), "explicit target still required");
    Check(StartupTestAccess::DryRun(LimitBreak("discover")), "read-only discover preserved");
    Run(384, false, false);
    Run(320, false, false);
    Run(64, false, false);
    Run(192, false, false);
    Run(320, true, false);
    Run(320, false, true);
    Run(64, false, false, false);
    Run(320, false, true, false);
    CloseHandle(logFile);
    logFile = INVALID_HANDLE_VALUE;
    printf("%u startup callback checks passed\n", checks);
}
