#include "discovery.h"
#include "patch.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("usage: discovery_check capture.bin loaded-base");
        const auto base64 = std::stoull(argv[2], nullptr, 0);
        if (base64 > UINT32_MAX) throw std::runtime_error("invalid base");
        std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
        const auto length = file.tellg();
        if (!file || length < 0 || length > 64 * 1048576) throw std::runtime_error("invalid capture size");
        std::vector<char> data(static_cast<size_t>(length)); file.seekg(0);
        if (!file.read(data.data(), static_cast<std::streamsize>(data.size()))) throw std::runtime_error("capture read failed");
        const auto result = limitbreak::discovery::Discover(static_cast<uint32_t>(base64),
            [&data](uint32_t offset, void* output, size_t size) {
                if (uint64_t(offset) + size > data.size()) return false;
                memcpy(output, data.data() + offset, size); return true;
            });
        // Exercise the production patch gate against a disposable copy for every
        // parity/mutation case. Never execute or persist proprietary instructions.
        const auto trial = [](const std::vector<char>& bytes, const limitbreak::discovery::Result& found) {
            auto* copy = static_cast<unsigned char*>(VirtualAlloc(nullptr, bytes.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!copy) throw std::runtime_error("test allocation failed");
            memcpy(copy, bytes.data(), bytes.size());
            auto expected = bytes;
            const auto it = found.match.addresses.find("query_return");
            const auto offset = it == found.match.addresses.end() ? 0 : it->second;
            const bool shouldPatch = found.valid && found.validated == 1 && found.match.uninitialized && found.match.cap == 256;
            const auto status = limitbreak::PatchDiscovered(reinterpret_cast<uintptr_t>(copy),
                reinterpret_cast<uintptr_t>(copy) + offset, 4096, found);
            if (shouldPatch) for (const auto operand : found.match.caps)
                memcpy(expected.data() + operand, &limitbreak::NewCap, 4);
            const bool good = (status == limitbreak::PatchResult::Applied) == shouldPatch
                && memcmp(copy, expected.data(), expected.size()) == 0;
            VirtualFree(copy, 0, MEM_RELEASE);
            if (!good) throw std::runtime_error("discovery-to-patch byte invariant failed");
        };
        trial(data, result);
        if (result.valid && result.match.cap == 256) {
            auto startup = data;
            for (const auto global : result.match.globals) memset(startup.data() + global, 0, 8);
            const auto early = limitbreak::discovery::Discover(static_cast<uint32_t>(base64),
                [&startup](uint32_t offset, void* output, size_t size) {
                    if (uint64_t(offset) + size > startup.size()) return false;
                    memcpy(output, startup.data() + offset, size); return true;
                });
            if (!early.valid || !early.match.uninitialized) throw std::runtime_error("startup rediscovery failed");
            trial(startup, early);
        }
        std::cout << limitbreak::discovery::Json(result) << '\n';
        return result.valid ? 0 : 2;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
}
