#include "discovery.h"
#include "discovery_rules.generated.h"
#include <capstone/capstone.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>

namespace limitbreak::discovery {
namespace {
using Bytes = std::vector<unsigned char>;
using Values = std::map<std::string, uint32_t>;
struct Refusal : std::runtime_error { using std::runtime_error::runtime_error; };
void Need(bool ok, const std::string& why) { if (!ok) throw Refusal(why); }
std::string Hex(uint64_t value) { std::ostringstream s; s << "0x" << std::hex << value; return s.str(); }
std::string Trim(std::string s) {
    const auto first = s.find_first_not_of(" \r\n\t");
    return first == std::string::npos ? "" : s.substr(first, s.find_last_not_of(" \r\n\t") - first + 1);
}
uint32_t Number(const std::string& s) {
    const auto n = std::stoull(s, nullptr, 0); Need(n <= UINT32_MAX, "operand outside x86 range");
    return static_cast<uint32_t>(n);
}
template<class T> T At(const Bytes& bytes, size_t offset) {
    Need(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset, "short field");
    T value{}; memcpy(&value, bytes.data() + offset, sizeof(value)); return value;
}
void Append(Bytes& bytes, uint32_t value) {
    for (int i = 0; i < 4; ++i) bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
}
struct Section { uint32_t rva, size, flags; Bytes code; };
class Image {
    const Reader& reader;
    std::map<std::pair<uint32_t, uint32_t>, Bytes> reads;
public:
    uint32_t base, size = 64u * 1048576u, importRva = 0, importSize = 0;
    std::vector<Section> sections;
    Image(uint32_t b, const Reader& r) : reader(r), base(b) {
        const auto dos = Read(0, 64);
        Need(At<uint16_t>(dos, 0) == 0x5a4d, "missing DOS signature");
        const auto pe = At<uint32_t>(dos, 60);
        Need(pe >= 64 && pe <= 4096, "PE offset outside budget");
        const auto header = Read(pe, 24);
        Need(At<uint32_t>(header, 0) == 0x4550 && At<uint16_t>(header, 4) == 0x14c, "expected x86 PE");
        const auto count = At<uint16_t>(header, 6), optional = At<uint16_t>(header, 20);
        Need(count >= 1 && count <= 32 && optional == 224, "unsupported PE headers");
        const auto opt = Read(pe + 24, optional);
        Need(At<uint16_t>(opt, 0) == 0x10b, "expected PE32");
        size = At<uint32_t>(opt, 56);
        const auto headerSize = At<uint32_t>(opt, 60);
        Need(size >= 4096 && size <= 64u * 1048576u && headerSize && headerSize <= size, "invalid image size");
        Need(base >= 0x10000 && uint64_t(base) + size <= 0x100000000ull, "invalid x86 image base");
        importRva = At<uint32_t>(opt, 104); importSize = At<uint32_t>(opt, 108);
        for (uint32_t i = 0; i < count; ++i) {
            const auto s = Read(pe + 24 + optional + i * 40, 40);
            Section section{At<uint32_t>(s, 12), At<uint32_t>(s, 8), At<uint32_t>(s, 36), {}};
            Need(section.size && section.rva >= headerSize && uint64_t(section.rva) + section.size <= size, "invalid section bounds");
            for (const auto& prev : sections)
                Need(uint64_t(section.rva) + section.size <= prev.rva || uint64_t(prev.rva) + prev.size <= section.rva, "overlapping sections");
            sections.push_back(std::move(section));
        }
        for (auto& section : sections)
            if (section.flags & 0x20000000u) section.code = Read(section.rva, section.size);
    }
    Bytes Read(uint32_t rva, uint32_t amount) {
        Need(uint64_t(rva) + amount <= size, "read outside image");
        Bytes data(amount);
        Need(reader(rva, data.data(), amount), "unreadable range at RVA " + Hex(rva));
        reads.try_emplace({rva, amount}, data);
        return data;
    }
    uint32_t U32(uint32_t rva) { return At<uint32_t>(Read(rva, 4), 0); }
    const Section& Find(uint32_t rva, uint32_t amount = 1) const {
        for (const auto& section : sections)
            if (rva >= section.rva && uint64_t(rva) + amount <= uint64_t(section.rva) + section.size) return section;
        throw Refusal("derived address outside sections");
    }
    uint32_t Va(uint32_t address, uint32_t amount = 1, bool code = false, bool writable = false) const {
        Need(address >= base, "derived address below module");
        const auto rva = address - base;
        const auto& section = Find(rva, amount);
        Need(!code || (section.flags & 0x20000000u), "derived target is not executable");
        Need(!writable || ((section.flags & 0x80000000u) && !(section.flags & 0x20000000u)), "globals are not writable non-executable data");
        return rva;
    }
    std::string String(uint32_t rva) {
        std::string value;
        for (uint32_t i = 0; i < 256; ++i) {
            const auto b = Read(rva + i, 1)[0]; if (!b) return value;
            Need(b < 128, "non-ASCII import name"); value += static_cast<char>(b);
        }
        throw Refusal("unterminated import name");
    }
    Values Imports() {
        Need(importSize >= 20 && importSize <= 65536, "unsupported import directory");
        Values result;
        for (uint32_t i = 0; i < std::min(importSize / 20, 256u); ++i) {
            const auto desc = Read(importRva + i * 20, 20);
            const auto lookup = At<uint32_t>(desc, 0), name = At<uint32_t>(desc, 12), iat = At<uint32_t>(desc, 16);
            if (!lookup && !name && !iat) return result;
            Need(lookup && name && iat, "original import names unavailable");
            auto dll = String(name);
            std::transform(dll.begin(), dll.end(), dll.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            bool terminated = false;
            for (uint32_t j = 0; j < 4096; ++j) {
                const auto entry = U32(lookup + j * 4);
                if (!entry) { terminated = true; break; }
                if (entry & 0x80000000u) continue;
                const auto key = dll + ":" + String(entry + 2);
                Need(!result.contains(key), "duplicate named import");
                Va(base + iat + j * 4, 4); result[key] = base + iat + j * 4;
            }
            Need(terminated, "import thunk budget exceeded");
        }
        throw Refusal("unterminated import directory");
    }
    void Stable() {
        for (const auto& [range, before] : reads) {
            Bytes after(range.second);
            Need(reader(range.first, after.data(), after.size()) && after == before, "image changed/unreadable during discovery");
        }
    }
};
struct Instruction { uint32_t address; uint16_t size; uint8_t immOffset, immSize; std::string mnemonic, operand; };
struct Row { std::string expected; std::regex pattern; std::vector<std::pair<char, std::string>> variables; };
struct Rule { std::vector<Row> rows; std::map<std::string, size_t> labels; };
Rule Compile(const char* text) {
    Rule rule; std::istringstream input(text); std::string line;
    while (std::getline(input, line)) {
        line = Trim(line); if (line.empty()) continue;
        const auto colon = line.find(": ");
        if (colon != std::string::npos) { rule.labels[line.substr(0, colon)] = rule.rows.size(); line = line.substr(colon + 2); }
        Row row; row.expected = line; std::string pattern;
        for (size_t i = 0; i < line.size();) {
            if (line[i] == '$' || line[i] == '@') {
                const char type = line[i++]; const auto start = i;
                while (i < line.size() && (std::isalnum(static_cast<unsigned char>(line[i])) || line[i] == '_')) ++i;
                row.variables.emplace_back(type, line.substr(start, i - start));
                pattern += "(0x[0-9a-f]+|[0-9]+)";
            } else {
                if (std::string(".^$|()[]{}*+?\\").find(line[i]) != std::string::npos) pattern += '\\';
                pattern += line[i++];
            }
        }
        row.pattern = std::regex(pattern); rule.rows.push_back(std::move(row));
    }
    return rule;
}
struct Bound { Values values, labels; std::vector<Instruction> instructions; };
class Engine {
    Image& image;
    csh decoder = 0;
    std::map<const char*, Rule> rulesCache;
    Values imports;
public:
    explicit Engine(Image& i) : image(i), imports(i.Imports()) {
        Need(cs_open(CS_ARCH_X86, CS_MODE_32, &decoder) == CS_ERR_OK, "decoder unavailable");
        if (cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) { cs_close(&decoder); throw Refusal("decoder detail unavailable"); }
    }
    ~Engine() { cs_close(&decoder); }
    std::vector<Instruction> Decode(uint32_t address, uint32_t budget = 1024) {
        const auto rva = image.Va(address, 1, true);
        const auto& section = image.Find(rva);
        const auto data = image.Read(rva, std::min(budget, section.rva + section.size - rva));
        cs_insn* decoded = nullptr;
        const auto count = cs_disasm(decoder, data.data(), data.size(), address, 0, &decoded);
        std::vector<Instruction> result;
        try {
            for (size_t i = 0; i < count; ++i) {
                const auto& ins = decoded[i]; Need(ins.detail != nullptr, "missing instruction detail");
                result.push_back({static_cast<uint32_t>(ins.address), ins.size,
                    ins.detail->x86.encoding.imm_offset, ins.detail->x86.encoding.imm_size, ins.mnemonic, ins.op_str});
            }
        } catch (...) { cs_free(decoded, count); throw; }
        cs_free(decoded, count); return result;
    }
    Bound Bind(uint32_t address, const char* text, Values values = {}) {
        if (!rulesCache.contains(text)) rulesCache.emplace(text, Compile(text));
        const auto& rule = rulesCache.at(text);
        auto ins = Decode(address);
        Need(ins.size() >= rule.rows.size(), "short/undecodable function"); ins.resize(rule.rows.size());
        Bound bound{std::move(values), {}, std::move(ins)};
        for (const auto& [label, index] : rule.labels) bound.labels[label] = bound.instructions[index].address;
        for (size_t i = 0; i < rule.rows.size(); ++i) {
            const auto& row = rule.rows[i]; const auto& instruction = bound.instructions[i];
            const auto actual = Trim(instruction.mnemonic + " " + instruction.operand);
            std::smatch match;
            Need(std::regex_match(actual, match, row.pattern), "semantic mismatch at RVA " + Hex(instruction.address - image.base) + ": " + row.expected);
            for (size_t j = 0; j < row.variables.size(); ++j) {
                const auto& [type, name] = row.variables[j]; const auto value = Number(match[j + 1].str());
                if (type == '@') Need(bound.labels.at(name) == value, "branch target relationship mismatch: " + name);
                else {
                    Need(!bound.values.contains(name) || bound.values.at(name) == value, "operand relationship mismatch: " + name);
                    bound.values[name] = value;
                }
            }
        }
        return bound;
    }
    std::vector<uint32_t> Search(const Bytes& needle) {
        std::vector<uint32_t> result;
        for (const auto& section : image.sections) {
            auto at = section.code.begin();
            while ((at = std::search(at, section.code.end(), needle.begin(), needle.end())) != section.code.end()) {
                result.push_back(image.base + section.rva + static_cast<uint32_t>(at - section.code.begin()));
                Need(result.size() <= 256, "candidate budget exceeded"); ++at;
            }
        }
        return result;
    }
    uint32_t Import(const std::string& name) {
        const auto key = "kernel32.dll:" + name;
        Need(imports.contains(key), name + " named import missing"); return imports.at(key);
    }
    Match Validate(uint32_t address, uint32_t memory) {
        Match result;
        const auto init = Bind(address, rules::INITIALIZER, {{"memory_iat", memory}});
        const auto& v = init.values;
        result.cap = v.at("cap"); Need(result.cap == 256 || result.cap == 384, "unsupported cap pair");
        result.addresses["initializer"] = address - image.base;
        result.addresses["query_return"] = init.labels.at("query_return") - image.base;
        size_t index = 0;
        for (const auto name : {"cap_compare", "cap_store"}) {
            const auto at = init.labels.at(name);
            const auto& i = *std::find_if(init.instructions.begin(), init.instructions.end(), [at](const Instruction& x) { return x.address == at; });
            Need(i.immSize == 4 && i.immOffset, "cap is not an imm32 operand");
            result.caps[index++] = at + i.immOffset - image.base;
            Need(image.U32(at + i.immOffset - image.base) == result.cap, "cap decoding mismatch");
        }
        const auto& last = init.instructions.back();
        result.patchBytes = image.Read(result.addresses.at("query_return"),
            last.address + last.size - init.labels.at("query_return"));
        result.passed.push_back("complete initializer, equal caps, calculation, internal branches and 64 MiB fallback");
        uint32_t builder = 0; std::set<uint32_t> wrappers;
        for (size_t i = 0; i < 5; ++i) {
            const auto wrapper = v.at("pool" + std::to_string(i));
            const auto w = Bind(wrapper, rules::POOL_WRAPPER).values;
            const auto head = w.at("head");
            Need(uint64_t(head) + 4 == w.at("end") && head % 4 == 0, "invalid pool global pair");
            result.globals[i] = image.Va(head, 8, false, true);
            result.wrappers[i] = wrapper - image.base; wrappers.insert(wrapper);
            Need(!builder || builder == w.at("builder"), "builders do not converge"); builder = w.at("builder");
            Need(result.globals[i] == result.globals[0] + i * 8, "globals not distinct contiguous slots");
        }
        Need(wrappers.size() == 5, "aliased construction wrappers"); Bind(builder, rules::BUILDER);
        result.addresses["builder"] = builder - image.base;
        result.passed.push_back("five wrappers, shared builder, aligned headers/sentinel and physical order 0,1,3,2,4");
        const auto head = image.base + result.globals[0];
        Bytes routeNeedle{0x8b, 0x0d}; Append(routeNeedle, head + 4); routeNeedle.insert(routeNeedle.end(), {0x8b, 0x15}); Append(routeNeedle, head);
        uint32_t routes = 0; std::string routeError;
        for (const auto route : Search(routeNeedle)) {
            try {
                const auto r = Bind(route, rules::RESOURCE_ROUTE, {{"head", head}, {"end", head + 4}}).values;
                const auto a = Bind(r.at("reverse"), rules::REVERSE).values;
                Bind(a.at("size_helper"), rules::SIZE_HELPER);
                Need(a.at("request") == head + 40 && a.at("tag") == head + 44, "allocator scratch/tag relationship mismatch");
                image.Va(a.at("request"), 8, false, true); image.Va(r.at("vtable"), 4); image.Va(r.at("route_failure"), 1, true);
                Bytes needle{0x8b, 0x44, 0x24, 0x04, 0x8b, 0x15}; Append(needle, a.at("request"));
                uint32_t dispatcher = 0, dispatchers = 0;
                for (const auto candidate : Search(needle)) {
                    try {
                        const auto d = Bind(candidate, rules::DISPATCH, {{"request", a.at("request")}}).values;
                        const auto table = image.Read(image.Va(d.at("table"), 28), 28);
                        Need(At<uint32_t>(table, 4) == route, "selector 1 does not reach resource route");
                        for (size_t j = 0; j < 7; ++j) image.Va(At<uint32_t>(table, j * 4), 1, true);
                        image.Va(d.at("default"), 1, true); dispatcher = candidate; ++dispatchers;
                    } catch (const Refusal&) {}
                }
                Need(dispatchers == 1, "resource dispatcher missing or ambiguous"); ++routes;
                result.addresses["resource_dispatcher"] = dispatcher - image.base;
                result.addresses["resource_route"] = route - image.base;
                result.addresses["reverse_allocator"] = r.at("reverse") - image.base;
                result.addresses["size_helper"] = a.at("size_helper") - image.base;
            } catch (const Refusal& error) { if (routeError.size() < 1024) routeError += std::string(error.what()) + "; "; }
        }
        Need(routes == 1, "reverse relationship missing/unsupported/ambiguous: " + routeError);
        result.passed.push_back("unique selector-1 route, reverse allocator split/free-list/null-return and size helper");
        const auto backing = Bind(v.at("backing"), rules::BACKING).values;
        const auto retry = Bind(backing.at("retry"), rules::RETRY).values;
        image.Va(retry.at("new_handler"), 1, true);
        const auto heap = Import("HeapAlloc");
        auto adapter = Decode(retry.at("heap_adapter"), 512);
        Bind(retry.at("heap_adapter"), rules::ADAPTER_PREFIX);
        size_t epilogue = 0;
        for (size_t i = 0; i + 1 < adapter.size(); ++i)
            if (adapter[i].mnemonic == "leave" && adapter[i + 1].mnemonic == "ret") { epilogue = i + 2; break; }
        Need(epilogue != 0, "backing adapter epilogue unavailable"); adapter.resize(epilogue);
        size_t heapIndex = 0, heapCount = 0;
        for (size_t i = 0; i < adapter.size(); ++i) {
            const auto& ins = adapter[i];
            if (ins.mnemonic.starts_with('j'))
                Need(ins.operand.starts_with("0x") && Number(ins.operand) >= adapter.front().address && Number(ins.operand) <= adapter.back().address, "backing branch leaves bounded function");
            if (ins.mnemonic == "call" && ins.operand == "dword ptr [" + Hex(heap) + "]") { heapIndex = i; ++heapCount; }
        }
        Need(heapCount == 1 && heapIndex >= 2, "unique HeapAlloc tail missing");
        const auto tail = Bind(adapter[heapIndex - 2].address, rules::HEAP_TAIL, {{"heap_iat", heap}}).values;
        image.Va(tail.at("heap_handle"), 4, false, true);
        for (const auto& [name, value] : Values{{"backing_wrapper", v.at("backing")}, {"backing_retry", backing.at("retry")},
                {"heap_adapter", retry.at("heap_adapter")}, {"memory_status_iat", memory}, {"heap_alloc_iat", heap}})
            result.addresses[name] = value - image.base;
        result.passed.push_back("same initial/fallback backing wrapper, CRT retry and HeapAlloc tail linked");
        const auto bounds = image.Read(result.globals[0], 40);
        result.uninitialized = std::all_of(bounds.begin(), bounds.end(), [](unsigned char b) { return !b; });
        if (result.uninitialized) result.layout = "uninitialized";
        else {
            std::array<uint32_t, 5> heads{}, ends{};
            for (size_t i = 0; i < 5; ++i) { heads[i] = At<uint32_t>(bounds, i * 8); ends[i] = At<uint32_t>(bounds, i * 8 + 4); }
            const auto span = uint64_t(ends[0]) - heads[0]; uint32_t capacity = 0;
            for (const auto n : {64u, 192u, 320u}) if (span == uint64_t(n) * 1048576 - 144) capacity = n;
            Need(capacity != 0, "unexpected resource pool span");
            Need((result.cap == 256 && (capacity == 64 || capacity == 192)) || (result.cap == 384 && (capacity == 64 || capacity == 320)), "cap/layout disagreement");
            const uint32_t budgets[]{capacity * 1048576u, 10u * 1048576u, 16u * 1048576u, 4096, 4096};
            for (size_t i = 0; i < 5; ++i)
                Need(heads[i] >= 0x10000 && ends[i] > heads[i] && uint64_t(ends[i]) + 32 <= 0x100000000ull && heads[i] % 16 == 0 && ends[i] % 16 == 0 && ends[i] - heads[i] == budgets[i] - 144, "malformed pool bounds/span/alignment");
            constexpr size_t order[]{0, 1, 3, 2, 4};
            for (size_t i = 1; i < 5; ++i) Need(uint64_t(ends[order[i-1]]) + 144 == heads[order[i]], "mixed/overlapping pool layout");
            result.layout = std::to_string(capacity) + " MiB complete layout";
        }
        result.passed.push_back("pool globals: " + result.layout);
        return result;
    }
    Result Run() {
        const auto memory = Import("GlobalMemoryStatus"); Bytes needle{0xff, 0x15}; Append(needle, memory);
        std::set<uint32_t> candidates;
        for (const auto call : Search(needle)) {
            for (const auto& section : image.sections) {
                if (call < image.base + section.rva) continue;
                const auto relative = call - image.base - section.rva;
                if (relative >= section.code.size()) continue;
                for (auto at = relative > 64 ? relative - 64 : 0; at < relative; ++at)
                    if (at + 3 <= section.code.size() && section.code[at] == 0x83 && section.code[at+1] == 0xec && section.code[at+2] == 0x20)
                        candidates.insert(image.base + section.rva + at);
            }
        }
        Need(candidates.size() <= 64, "initializer candidate budget exceeded");
        Result result; result.candidates = static_cast<uint32_t>(candidates.size());
        for (const auto candidate : candidates) {
            try { result.match = Validate(candidate, memory); ++result.validated; }
            catch (const Refusal& error) { result.failures.push_back(Hex(candidate - image.base) + ": " + error.what()); }
        }
        result.valid = result.validated == 1;
        if (!result.valid) result.failures.push_back(result.validated ? "ambiguous fully validated initializers" : "no fully validated initializer");
        image.Stable(); return result;
    }
};
std::string Quote(const std::string& value) {
    std::string out = "\"";
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 32) out += ' ';
        else out += static_cast<char>(c);
    }
    return out + '"';
}
}
Result Discover(uint32_t base, const Reader& reader) {
    const auto began = std::chrono::steady_clock::now(); Result result;
    try { Image image(base, reader); Engine engine(image); result = engine.Run(); }
    catch (const std::exception& error) { result.valid = false; result.failures.push_back(error.what()); }
    catch (...) { result.valid = false; result.failures.push_back("unexpected discovery exception"); }
    result.milliseconds = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - began).count();
    return result;
}
std::string Json(const Result& r) {
    std::ostringstream s;
    s << "{\"status\":" << Quote(r.valid ? "discovered" : "refused") << ",\"candidate_count\":" << r.candidates
      << ",\"validated_count\":" << r.validated << ",\"milliseconds\":" << r.milliseconds
      << ",\"cap_mib\":" << r.match.cap << ",\"uninitialized\":" << (r.match.uninitialized ? "true" : "false")
      << ",\"layout\":" << Quote(r.match.layout) << ",\"addresses\":{";
    bool comma = false;
    for (const auto& [name, value] : r.match.addresses) { if (comma) s << ','; comma = true; s << Quote(name) << ':' << Quote(Hex(value)); }
    s << "},\"cap_operands\":[" << Quote(Hex(r.match.caps[0])) << ',' << Quote(Hex(r.match.caps[1])) << "],\"pool_globals\":[";
    for (size_t i = 0; i < 5; ++i) { if (i) s << ','; s << Quote(Hex(r.match.globals[i])); }
    s << "],\"wrappers\":[";
    for (size_t i = 0; i < 5; ++i) { if (i) s << ','; s << Quote(Hex(r.match.wrappers[i])); }
    s << "],\"failures\":[";
    for (size_t i = 0; i < r.failures.size(); ++i) { if (i) s << ','; s << Quote(r.failures[i]); }
    s << "],\"passed\":[";
    for (size_t i = 0; i < r.match.passed.size(); ++i) { if (i) s << ','; s << Quote(r.match.passed[i]); }
    return s.str() + "]}";
}
}
