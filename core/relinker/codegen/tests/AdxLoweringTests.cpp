#include <codegen/x86/AdxLowering.hpp>
#include <codegen/x86/IAmd64OnlyInstructionMatcher.hpp>
#include <codegen/CodegenException.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>
#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)
#include <sys/mman.h>
#endif

namespace {

using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename TCall>
bool rejects(TCall call) {
    try { call(); }
    catch (const Codegen::CodegenException&) { return true; }
    return false;
}

Bytes instruction(bool overflow, bool wide, std::uint8_t dst, std::uint8_t src) {
    return {static_cast<std::uint8_t>(overflow ? 0xF3 : 0x66),
        static_cast<std::uint8_t>(0x40 | (wide ? 8 : 0) | ((dst & 8) >> 1) | ((src & 8) >> 3)), 0x0F, 0x38, 0xF6,
        static_cast<std::uint8_t>(0xC0 | ((dst & 7) << 3) | (src & 7))};
}

void decoding() {
    for (bool overflow : {false, true}) {
        for (bool wide : {false, true}) {
            for (std::uint8_t dst = 0; dst < 16; ++dst) {
                for (std::uint8_t src = 0; src < 16; ++src) {
                    const auto bytes = instruction(overflow, wide, dst, src);
                    const auto operands = Codegen::DecodeAdx(bytes.data(), bytes.size());
                    require(operands && operands->Overflow == overflow && operands->Wide == wide && operands->Destination == dst && operands->Source == src && !operands->Memory, "ADCX/ADOX register decoding changed an operand");
                }
            }
        }
    }
    const Bytes noRex{0x66, 0x0F, 0x38, 0xF6, 0xC1};
    const auto plain = Codegen::DecodeAdx(noRex.data(), noRex.size());
    require(plain && !plain->Overflow && !plain->Wide && plain->Destination == 0 && plain->Source == 1, "ADCX without REX was not decoded");
    const Bytes memory{0x64, 0xF3, 0x67, 0x4F, 0x0F, 0x38, 0xF6, 0x8C, 0xAC, 0x10, 0, 0, 0};
    const auto operands = Codegen::DecodeAdx(memory.data(), memory.size());
    require(operands && operands->Overflow && operands->Wide && operands->Destination == 9 && operands->Memory && operands->Memory->RexIndexBase == 3 && operands->Memory->Prefixes == Bytes{0x64, 0x67}, "ADOX memory extensions or prefixes were lost");
    for (const Bytes bytes : {Bytes{0x90}, Bytes{0x0F, 0x38, 0xF6, 0xC1}, Bytes{0xF2, 0x0F, 0x38, 0xF6, 0xC1}, Bytes{0x66, 0x0F, 0x38, 0xF7, 0xC1}, Bytes{0x66, 0x0F, 0x38}})
        require(!Codegen::DecodeAdx(bytes.data(), bytes.size()), "Unrelated or truncated opcode matched ADCX/ADOX");
    for (const Bytes bytes : {Bytes{0x66, 0xF3, 0x0F, 0x38, 0xF6, 0xC1}, Bytes{0x66, 0x0F, 0x38, 0xF6, 0xC1, 0x90}, Bytes{0x66, 0x0F, 0x38, 0xF6, 0x84}})
        require(rejects([&] { (void)Codegen::DecodeAdx(bytes.data(), bytes.size()); }), "Malformed ADCX/ADOX was accepted");
    for (bool overflow : {false, true}) {
        const auto bytes = instruction(overflow, true, 4, 1);
        require(rejects([&] { Codegen::StubBodyBuilder body; Codegen::EmitAdx(body, *Codegen::DecodeAdx(bytes.data(), bytes.size())); }), "An RSP destination was lowered");
    }
    const Bytes overflowing{0x66, 0x48, 0x0F, 0x38, 0xF6, 0x84, 0x24, 0xFF, 0xFF, 0xFF, 0x7F};
    require(rejects([&] { Codegen::StubBodyBuilder body; Codegen::EmitAdx(body, *Codegen::DecodeAdx(overflowing.data(), overflowing.size())); }), "An overflowing stack displacement was silently wrapped");
}

void matching() {
    const auto intel = Codegen::MakeAmd64OnlyInstructionMatcher();
    const auto rosetta = Codegen::MakeAmd64OnlyInstructionMatcher(Codegen::Amd64OnlyTarget::Rosetta);
    for (bool overflow : {false, true}) {
        const auto bytes = instruction(overflow, true, 0, 6);
        require(!intel->Match(bytes.data(), bytes.size()), "Intel mode rewrote ADCX/ADOX");
        const auto match = rosetta->Match(bytes.data(), bytes.size());
        require(match && match->InstructionName == (overflow ? "ADOX" : "ADCX") && match->Lowering == Codegen::Amd64OnlyLowering::Trampoline && !match->Optional, "Rosetta mode did not require an ADCX/ADOX trampoline");
        const std::array<std::span<const std::uint8_t>, 2> sequence{bytes, bytes};
        require(rosetta->MatchSequence(sequence, {}).has_value(), "An ADCX/ADOX sequence could not move out of line");
    }
}

#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)

constexpr std::uint64_t kArithmeticFlags = 0x8D5;
constexpr std::uint64_t kCarry = 1;
constexpr std::uint64_t kOverflow = 0x800;

struct State {
    std::array<std::uint64_t, 16> Input{};
    std::array<std::uint64_t, 16> Output{};
    std::uint64_t Flags = 0;
    std::array<std::uint64_t, 16> RedZone{};
    std::uint64_t InputFlags = 2;
};

class Execution {
public:
    Execution(const Bytes& site, std::uint64_t memoryValue) {
        auto operands = Codegen::DecodeAdx(site.data(), site.size());
        require(operands.has_value(), "Execution site was not ADCX/ADOX");
        for (auto reg : {3, 5, 12, 13, 14, 15}) push(static_cast<std::uint8_t>(reg));
        memory(0x8D, 4, 4, -128);
        rip({0x48, 0x89, 0x3D}, 0);
        rip({0x48, 0x89, 0x25}, 8);
        memory(0x89, 4, 7, 32);
        bytes.insert(bytes.end(), {0xFF, 0xB7});
        append32(static_cast<std::int32_t>(offsetof(State, InputFlags)));
        bytes.push_back(0x9D);
        bytes.insert(bytes.end(), {0x48, 0xB8});
        append64(kSentinel);
        for (int displacement = -128; displacement < 0; displacement += 8)
            memory(0x89, 0, 4, displacement);
        memory(0x8B, 0, 7, 16 * 8);
        memory(0x89, 0, 4, 64);
        for (std::uint8_t reg = 0; reg < 16; ++reg)
            if (reg != 4 && reg != 7) memory(0x8B, reg, 7, reg * 8);
        memory(0x8B, 7, 7, 7 * 8);
        const auto siteOffset = bytes.size();
        if (operands->Memory && operands->Memory->RipRelative) {
            auto relocated = site;
            const auto displacement = static_cast<std::int32_t>(4096 + 24 - (siteOffset + site.size()));
            std::memcpy(relocated.data() + relocated.size() - 4, &displacement, sizeof(displacement));
            operands = Codegen::DecodeAdx(relocated.data(), relocated.size());
        }
        Codegen::StubBodyBuilder builder;
        Codegen::EmitAdx(builder, *operands);
        auto body = builder.Finish();
        const auto stubOffset = bytes.size();
        Codegen::ApplyStubRelocations(body.Bytes, body.Relocations, siteOffset, stubOffset, 0);
        bytes.insert(bytes.end(), body.Bytes.begin(), body.Bytes.begin() + static_cast<std::ptrdiff_t>(body.ReturnBranchOffset));
        rip({0x48, 0x89, 0x25}, 16);
        rip({0x48, 0x8B, 0x25}, 8);
        memory(0x8D, 4, 4, -256);
        for (std::uint8_t reg = 0; reg < 16; ++reg) if (reg != 4) push(reg);
        bytes.push_back(0x9C);
        rip({0x48, 0x8B, 0x3D}, 0);
        memory(0x8B, 0, 4, 0);
        memory(0x89, 0, 7, 32 * 8);
        int offset = 8;
        for (int reg = 15; reg >= 0; --reg) {
            if (reg == 4) continue;
            memory(0x8B, 0, 4, offset);
            memory(0x89, 0, 7, (16 + reg) * 8);
            offset += 8;
        }
        rip({0x48, 0x8B, 0x05}, 16);
        memory(0x89, 0, 7, 20 * 8);
        for (int slot = 0; slot < 16; ++slot) {
            memory(0x8B, 0, 4, 256 + slot * 8);
            memory(0x89, 0, 7, (33 + slot) * 8);
        }
        rip({0x48, 0x8B, 0x25}, 8);
        memory(0x8D, 4, 4, 128);
        for (auto reg : {15, 14, 13, 12, 5, 3}) pop(static_cast<std::uint8_t>(reg));
        bytes.push_back(0xC3);
        require(bytes.size() < 4096, "Execution wrapper exceeded its code page");
        code = static_cast<std::uint8_t*>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        require(code != MAP_FAILED, "Cannot allocate execution test pages");
        std::memcpy(code, bytes.data(), bytes.size());
        std::memcpy(code + 4096 + 24, &memoryValue, sizeof(memoryValue));
        require(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0, "Cannot make ADCX/ADOX test code executable");
    }

    ~Execution() { if (code != MAP_FAILED) munmap(code, 8192); }

    void Run(State& state) const { reinterpret_cast<void (*)(State*)>(code)(&state); }
    const void* Memory() const { return code + 4096 + 24; }
    static constexpr std::uint64_t kSentinel = 0xBADC0FFEE0DDF00Dull;

private:
    Bytes bytes;
    std::uint8_t* code = reinterpret_cast<std::uint8_t*>(MAP_FAILED);

    void append32(std::int32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
    }
    void append64(std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8) bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void rip(std::initializer_list<std::uint8_t> opcode, int slot) {
        bytes.insert(bytes.end(), opcode);
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void push(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x50 | (reg & 7)));
    }
    void pop(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x58 | (reg & 7)));
    }
    void memory(std::uint8_t opcode, std::uint8_t reg, std::uint8_t base, int displacement) {
        bytes.insert(bytes.end(), {static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1) | ((base & 8) >> 3)), opcode,
            static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | (base & 7))});
        if ((base & 7) == 4) bytes.push_back(0x24);
        append32(displacement);
    }
};

void check(const State& state, const Codegen::AdxOperands& operands, std::uint64_t second) {
    const auto mask = operands.Wide ? ~std::uint64_t{0} : 0xFFFFFFFFull;
    const auto first = state.Input[operands.Destination] & mask;
    second &= mask;
    const auto flag = operands.Overflow ? kOverflow : kCarry;
    const std::uint64_t in = (state.InputFlags & flag) != 0 ? 1 : 0;
    const auto sum = first + second + in;
    const auto expected = sum & mask;
    const bool carry = operands.Wide ? (sum < first || (sum == first && in != 0)) : (sum >> 32) != 0;
    for (std::size_t reg = 0; reg < 16; ++reg)
        require(state.Output[reg] == (reg == operands.Destination ? expected : state.Input[reg]), "ADCX/ADOX changed a source/scratch register or produced an incorrect result");
    const auto flags = (state.InputFlags & kArithmeticFlags & ~flag) | (carry ? flag : 0);
    require((state.Flags & kArithmeticFlags) == flags, "ADCX/ADOX changed a flag other than its own or computed its carry incorrectly");
    for (const auto value : state.RedZone) require(value == Execution::kSentinel, "ADCX/ADOX overwrote the caller's red zone");
}

State initialState() {
    State state;
    for (std::size_t reg = 0; reg < 16; ++reg) state.Input[reg] = 0xABCD123456789000ull + reg * 0x1234567ull;
    return state;
}

void execution() {
    constexpr std::array<std::uint64_t, 4> inputFlags{2, 2 | kArithmeticFlags, 2 | kCarry, 2 | kOverflow};
    for (bool overflow : {false, true}) {
        for (bool wide : {false, true}) {
            for (std::uint8_t dst = 0; dst < 16; ++dst) {
                if (dst == 4) continue;
                for (const std::uint8_t src : {std::uint8_t{6}, dst, std::uint8_t{11}, std::uint8_t{4}}) {
                    const auto site = instruction(overflow, wide, dst, src);
                    const Execution executable(site, 0);
                    for (int variant = 0; variant < 3; ++variant) {
                        for (const auto flags : inputFlags) {
                            auto state = initialState();
                            if (variant == 1) state.Input.fill(0);
                            if (variant == 2) state.Input.fill(~std::uint64_t{0});
                            state.InputFlags = flags;
                            executable.Run(state);
                            const auto second = src == 4 ? state.Output[4] : state.Input[src];
                            check(state, *Codegen::DecodeAdx(site.data(), site.size()), second);
                        }
                    }
                }
            }
            for (const Bytes tail : {Bytes{0x06}, Bytes{0x46, 0x10}, Bytes{0x84, 0x24, 0x40, 0, 0, 0}, Bytes{0x04, 0xCA}, Bytes{0x85, 0x10, 0, 0, 0}, Bytes{0x05, 0, 0, 0, 0}}) {
                Bytes site{static_cast<std::uint8_t>(overflow ? 0xF3 : 0x66), static_cast<std::uint8_t>(wide ? 0x48 : 0x40), 0x0F, 0x38, 0xF6};
                site.insert(site.end(), tail.begin(), tail.end());
                constexpr std::uint64_t value = 0xFEDCBA9876543210ull;
                const Execution executable(site, value);
                for (const auto flags : inputFlags) {
                    auto state = initialState();
                    state.Input[0] = ~std::uint64_t{0} - 5;
                    state.Input[6] = reinterpret_cast<std::uint64_t>(executable.Memory()) - (tail[0] == 0x46 ? 16 : 0);
                    state.Input[2] = reinterpret_cast<std::uint64_t>(executable.Memory()) - 3 * 8;
                    state.Input[1] = 3;
                    state.Input[5] = reinterpret_cast<std::uint64_t>(executable.Memory()) - 16;
                    state.Output[0] = value;
                    state.InputFlags = flags;
                    executable.Run(state);
                    check(state, *Codegen::DecodeAdx(site.data(), site.size()), value);
                }
            }
        }
    }
}
#else
void execution() { std::cout << "ADCX/ADOX execution checks require a Linux/macOS x86-64 build\n"; }
#endif

}

int main() {
    try {
        decoding();
        matching();
        execution();
        std::cout << "ADCX/ADOX lowering checks passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
