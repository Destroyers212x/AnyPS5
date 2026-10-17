#include <codegen/x86/AdxLowering.hpp>
#include <codegen/CodegenException.hpp>
#include <algorithm>
#include <array>
#include <limits>

namespace Codegen {

namespace {

constexpr std::int32_t kFrameSize = 144;
constexpr std::int32_t kFlagsSlot = 8;
constexpr std::uint8_t kStack = 4;
constexpr std::uint8_t kOverflowBit = 11;

bool _prefix(std::uint8_t value) {
    return value == 0x2E || value == 0x36 || value == 0x3E || value == 0x26 || value == 0x64 || value == 0x65 || value == 0x67;
}

void _append32(std::vector<std::uint8_t>& bytes, std::int32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
}

std::uint8_t _rex(bool wide, std::uint8_t reg, std::uint8_t rm) {
    return static_cast<std::uint8_t>(0x40 | (wide ? 8 : 0) | ((reg & 8) >> 1) | ((rm & 8) >> 3));
}

void _register(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::uint8_t rm) {
    const std::array bytes{_rex(wide, reg, rm), opcode, static_cast<std::uint8_t>(0xC0 | ((reg & 7) << 3) | (rm & 7))};
    body.Raw(bytes);
}

void _registerImm8(StubBodyBuilder& body, std::initializer_list<std::uint8_t> opcode, std::uint8_t extension, std::uint8_t rm, std::uint8_t imm) {
    std::vector<std::uint8_t> bytes{_rex(true, 0, rm)};
    bytes.insert(bytes.end(), opcode);
    bytes.push_back(static_cast<std::uint8_t>(0xC0 | (extension << 3) | (rm & 7)));
    bytes.push_back(imm);
    body.Raw(bytes);
}

void _stack(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::int32_t displacement) {
    std::vector<std::uint8_t> bytes{_rex(wide, reg, kStack), opcode, static_cast<std::uint8_t>(0x84 | ((reg & 7) << 3)), 0x24};
    _append32(bytes, displacement);
    body.Raw(bytes);
}

void _pop(StubBodyBuilder& body, std::uint8_t reg) {
    const std::array bytes{_rex(false, 0, reg), static_cast<std::uint8_t>(0x58 | (reg & 7))};
    body.Raw(bytes);
}

std::uint8_t _scratch(const AdxOperands& operands) {
    std::array<bool, 16> used{};
    used[kStack] = used[operands.Destination] = true;
    if (!operands.Memory) {
        used[operands.Source] = true;
    } else {
        const auto& memory = *operands.Memory;
        if (memory.Rm == 4) {
            const auto base = static_cast<std::uint8_t>((memory.Sib & 7) | ((memory.RexIndexBase & 1) << 3));
            const auto index = static_cast<std::uint8_t>(((memory.Sib >> 3) & 7) | ((memory.RexIndexBase & 2) << 2));
            if (memory.Mod != 0 || (memory.Sib & 7) != 5) used[base] = true;
            if (index != kStack) used[index] = true;
        } else if (!memory.RipRelative) {
            used[memory.Rm | ((memory.RexIndexBase & 1) << 3)] = true;
        }
    }
    for (const auto reg : {11, 10, 9, 8, 0, 1, 2, 3, 5, 6, 7, 12, 13, 14, 15})
        if (!used[reg]) return static_cast<std::uint8_t>(reg);
    throw CodegenException("ADCX/ADOX has no scratch register");
}

void _memory(StubBodyBuilder& body, const AdxOperands& operands) {
    const auto& memory = *operands.Memory;
    auto displacement = static_cast<std::int64_t>(memory.Displacement);
    if (memory.StackBase) displacement += kFrameSize;
    const bool address32 = std::find(memory.Prefixes.begin(), memory.Prefixes.end(), 0x67) != memory.Prefixes.end();
    if (!address32 && displacement > std::numeric_limits<std::int32_t>::max())
        throw CodegenException("ADCX/ADOX stack displacement does not fit after spilling");
    const auto mod = memory.StackBase ? 2 : memory.Mod;
    auto bytes = memory.Prefixes;
    bytes.push_back(static_cast<std::uint8_t>(_rex(operands.Wide, operands.Destination, 0) | memory.RexIndexBase));
    bytes.push_back(0x13);
    bytes.push_back(static_cast<std::uint8_t>((mod << 6) | ((operands.Destination & 7) << 3) | memory.Rm));
    if (memory.Rm == 4) bytes.push_back(memory.Sib);
    const auto offset = bytes.size();
    if (mod == 1) bytes.push_back(static_cast<std::uint8_t>(displacement));
    if (mod == 2 || (mod == 0 && (memory.RipRelative || (memory.Rm == 4 && (memory.Sib & 7) == 5))))
        _append32(bytes, static_cast<std::int32_t>(displacement));
    if (memory.RipRelative)
        body.RipRelative(bytes, offset, static_cast<std::int64_t>(memory.InstructionLength) + memory.Displacement);
    else
        body.Raw(bytes);
}

void _pushFlags(StubBodyBuilder& body, std::uint8_t scratch) {
    const std::array pushf{std::uint8_t{0x9C}};
    body.Raw(pushf);
    _pop(body, scratch);
}

}

std::optional<AdxOperands> DecodeAdx(const std::uint8_t* data, const std::size_t length) {
    std::vector<std::uint8_t> prefixes;
    bool carry = false;
    bool overflow = false;
    bool other = false;
    std::size_t index = 0;
    for (; index < length; ++index) {
        const auto value = data[index];
        if (_prefix(value)) prefixes.push_back(value);
        else if (value == 0x66) carry = true;
        else if (value == 0xF3) overflow = true;
        else if (value == 0xF2 || value == 0xF0) other = true;
        else break;
    }
    std::uint8_t rex = 0;
    if (index < length && (data[index] & 0xF0) == 0x40) rex = data[index++];
    if (index + 4 > length || data[index] != 0x0F || data[index + 1] != 0x38 || data[index + 2] != 0xF6)
        return std::nullopt;
    if (other || (!carry && !overflow))
        return std::nullopt;
    if (carry && overflow)
        throw CodegenException("ADCX/ADOX has both 66 and F3 prefixes");
    const auto modrmOffset = index + 3;
    const auto modrm = data[modrmOffset];
    AdxOperands operands{
        overflow,
        static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((rex & 4) << 1)),
        static_cast<std::uint8_t>((modrm & 7) | ((rex & 1) << 3)),
        (rex & 8) != 0, std::nullopt};
    if ((modrm >> 6) == 3) {
        if (modrmOffset + 1 != length) throw CodegenException("ADCX/ADOX register operand has trailing bytes");
    } else {
        operands.Source = 0;
        operands.Memory = DecodeMemoryOperand(data, length, modrmOffset, static_cast<std::uint8_t>(rex & 3), std::move(prefixes));
        if (modrmOffset + operands.Memory->EncodedSize != length)
            throw CodegenException("ADCX/ADOX memory operand has trailing bytes");
    }
    return operands;
}

const char* AdxName(const AdxOperands& operands) {
    return operands.Overflow ? "ADOX" : "ADCX";
}

void EmitAdx(StubBodyBuilder& body, const AdxOperands& operands) {
    if (operands.Destination == kStack)
        throw CodegenException("ADCX/ADOX with an RSP destination is not lowered");
    const auto scratch = _scratch(operands);
    _stack(body, 0x8D, true, kStack, -kFrameSize);
    _stack(body, 0x89, true, scratch, 0);
    _pushFlags(body, scratch);
    _stack(body, 0x89, true, scratch, kFlagsSlot);
    if (operands.Overflow)
        _registerImm8(body, {0x0F, 0xBA}, 4, scratch, kOverflowBit);
    if (operands.Memory) {
        _memory(body, operands);
    } else if (operands.Source == kStack) {
        _stack(body, 0x8D, true, scratch, kFrameSize);
        _register(body, 0x13, operands.Wide, operands.Destination, scratch);
    } else {
        _register(body, 0x13, operands.Wide, operands.Destination, operands.Source);
    }
    _pushFlags(body, scratch);
    _registerImm8(body, {0x83}, 4, scratch, 1);
    if (operands.Overflow)
        _registerImm8(body, {0xC1}, 4, scratch, kOverflowBit);
    std::vector<std::uint8_t> clear{0x48, 0x81, 0xA4, 0x24};
    _append32(clear, kFlagsSlot);
    _append32(clear, ~static_cast<std::int32_t>(operands.Overflow ? 1 << kOverflowBit : 1));
    body.Raw(clear);
    _stack(body, 0x09, true, scratch, kFlagsSlot);
    std::vector<std::uint8_t> push{0xFF, 0xB4, 0x24};
    _append32(push, kFlagsSlot);
    body.Raw(push);
    const std::array popf{std::uint8_t{0x9D}};
    body.Raw(popf);
    _stack(body, 0x8B, true, scratch, 0);
    _stack(body, 0x8D, true, kStack, kFrameSize);
}

}
