#ifndef CODEGEN_X86_ADXLOWERING_HPP
#define CODEGEN_X86_ADXLOWERING_HPP

#include <codegen/x86/StubBodyBuilder.hpp>
#include <optional>

namespace Codegen {

struct AdxOperands {
    bool Overflow;
    std::uint8_t Destination;
    std::uint8_t Source;
    bool Wide;
    std::optional<MemoryOperand> Memory;
};

[[nodiscard]] std::optional<AdxOperands> DecodeAdx(const std::uint8_t* data, std::size_t length);
[[nodiscard]] const char* AdxName(const AdxOperands& operands);
void EmitAdx(StubBodyBuilder& body, const AdxOperands& operands);

}

#endif
