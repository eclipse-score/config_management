// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

#include "score/config_management/lib/parameter_set_json_serializer/details/parameter_set_json_serializer_impl.h"
#include "score/config_management/lib/parameter_set_json_serializer/error/error.h"

#include "score/json/internal/model/any.h"
#include "score/json/internal/model/number.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <string>
#include <string_view>

namespace score
{
namespace config_management
{

namespace
{

/// First code point that does not have to be escaped in a JSON string (RFC 8259, section 7).
constexpr std::uint8_t kFirstNonControlCharacter{0x20U};
constexpr std::string_view kLowercaseHexDigits{"0123456789abcdef"};

/// Largest qualifier value that fits into the 1 octet budgeted by BUD-02 of the Parameter Set JSON Format Contract.
constexpr std::uint8_t kMaxQualifier{9U};

/// @brief Appends the given string as a quoted JSON string, escaping exactly the characters required by
/// RFC 8259 in the form pinned by STR-01 of the Parameter Set JSON Format Contract.
void AppendEscaped(const std::string_view value, score::cpp::pmr::string& out)
{
    out += '"';
    for (const char character : value)
    {
        switch (character)
        {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\r':
                out += "\\r";
                break;
            default:
            {
                // 'char' may be signed; inspect the raw octet so that octets of multi-byte UTF-8 sequences
                // (>= 0x80) are never mistaken for control characters.
                const auto octet = static_cast<std::uint8_t>(character);
                if (octet < kFirstNonControlCharacter)
                {
                    out += "\\u00";
                    out += kLowercaseHexDigits[static_cast<std::size_t>(octet >> 4U)];
                    out += kLowercaseHexDigits[static_cast<std::size_t>(octet & 0x0FU)];
                }
                else
                {
                    out += character;
                }
                break;
            }
        }
    }
    out += '"';
}

score::Result<void> AppendDouble(const double value, score::cpp::pmr::string& out)
{
    // JSON (RFC 8259) has no token for NaN/Infinity; streaming them via operator<< would emit "nan"/"inf"/"-inf"
    // (formatting is locale/platform-dependent), producing invalid JSON that would break any conformant parser.
    // Refuse to guess a value (e.g. by falling back to `null`) and report an error instead.
    if (!std::isfinite(value))
    {
        return score::MakeUnexpected<void>(ParameterSetJsonSerializerError::kNonFiniteNumber);
    }
    std::ostringstream stream{};
    // Force the classic (C) locale so the decimal separator is always '.', independent of any globally imbued
    // locale that might otherwise cause e.g. ',' to be used, which would produce invalid JSON.
    stream.imbue(std::locale::classic());
    // A double with max_digits10 significant digits round-trips exactly and never exceeds 24 octets
    // as required by NUM-02 / BUD-01 of the Parameter Set JSON Format Contract.
    stream << std::setprecision(std::numeric_limits<double>::max_digits10) << value;
    out += stream.str();
    return {};
}

// Forward declaration: AppendValue and AppendList are mutually recursive (nested lists).
score::Result<void> AppendValue(const score::json::Any& value, score::cpp::pmr::string& out);

score::Result<void> AppendParameters(const score::json::Object& parameters, score::cpp::pmr::string& out)
{
    // STRUCT-02: one member per parameter, member name = parameter name, member value = parameter value.
    out += '{';
    bool is_first_entry{true};
    for (const auto& entry : parameters)
    {
        if (!is_first_entry)
        {
            out += ',';
        }
        is_first_entry = false;

        const auto key = entry.first.GetAsStringView();
        AppendEscaped(key, out);
        out += ':';
        const auto result = AppendValue(entry.second, out);
        if (!result.has_value())
        {
            return result;
        }
    }
    out += '}';
    return {};
}

score::Result<void> AppendList(const score::json::List& list, score::cpp::pmr::string& out)
{
    // STRUCT-04: one nesting level per dimension; element order (first dimension outermost) is preserved.
    out += '[';
    bool is_first_entry{true};
    for (const auto& element : list)
    {
        if (!is_first_entry)
        {
            out += ',';
        }
        is_first_entry = false;

        const auto result = AppendValue(element, out);
        if (!result.has_value())
        {
            return result;
        }
    }
    out += ']';
    return {};
}

score::Result<void> AppendNumber(const score::json::Number& number, score::cpp::pmr::string& out)
{
    // score::json::Number hides its actual underlying arithmetic type. The only way to recover a value from it is to
    // probe the supported alternatives via As<T>() and use the first one that succeeds without loss.
    //
    // This class is only ever used on JSON produced by parsing a JSON string via the score::json parser, which
    // guarantees that every number is stored either as an unsigned/signed integer (as small as it fits) or, for
    // floating-point numbers, always as a 'double' (never as a 'float'). Hand-constructed score::json::Object trees
    // that hold a 'float' value are out of scope for this class and are not probed for here.
    if (const auto unsigned_value = number.As<std::uint64_t>(); unsigned_value.has_value())
    {
        out += std::to_string(unsigned_value.value());
        return {};
    }
    if (const auto signed_value = number.As<std::int64_t>(); signed_value.has_value())
    {
        out += std::to_string(signed_value.value());
        return {};
    }
    if (const auto double_value = number.As<double>(); double_value.has_value())
    {
        return AppendDouble(double_value.value(), out);
    }
    // Every alternative of score::json::ArithmeticType that the parser can produce is expected to convert losslessly to
    // at least one of the types probed above. If none did, refuse to guess a value (which could silently write an
    // incorrect number into the output) and report an error instead.
    return score::MakeUnexpected<void>(ParameterSetJsonSerializerError::kUnsupportedNumberType);
}

score::Result<void> AppendValue(const score::json::Any& value, score::cpp::pmr::string& out)
{
    // A parameter value is a scalar (number or boolean) or a (nested) list thereof (STRUCT-02, STRUCT-04).
    if (const auto list = value.As<score::json::List>(); list.has_value())
    {
        return AppendList(list.value().get(), out);
    }
    if (const auto number = value.As<score::json::Number>(); number.has_value())
    {
        return AppendNumber(number.value().get(), out);
    }
    if (const auto boolean_value = value.As<bool>(); boolean_value.has_value())
    {
        out += boolean_value.value() ? "true" : "false";
        return {};
    }
    // Any other value (e.g. a score::json::Object, score::json::Null or a string) is not a valid parameter value as per
    // the contract and has no budget in the size formula. Refuse to emit it, as that could exceed the buffer size
    // computed at build time; report an error instead.
    return score::MakeUnexpected<void>(ParameterSetJsonSerializerError::kUnsupportedValueType);
}

}  // namespace

score::Result<score::cpp::pmr::string> ParameterSetJsonSerializerImpl::SerializeParameters(
    const score::json::Object& parameters) const
{
    score::cpp::pmr::string buffer{};
    const auto result = AppendParameters(parameters, buffer);
    if (!result.has_value())
    {
        return score::MakeUnexpected<score::cpp::pmr::string>(result.error());
    }
    return buffer;
}

score::Result<score::cpp::pmr::string> ParameterSetJsonSerializerImpl::SerializeParameterSet(
    const score::json::Object& parameters,
    const std::uint8_t qualifier) const
{
    // BUD-02: the qualifier is budgeted with 1 octet. Refuse any value that is not a single decimal digit, as it would
    // exceed the buffer size computed at build time.
    if (qualifier > kMaxQualifier)
    {
        return score::MakeUnexpected<score::cpp::pmr::string>(ParameterSetJsonSerializerError::kQualifierOutOfRange);
    }
    // STRUCT-01: exactly the two members "parameters" and "qualifier".
    score::cpp::pmr::string buffer{R"({"parameters":)"};
    const auto result = AppendParameters(parameters, buffer);
    if (!result.has_value())
    {
        return score::MakeUnexpected<score::cpp::pmr::string>(result.error());
    }
    // STRUCT-03 / BUD-02: numeric underlying value of the qualifier. Widen explicitly so that the value is never
    // formatted as a character.
    buffer += R"(,"qualifier":)";
    buffer += std::to_string(static_cast<std::uint32_t>(qualifier));
    buffer += '}';
    return buffer;
}

}  // namespace config_management
}  // namespace score
