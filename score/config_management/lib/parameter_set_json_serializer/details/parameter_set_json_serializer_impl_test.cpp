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
#include "score/json/json_parser.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <limits>
#include <locale>
#include <regex>
#include <string>
#include <string_view>
#include <utility>

namespace score
{
namespace config_management
{
namespace test
{

namespace
{

// Requirement IDs (e.g. STRUCT-01) and section numbers referenced in the test descriptions below refer to the
// Parameter Set JSON Format Contract.

constexpr auto kVerifiesSerializeParameters =
    "::score::config_management::ParameterSetJsonSerializerImpl::SerializeParameters()";
constexpr auto kVerifiesBoth =
    "::score::config_management::ParameterSetJsonSerializerImpl::SerializeParameters(), "
    "::score::config_management::ParameterSetJsonSerializerImpl::SerializeParameterSet()";

// Octet counts pinned by the contract (Section 4.4 and Section 5).
constexpr std::size_t kSkeletonOctets{30U};                   // {"parameters":{},"qualifier":}
constexpr std::size_t kQualifierOctets{1U};                   // BUD-02
constexpr std::size_t kColonOctets{1U};                       // the colon of "name":<value>
constexpr std::size_t kConfigCalibrationHeadroomOctets{29U};  // BUD-03
constexpr std::uint8_t kMaxQualifier{9U};                     // BUD-02: largest single decimal digit
constexpr std::size_t kLvalBool{5U};
constexpr std::size_t kLvalUint8{3U};
constexpr std::size_t kLvalUint16{5U};
constexpr std::size_t kLvalUint32{10U};
constexpr std::size_t kLvalUint64{20U};
constexpr std::size_t kLvalSint8{4U};
constexpr std::size_t kLvalSint16{6U};
constexpr std::size_t kLvalSint32{11U};
constexpr std::size_t kLvalSint64{20U};
constexpr std::size_t kLvalFloat{24U};

// UTF-8 encoding of the byte-order mark U+FEFF (ENC-01 forbids it in the payloads).
constexpr std::string_view kUtf8ByteOrderMark{"\xEF\xBB\xBF"};

// A minimal numpunct facet that uses ',' as the decimal separator, used to simulate a globally imbued locale
// that differs from the classic (C) locale.
class CommaDecimalPointNumpunct : public std::numpunct<char>
{
  protected:
    char do_decimal_point() const override
    {
        return ',';
    }
};

// Parses the given JSON text into a score::json::Object, exactly like the real production code path does. Test inputs
// are created through this helper rather than by assembling score::json::Any values directly, unless the input cannot
// be expressed through the parser (documented at the respective test).
score::json::Object ParseObject(const std::string_view json_text)
{
    auto parse_result = score::json::JsonParser{}.FromBuffer(json_text);
    if (!parse_result.has_value())
    {
        ADD_FAILURE() << "Failed to parse test JSON input: " << json_text;
        return {};
    }
    auto object_result = parse_result.value().As<score::json::Object>();
    if (!object_result.has_value())
    {
        ADD_FAILURE() << "Test JSON input did not parse to a JSON object: " << json_text;
        return {};
    }
    return std::move(object_result.value().get());
}

std::string ToStdString(const score::cpp::pmr::string& value)
{
    return std::string{value.data(), value.size()};
}

// Serializes the parameters {"v":<json_value_text>} and returns only the emitted text of the value.
std::string SerializeSingleValue(const ParameterSetJsonSerializerImpl& serializer,
                                 const std::string_view json_value_text)
{
    const std::string prefix{R"({"v":)"};
    const std::string input{prefix + std::string{json_value_text} + "}"};
    const auto result = serializer.SerializeParameters(ParseObject(input));
    if (!result.has_value())
    {
        ADD_FAILURE() << "Failed to serialize: " << input;
        return {};
    }
    const std::string output{ToStdString(result.value())};
    if ((output.size() <= prefix.size()) || (output.compare(0U, prefix.size(), prefix) != 0) || (output.back() != '}'))
    {
        ADD_FAILURE() << "score::Unexpected output framing: " << output;
        return {};
    }
    return output.substr(prefix.size(), output.size() - prefix.size() - 1U);
}

// frame(n, e) of Section 5.
std::size_t Frame(const std::size_t element_count, const std::size_t element_budget)
{
    return (element_count * element_budget) + ((element_count > 0U) ? (element_count - 1U) : 0U) + 2U;
}

// member(p) = str_len(name(p)) + 1 + value(p) of Section 5, str_len including the two enclosing quotes (STR-01).
std::size_t Member(const std::size_t name_str_len, const std::size_t value_budget)
{
    return name_str_len + kColonOctets + value_budget;
}

// budget(L) of Section 5.
std::size_t Budget(const std::initializer_list<std::size_t> members)
{
    std::size_t budget{kSkeletonOctets + kQualifierOctets};
    for (const auto member : members)
    {
        budget += member;
    }
    budget += (members.size() > 0U) ? (members.size() - 1U) : 0U;
    return budget;
}

}  // namespace

class ParameterSetJsonSerializerImplFixture : public ::testing::Test
{
  protected:
    ParameterSetJsonSerializerImpl serializer_{};
};

// ---------------------------------------------------------------------------------------------------------------
// Section 3: IPC payload JSON structure
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ParameterSetJsonSerializerImplFixture, SerializesBothPayloadsAsObjectWithOneMemberPerParameter)
{
    RecordProperty("Description",
                   "STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-05: Verifies that the InternalConfigProvider payload is "
                   "one JSON object with exactly the two members 'parameters' and 'qualifier' (numeric value), and "
                   "that the ConfigCalibration payload is the parameters object alone, without 'parameters' wrapper "
                   "and without 'qualifier'. The parameters object holds one member per parameter, member name = "
                   "parameter name, member value = parameter value.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    const std::string parameters_json{R"({"param_a":1,"param_b":true,"param_c":-2})"};
    const auto parameters = ParseObject(parameters_json);

    const auto parameters_result = serializer_.SerializeParameters(parameters);
    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, 2U);

    ASSERT_TRUE(parameters_result.has_value());
    ASSERT_TRUE(parameter_set_result.has_value());
    EXPECT_EQ(ToStdString(parameters_result.value()), parameters_json);
    EXPECT_EQ(ToStdString(parameter_set_result.value()), R"({"parameters":)" + parameters_json + R"(,"qualifier":2})");
}

TEST_F(ParameterSetJsonSerializerImplFixture, SerializesEmptyParametersWithQualifierBoundaryValuesWithinBudget)
{
    RecordProperty("Description",
                   "STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-05, BUD-02: Verifies that a parameter set without "
                   "parameters is emitted with an empty parameters object in both payloads, and that the qualifier is "
                   "emitted as its numeric value (not as a character) for the boundary values 0 and 9. The "
                   "worst-case qualifier value is emitted as a number of 1 octet, so that a parameter set without "
                   "parameters fits exactly into 30 + 1 octets.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    const auto parameters_result = serializer_.SerializeParameters(score::json::Object{});
    const auto min_qualifier_result = serializer_.SerializeParameterSet(score::json::Object{}, 0U);
    const auto max_qualifier_result = serializer_.SerializeParameterSet(score::json::Object{}, kMaxQualifier);

    ASSERT_TRUE(parameters_result.has_value());
    ASSERT_TRUE(min_qualifier_result.has_value());
    ASSERT_TRUE(max_qualifier_result.has_value());
    EXPECT_EQ(parameters_result.value(), "{}");
    EXPECT_EQ(min_qualifier_result.value(), R"({"parameters":{},"qualifier":0})");
    EXPECT_EQ(max_qualifier_result.value(), R"({"parameters":{},"qualifier":9})");
    EXPECT_EQ(max_qualifier_result.value().size(), Budget({}));
}

TEST_F(ParameterSetJsonSerializerImplFixture, FailsToSerializeQualifierThatIsNotASingleDigit)
{
    RecordProperty("Description",
                   "BUD-02: Verifies that a qualifier greater than 9, which would exceed the 1 octet budgeted for it, "
                   "causes SerializeParameterSet to fail with kQualifierOutOfRange instead of emitting a payload that "
                   "could exceed the buffer size computed at build time.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::ParameterSetJsonSerializerImpl::SerializeParameterSet()");

    for (const std::uint8_t qualifier : {std::uint8_t{kMaxQualifier + 1U}, std::numeric_limits<std::uint8_t>::max()})
    {
        SCOPED_TRACE(static_cast<std::uint32_t>(qualifier));

        const auto result = serializer_.SerializeParameterSet(score::json::Object{}, qualifier);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), MakeError(ParameterSetJsonSerializerError::kQualifierOutOfRange));
    }
}

TEST_F(ParameterSetJsonSerializerImplFixture, SerializesDimensionedParametersAsNestedArraysFirstDimensionOutermost)
{
    RecordProperty("Description",
                   "STRUCT-04: Verifies that parameters with dimensions are emitted as nested JSON arrays, one "
                   "nesting level per dimension with the first dimension outermost, including empty arrays, in both "
                   "payloads.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    // "matrix" has dimensions 2 x 3, "vector" has dimension 2, "empty" has dimension 0.
    const std::string parameters_json{R"({"empty":[],"matrix":[[1,2,3],[4,5,6]],"vector":[true,false]})"};
    const auto parameters = ParseObject(parameters_json);

    const auto parameters_result = serializer_.SerializeParameters(parameters);
    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, 0U);

    ASSERT_TRUE(parameters_result.has_value());
    ASSERT_TRUE(parameter_set_result.has_value());
    EXPECT_EQ(ToStdString(parameters_result.value()), parameters_json);
    EXPECT_EQ(ToStdString(parameter_set_result.value()), R"({"parameters":)" + parameters_json + R"(,"qualifier":0})");
}

TEST_F(ParameterSetJsonSerializerImplFixture, FailsToSerializeParameterValuesThatAreNeitherScalarsNorLists)
{
    RecordProperty("Description",
                   "STRUCT-02, STRUCT-04: Verifies that parameter values that are neither a number, a boolean nor a "
                   "(nested) list thereof - i.e. objects, null and strings, also when nested inside a list - are "
                   "rejected with an error by both entry points, as they have no budget in the size formula.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    for (const std::string_view input : {R"({"a":{"x":1}})",
                                         R"({"a":null})",
                                         R"({"a":"text"})",
                                         R"({"a":[1,{"x":1}]})",
                                         R"({"a":[[1,2],[null,4]]})",
                                         R"({"a":1,"b":["text"]})"})
    {
        SCOPED_TRACE(std::string{input});
        const auto parameters = ParseObject(input);

        EXPECT_FALSE(serializer_.SerializeParameters(parameters).has_value());
        EXPECT_FALSE(serializer_.SerializeParameterSet(parameters, 0U).has_value());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Section 4: Variable aspects of the JSON format
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ParameterSetJsonSerializerImplFixture, EmitsNoInsignificantWhitespace)
{
    RecordProperty("Description",
                   "WS-01: Verifies that neither payload contains insignificant whitespace, even if the input JSON "
                   "text contained whitespace around every structural character.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    const auto parameters =
        ParseObject("{\r\n  \"a\" : [ [ 1 , 2 ] , [ 3 , 4 ] ] ,\n  \"b\" :\tfalse ,\n  \"c\" : 1.5\n }\n");

    const auto parameters_result = serializer_.SerializeParameters(parameters);
    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, 1U);

    ASSERT_TRUE(parameters_result.has_value());
    ASSERT_TRUE(parameter_set_result.has_value());
    EXPECT_EQ(parameters_result.value(), R"({"a":[[1,2],[3,4]],"b":false,"c":1.5})");
    EXPECT_EQ(parameter_set_result.value(), R"({"parameters":{"a":[[1,2],[3,4]],"b":false,"c":1.5},"qualifier":1})");
    EXPECT_EQ(ToStdString(parameters_result.value()).find_first_of(" \t\n\r"), std::string::npos);
    EXPECT_EQ(ToStdString(parameter_set_result.value()).find_first_of(" \t\n\r"), std::string::npos);
}

TEST_F(ParameterSetJsonSerializerImplFixture, EmitsUtf8WithoutByteOrderMark)
{
    RecordProperty("Description",
                   "ENC-01, STR-01: Verifies that both payloads are UTF-8 encoded without a byte-order mark and that "
                   "multi-byte UTF-8 characters (2, 3 and 4 octets) in parameter names are emitted literally.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    // U+00E4 (2 octets), U+20AC (3 octets), U+1D11E (4 octets)
    const std::string utf8_name{
        "\xC3\xA4"
        "\xE2\x82\xAC"
        "\xF0\x9D\x84\x9E"};
    const std::string input{"{\"" + utf8_name + "\":1}"};
    const auto parameters = ParseObject(input);

    const auto parameters_result = serializer_.SerializeParameters(parameters);
    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, 0U);

    ASSERT_TRUE(parameters_result.has_value());
    ASSERT_TRUE(parameter_set_result.has_value());
    const std::pair<std::string, std::string> outputs_and_expectations[]{
        {ToStdString(parameters_result.value()), input},
        {ToStdString(parameter_set_result.value()), R"({"parameters":)" + input + R"(,"qualifier":0})"}};
    for (const auto& [output, expected] : outputs_and_expectations)
    {
        EXPECT_EQ(output, expected);
        EXPECT_NE(std::string_view{output}.substr(0U, kUtf8ByteOrderMark.size()), kUtf8ByteOrderMark)
            << "Payload must not start with a byte-order mark";
    }
}

TEST_F(ParameterSetJsonSerializerImplFixture, EscapesExactlyTheCharactersOfTheEscapeTable)
{
    RecordProperty("Description",
                   "STR-01: Verifies that in parameter names '\"', '\\', backspace, tab, line feed, form feed and "
                   "carriage return are escaped as the two-character sequences \\\", \\\\, \\b, \\t, \\n, \\f and "
                   "\\r, that every other character in U+0000..U+001F is escaped as \\u00xx with lowercase hex "
                   "digits, and that characters outside the escape set, in particular '/' and U+007F, are emitted "
                   "literally.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    // RFC 8259 forbids raw control characters inside JSON strings, so the only valid way to express them in the input
    // text would be the \uXXXX escape notation. The parser rejects that notation (it does support UTF-8 encoded
    // characters, just not the \uXXXX escape), hence the parameter name holding '"', '\', '/', U+007F and every
    // control character U+0000..U+001F is constructed directly.
    std::string name{"\"\\/\x7F"};
    for (std::uint8_t code{0U}; code < 0x20U; ++code)
    {
        name.push_back(static_cast<char>(code));
    }
    score::json::Object parameters{};
    parameters.emplace(std::move(name), score::json::Any{std::uint8_t{1U}});

    const auto result = serializer_.SerializeParameters(parameters);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ToStdString(result.value()),
              std::string{R"({"\"\\/)"
                          "\x7F"
                          R"(\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f)"
                          R"(\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d)"
                          R"(\u001e\u001f":1})"});
}

TEST_F(ParameterSetJsonSerializerImplFixture, EmitsIntegralValuesInShortestDecimalForm)
{
    RecordProperty("Description",
                   "NUM-01: Verifies that integral values, including the boundary values of all supported integer "
                   "types, are emitted in the shortest decimal form (optional '-' followed by decimal digits, no "
                   "leading zeros, no '+', no fraction, no exponent).");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    const std::string parameters_json{
        R"({"a":0,"b":1,"c":255,"d":65535,"e":4294967295,"f":18446744073709551615,)"
        R"("g":-1,"h":-128,"i":-32768,"j":-2147483648,"k":-9223372036854775808,"l":9223372036854775807})"};
    const auto parameters = ParseObject(parameters_json);

    const auto result = serializer_.SerializeParameters(parameters);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ToStdString(result.value()), parameters_json);
}

TEST_F(ParameterSetJsonSerializerImplFixture, EmitsFiniteFloatingPointValuesAsJsonNumbersOfAtMost24Octets)
{
    RecordProperty("Description",
                   "NUM-02, BUD-01: Verifies that finite floating-point values - including extreme magnitudes, "
                   "subnormals, negative values and values rendered in fixed notation - are emitted as valid "
                   "RFC 8259 JSON numbers occupying no more than 24 octets, and that they round-trip exactly.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    // number = [ minus ] int [ frac ] [ exp ] (RFC 8259, section 6)
    const std::regex rfc8259_number{R"(-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?)"};

    for (const std::string_view input : {"-1.2345678901234567e-308",
                                         "-1.7976931348623157e+308",
                                         "1.7976931348623157e+308",
                                         "-2.2250738585072014e-308",
                                         "-4.9406564584124654e-324",
                                         "-1.2345678901234567e-100",
                                         "-1.2345678901234567e-05",
                                         "-0.00012345678901234567",
                                         "-0.1",
                                         "-0.0",
                                         "0.5",
                                         "-1234567890123456.7",
                                         "-1.2345678901234567e+17",
                                         "-1.8446744073709552e+19",
                                         "-3.4028234663852886e+38"})
    {
        SCOPED_TRACE(std::string{input});

        const std::string output{SerializeSingleValue(serializer_, input)};

        // BUD-01: the emitted number must not exceed the 24 octets Lval(float) budgeted for a floating-point value.
        EXPECT_LE(output.size(), kLvalFloat) << output;
        // NUM-02: the emitted text must be a valid RFC 8259 number (e.g. no "nan", "inf", ',' or leading '+').
        EXPECT_TRUE(std::regex_match(output, rfc8259_number)) << output;
        // NUM-02: round trip - reading the emitted text back must yield bit-for-bit the same double as the input
        // text, i.e. no precision was lost by shortening the representation.
        EXPECT_EQ(std::strtod(output.c_str(), nullptr), std::strtod(std::string{input}.c_str(), nullptr)) << output;
    }
}

TEST_F(ParameterSetJsonSerializerImplFixture, SerializesFloatingPointValuesWithDotUnderNonClassicGlobalLocale)
{
    RecordProperty(
        "Description",
        "NUM-02: Verifies that floating point values are always serialized with '.' as the decimal separator, even "
        "if a non-classic locale (e.g. one using ',' as the decimal separator) has been imbued globally, since JSON "
        "(RFC 8259) mandates '.' and any other separator would produce invalid JSON.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    const std::string parameters_json{R"({"a_double":1.5})"};
    const auto parameters = ParseObject(parameters_json);

    const std::locale previous_global_locale{
        std::locale::global(std::locale{std::locale::classic(), new CommaDecimalPointNumpunct{}})};

    const auto result = serializer_.SerializeParameters(parameters);

    std::locale::global(previous_global_locale);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ToStdString(result.value()), parameters_json);
}

TEST_F(ParameterSetJsonSerializerImplFixture, FailsToSerializeNonFiniteFloatingPointValues)
{
    RecordProperty("Description",
                   "NUM-02: Verifies that non-finite floating-point values (NaN, +/-Infinity), which have no RFC 8259 "
                   "representation and are outside the contract's guarantee, cause serialization to fail instead of "
                   "emitting invalid JSON.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    // The parser cannot produce non-finite values, hence they are constructed directly.
    for (const double value : {std::numeric_limits<double>::quiet_NaN(),
                               std::numeric_limits<double>::infinity(),
                               -std::numeric_limits<double>::infinity()})
    {
        SCOPED_TRACE(value);
        score::json::Object parameters{};
        parameters.emplace("v", score::json::Any{value});

        EXPECT_FALSE(serializer_.SerializeParameters(parameters).has_value());
        EXPECT_FALSE(serializer_.SerializeParameterSet(parameters, 0U).has_value());
    }
}

TEST_F(ParameterSetJsonSerializerImplFixture, EmitsBooleansAsTrueOrFalse)
{
    RecordProperty("Description", "LIT-01: Verifies that booleans are emitted as the literals 'true' and 'false'.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    const std::string parameters_json{R"({"f":false,"t":true})"};
    const auto parameters = ParseObject(parameters_json);

    const auto result = serializer_.SerializeParameters(parameters);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ToStdString(result.value()), parameters_json);
}

TEST_F(ParameterSetJsonSerializerImplFixture, WorstCaseScalarValuesFitIntoTheirBudget)
{
    RecordProperty("Description",
                   "BUD-01: Verifies that the worst-case value of each declared scalar type does not exceed the "
                   "number of octets Lval(T) budgeted for it.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesSerializeParameters);

    const std::initializer_list<std::pair<std::string_view, std::size_t>> worst_cases{
        {"false", kLvalBool},
        {"255", kLvalUint8},
        {"65535", kLvalUint16},
        {"4294967295", kLvalUint32},
        {"18446744073709551615", kLvalUint64},
        {"-128", kLvalSint8},
        {"-32768", kLvalSint16},
        {"-2147483648", kLvalSint32},
        {"-9223372036854775808", kLvalSint64},
        // float/double: see EmitsFiniteFloatingPointValuesAsJsonNumbersOfAtMost24Octets.
    };

    for (const auto& worst_case : worst_cases)
    {
        SCOPED_TRACE(std::string{worst_case.first});

        const std::string output{SerializeSingleValue(serializer_, worst_case.first)};

        EXPECT_LE(output.size(), worst_case.second) << output;
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Sections 2, 5 and 6: Guarantee, size formula and example
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ParameterSetJsonSerializerImplFixture, SerializesContractExampleWithinBudget)
{
    RecordProperty("Description",
                   "Section 2, Section 5, Section 6, BUD-03: Verifies the contract example - 'foo' (uint8) = 255, "
                   "'bar' (uint32) = 4294967295, qualifier = 0 - serializes to the documented 57 octets as "
                   "InternalConfigProvider payload and to 28 octets as ConfigCalibration payload, both within the "
                   "budget of 57 octets.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    const auto parameters = ParseObject(R"({"foo":255,"bar":4294967295})");
    // str_len("foo") = str_len("bar") = 5
    const std::size_t budget{Budget({Member(5U, kLvalUint8), Member(5U, kLvalUint32)})};

    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, 0U);
    const auto parameters_result = serializer_.SerializeParameters(parameters);

    ASSERT_TRUE(parameter_set_result.has_value());
    ASSERT_TRUE(parameters_result.has_value());
    EXPECT_EQ(budget, std::size_t{57U});
    EXPECT_EQ(parameter_set_result.value(), R"({"parameters":{"bar":4294967295,"foo":255},"qualifier":0})");
    EXPECT_EQ(parameter_set_result.value().size(), std::size_t{57U});
    EXPECT_LE(parameter_set_result.value().size(), budget);
    EXPECT_EQ(parameters_result.value(), R"({"bar":4294967295,"foo":255})");
    EXPECT_EQ(parameters_result.value().size(), std::size_t{28U});
    EXPECT_LE(parameters_result.value().size(), budget);
}

TEST_F(ParameterSetJsonSerializerImplFixture, WorstCaseAssignmentOfMixedLayoutStaysWithinBudget)
{
    RecordProperty("Description",
                   "Section 2, Section 5, BUD-03: Verifies that serializing the worst admissible value assignment of "
                   "a layout mixing scalars, 1-D and 2-D arrays of several types and a parameter name requiring "
                   "escaping does not exceed budget(L) in either payload, and that the ConfigCalibration payload is "
                   "exactly 29 octets shorter than the InternalConfigProvider payload with a 1-digit qualifier.");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", kVerifiesBoth);

    // Layout L (str_len includes the two enclosing quotes, STR-01):
    //  - "b"    bool     scalar     (str_len = 3)
    //  - "i"    sint64   scalar     (str_len = 3)
    //  - "m"    bool     2 x 3      (str_len = 3)
    //  - "q\"x" uint8    scalar     (str_len = 2 + 1 + 2 + 1 = 6)
    //  - "u"    uint64   2          (str_len = 3)
    //  - "v"    double   3          (str_len = 3)
    const auto parameters =
        ParseObject(R"({)"
                    R"("b":false,)"
                    R"("i":-9223372036854775808,)"
                    R"("m":[[false,false,false],[false,false,false]],)"
                    R"("q\"x":255,)"
                    R"("u":[18446744073709551615,18446744073709551615],)"
                    R"("v":[-1.2345678901234567e-308,-1.7976931348623157e+308,-4.9406564584124654e-324])"
                    R"(})");
    const std::size_t budget{Budget({
        Member(3U, kLvalBool),
        Member(3U, kLvalSint64),
        Member(3U, Frame(2U, Frame(3U, kLvalBool))),
        Member(6U, kLvalUint8),
        Member(3U, Frame(2U, kLvalUint64)),
        Member(3U, Frame(3U, kLvalFloat)),
    })};

    const auto parameter_set_result = serializer_.SerializeParameterSet(parameters, kMaxQualifier);
    const auto parameters_result = serializer_.SerializeParameters(parameters);

    ASSERT_TRUE(parameter_set_result.has_value());
    ASSERT_TRUE(parameters_result.has_value());
    EXPECT_LE(parameter_set_result.value().size(), budget) << ToStdString(parameter_set_result.value());
    EXPECT_LE(parameters_result.value().size(), budget) << ToStdString(parameters_result.value());
    EXPECT_EQ(parameters_result.value().size() + kConfigCalibrationHeadroomOctets, parameter_set_result.value().size());
}

}  // namespace test
}  // namespace config_management
}  // namespace score
