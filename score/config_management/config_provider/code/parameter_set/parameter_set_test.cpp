// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
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
#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"
#include "score/json/json_parser.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace test
{
// -------------------------------------------------------------
// Compile-time public API regression coverage (parameter_set.h)
// * Unused helper referencing every public ParameterSet symbol (incl. templates).
// * Build fails if a public signature is removed or changed.
// * Update: add one trivial usage per newly added public method or alias.
// * Migration (add → deprecate → remove): add new symbol; add usage here; run
//   spp_promote_test; deprecate old; wait release window; remove old + usage.
// * Reviewer non‑breaking steps:
//     1. Run spp_promote_test for downstream usages.
//     2. Add new method beside old; include BOTH in coverage.
//     3. After migration, drop old usage + method.
//     4. If downstream remains, keep old method/usage unchanged.
// -------------------------------------------------------------
namespace
{
[[maybe_unused]] void CoverParameterSetAPI()
{
    using namespace score::platform::config_provider;
    score::json::Any dummy_json;  // empty JSON -> exercise error paths
    ParameterSet ps(std::move(dummy_json));
    ps.ContainsSameContent(ps);
    ps.GetQualifier();
    ps.FormatAsKeyValuePairs();
    ps.GetParametersAsString();
    score::cpp::string_view param_name{"regression_param"};
    ps.GetParameterAsJsonAny(param_name);
    // Template calls (compile only)
    ps.GetParameterAs<int>(param_name);
    ps.GetParameterAs<ParameterSet::Array<int>>(param_name);
    ps.GetParameterAs<ParameterSet::TwoDimensionalArray<int>>(param_name);
}
}  // namespace

std::string GenerateDummyJsonString()
{
    return R"(
    {
        "parameters": {
            "integer": 55,
            "float_as_integer": 42,
            "float_as_decimal": 42.0,
            "float_big_num": 123456789123456789.0,
            "string": "foo",
            "array": [1, 2, 3, 4],
            "array_float_as_decimal": [-3000.0, 2000.0, -12000.0, 500000.0, 0.0, 840000.0, 123456.0, 12345678.0],
            "array_float_as_integer": [-3000, 2000, -12000, 500000, 0, 840000, 123456, 12345678 ],
            "array_float_mixed_integer_and_decimal": [-3000, 2000.0, -12000, 500000.0, 0, 840000.0, 123456.0, 12345678.0 ],
            "array_string": ["a", "b"],
            "array2d": [
                [1, 2, 3],
                [4, 5 ,6]
            ],
            "array2d_float_as_decimal": [
                [1.0, 2.0, 3555.0],
                [4.0, 5.0 ,67777.0]
            ],
            "array2d_float_as_integer": [
                [1, 2, 3555],
                [4, 5 ,67777]
            ],
            "array2d_float_mixed_integer_and_decimal": [
                [1.0, 2, 3555],
                [4.0, 5.0 ,67777]
            ],
            "array2d_string": [
                ["a", "b"],
                ["c", "d"]
            ],
            "array2d_bool": [
                [true, false],
                [false, true]
            ]
        },
        "qualifier": 0
    }
    )";
}

std::string GenerateDummyParameterSetJsonString()
{
    return R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 0
    }
    )";
}

std::string GenerateDummySimpleParameterSetJsonString()
{
    return R"(
    {
        "parameters": {
            "parameter": 1
        },
        "qualifier": 0
    })";
}

std::string GenerateDummySimpleOfParametersJsonString()
{
    return R"(
    {
        "parameter": 1
    })";
}

TEST(ParameterQualifierTest, GetQualifierTest_Unqualified)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", "14602333");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "14602333: Verifies that the parameter set qualifier is unqualified.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");

    json::JsonParser json_parser{};
    // Given the parameter set qualifier is unqualified
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 0
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};
    auto result = parameter_set.GetQualifier();
    ASSERT_TRUE(result.has_value());
    // Then expect GetQualifier would retrieve unqualified
    EXPECT_EQ(result.value(), score::config_management::config_daemon::ParameterSetQualifier::kUnqualified);
}

TEST(ParameterQualifierTest, GetQualifierTest_Qualified)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", "14602333");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "14602333: Verifies that the parameter set qualifier is qualified.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");

    json::JsonParser json_parser{};
    // Given the parameter set qualifier is qualified
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 1
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would retrieve qualified
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), score::config_management::config_daemon::ParameterSetQualifier::kQualified);
}

TEST(ParameterQualifierTest, GetQualifierTest_Default)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", "14602333");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "14602333: Verifies that the parameter set qualifier is default.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");

    json::JsonParser json_parser{};
    // Given the parameter set qualifier is default
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 2
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would retrieve default
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), score::config_management::config_daemon::ParameterSetQualifier::kDefault);
}

TEST(ParameterQualifierTest, GetQualifierTest_Modified)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", "14602333");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "14602333: Verifies that the parameter set qualifier is modified.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    json::JsonParser json_parser{};
    // Given the parameter set qualifier is modified
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 3
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would retrieve modified
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), score::config_management::config_daemon::ParameterSetQualifier::kModified);
}

TEST(ParameterQualifierTest, GetQualifierTest_Invalid)
{
    RecordProperty("Priority", "3");
    RecordProperty("Description",
                   "Tests behaviour when int representation of qualifier isn't represented by any enum value.");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetQualifiers()");

    json::JsonParser json_parser{};
    // Given the parameter set qualifier is an invalid integer
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 4
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would return error
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kValueCastingError);
}

TEST(ParameterQualifierTest, GetQualifierTest_WrongJsonType)
{
    RecordProperty("Priority", "3");
    RecordProperty("Description", "Tests error handling when qualifier isn't an integer.");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetQualifiers()");

    json::JsonParser json_parser{};
    // Given the parameter set qualifier is of wrong json type
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": "kUnqualified"
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would return error
    ASSERT_FALSE(result.has_value());
}

TEST(ParameterQualifierTest, GetQualifierTest_NotAnObject)
{
    RecordProperty("Priority", "3");
    RecordProperty("Description", "Tests error handling when the root json isn't a JSON object.");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetQualifiers()");

    json::JsonParser json_parser{};
    score::json::Any set_json{false};
    // Given the parameter set is not a JSON object
    ParameterSet parameter_set{std::move(set_json)};

    auto result = parameter_set.GetQualifier();
    // Then expect GetQualifier would return error kObjectCastingError
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kObjectCastingError);
}

TEST(ParameterQualifierTest, GetQualifierTest_NoQualifier)
{
    RecordProperty("Priority", "3");
    RecordProperty("Description", "Tests error handling when the json is missing the qualifier.");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetQualifiers()");

    json::JsonParser json_parser{};
    // Given the parameter set is missing the qualifier
    const auto* str = R"(
    {
        "parameters": {
            "parameter_name": 55
        }
    }
    )";
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(str).value())};

    auto result = parameter_set.GetQualifier();
    ASSERT_FALSE(result.has_value());
    // Then expect GetQualifier would return error kParsingFailed
    EXPECT_EQ(result.error(), ConfigProviderError::kParsingFailed);
}

TEST(SimpleParameterSetTest, GetParameter_SetObjectCastingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameters()");
    RecordProperty(
        "Description",
        "This test verifies ContainsSameContent failed due to SetObjectCastingError for GetParameters method");
    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has "foo")
    score::json::Any set_json{false};
    ParameterSet parameter_set{std::move(set_json)};
    // Then expect ContainsSameContent would return false due to SetObjectCastingError
    auto result = parameter_set.ContainsSameContent(parameter_set);
    EXPECT_EQ(result, false);
}

TEST(SimpleParameterSetTest, ConstructionWithParamJson)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description", "This test verifies successful operation of GetParameterAs function");

    json::JsonParser json_parser{};
    auto string = GenerateDummyParameterSetJsonString();
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(string).value())};
    // Given the parameter set contains a parameter named "parameter_name" with integer value 55
    auto num = parameter_set.GetParameterAs<int>("parameter_name");
    // Then expect GetParameterAs would retrieve the integer value 55
    ASSERT_TRUE(num.has_value());
    EXPECT_EQ(num.value(), 55);
}

TEST(ParameterSetFormatTest, FormatAsKeyValuePairsPass)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::FormatAsKeyValuePairs()");
    RecordProperty("Description", "This test verifies error handling in the FormatAsKeyValuePairs function.");

    // Given the json format parameter set contains various parameters
    const auto* const json_input_string = R"({
    "parameters": {
        "alg_abort_ccm_offset_distance": 100,
        "alg_abort_ccm_offset_duration": 3.222,
        "alg_abort_distance_debounce_after_cut_off": 150,
        "alg_abort_distance_debounce_before_cut_off": 50,
        "alg_abort_distance_lane_depending_on_speed_base_value_x": [[
            16.6700001,
            27.7700005,
            37,
            50
        ], [29, 39, 29]
        ],
        "alg_abort_distance_location" : "Egypt",
        "alg_abort_distance_countries" : ["Germany", "France"],
        "alg_abort_distance_locations_places" : [["Cairo", "munich"], ["NewYork", "mexico"]],
        "alg_abort_distance_unsupported_type_1dArray" : [null],
        "alg_abort_distance_unsupported_type_2dArray" : [[1,2], null]
    }
    })";

    std::string parameter_set_expected_formatted_string = R"({
    "alg_abort_ccm_offset_distance": 100,
    "alg_abort_ccm_offset_duration": 3.22199988,
    "alg_abort_distance_countries": [
        "Germany",
        "France"
    ],
    "alg_abort_distance_debounce_after_cut_off": 150,
    "alg_abort_distance_debounce_before_cut_off": 50,
    "alg_abort_distance_lane_depending_on_speed_base_value_x": [
        [
            16.6700001,
            27.7700005,
            37,
            50
        ],
        [
            29,
            39,
            29
        ]
    ],
    "alg_abort_distance_location": "Egypt",
    "alg_abort_distance_locations_places": [
        [
            "Cairo",
            "munich"
        ],
        [
            "NewYork",
            "mexico"
        ]
    ],
    "alg_abort_distance_unsupported_type_1dArray" : [null],
    "alg_abort_distance_unsupported_type_2dArray" : [[1, 2], null]
    })";

    json::JsonParser json_parser{};
    ParameterSet parameter_set_input{std::move(json_parser.FromBuffer(json_input_string).value())};

    parameter_set_expected_formatted_string.erase(
        std::remove_if(
            parameter_set_expected_formatted_string.begin(), parameter_set_expected_formatted_string.end(), ::isspace),
        parameter_set_expected_formatted_string.cend());
    // When calling FormatAsKeyValuePairs
    auto parameter_set_output_formatted_string{parameter_set_input.FormatAsKeyValuePairs().value()};
    parameter_set_output_formatted_string.erase(
        std::remove_if(
            parameter_set_output_formatted_string.begin(), parameter_set_output_formatted_string.end(), ::isspace),
        parameter_set_output_formatted_string.cend());
    // Then expect a standardized key-value string representation with sorted keys and consistent formatting which
    // matches the expected formatted string
    EXPECT_EQ(parameter_set_output_formatted_string, parameter_set_expected_formatted_string);
}

TEST(ParameterSetFormatTest, FormatAsKeyValuePairsInvalidJsonFormat)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::FormatAsKeyValuePairs()");
    RecordProperty(
        "Description",
        "This test verifies error handling in the FormatAsKeyValuePairs function when invalid json format is used.");

    // Given the parameter set with invalid json format
    const auto* const json_input = R"("live")";
    json::JsonParser json_parser{};
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(json_input).value())};

    // Expect the FormatAsKeyValuePairs function to return an ObjectCastingError
    auto result = parameter_set.FormatAsKeyValuePairs();

    EXPECT_EQ(static_cast<ConfigProviderError>(*result.error()), ConfigProviderError::kObjectCastingError);
}

TEST(ParameterSetFormatTest, FormatAsKeyValuePairsParametersKeywordNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::FormatAsKeyValuePairs()");
    RecordProperty(
        "Description",
        "This test verifies error handling in the FormatAsKeyValuePairs function when parameters keyword is missing.");

    // Given the json format parameter set which do not contain "parameters" keyword
    const auto* const json_input = R"({
    "not_parameters": {
        "alg_abort_ccm_offset_distance": 100,
        "alg_abort_ccm_offset_duration": 3,
        "alg_abort_distance_debounce_after_cut_off": 150,
        "alg_abort_distance_debounce_before_cut_off": 50,
        "alg_abort_distance_lane_depending_on_speed_base_value_x": [[
            16.6700001,
            27.7700005,
            37,
            50
        ], [29, 39, 29]
        ],
        "alg_abort_distance_location" : "Egypt"
    }
    })";

    json::JsonParser json_parser{};
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(json_input).value())};

    // Then expect the FormatAsKeyValuePairs function to return a ParsingFailed error
    auto result = parameter_set.FormatAsKeyValuePairs();
    EXPECT_EQ(static_cast<ConfigProviderError>(*result.error()), ConfigProviderError::kParsingFailed);
}

TEST(SimpleParameterSetTest, GetParametersAsString)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAsString()");
    RecordProperty("Description",
                   "This test verifies success of conversion of parameters data from parameter set to string");
    // Given a parameter set contains simple parameters
    json::JsonParser json_parser{};
    auto complete_json = GenerateDummySimpleParameterSetJsonString();
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(complete_json).value())};
    auto parameter_get_from_parameter_set = parameter_set.GetParametersAsString().value();
    parameter_get_from_parameter_set.erase(
        std::remove_if(parameter_get_from_parameter_set.begin(), parameter_get_from_parameter_set.end(), ::isspace),
        parameter_get_from_parameter_set.cend());

    // Then expect GetParametersAsString would retrieve the correct parameter in parameter set
    auto parameters = GenerateDummySimpleOfParametersJsonString();
    parameters.erase(std::remove_if(parameters.begin(), parameters.end(), ::isspace), parameters.cend());
    EXPECT_EQ(parameter_get_from_parameter_set, parameters);
}

TEST(SimpleParameterSetTest, GetParametersAsString_ObjectCastingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAsString()");
    RecordProperty(
        "Description",
        "This test verifies success of SetObjectCasting error handling for FromParameterSetJsonString method");
    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has no keyword)
    score::json::Any invalid_json{false};
    ParameterSet parameter_set{std::move(invalid_json)};
    // Then expect GetParametersAsString would return object casting error
    auto result = parameter_set.GetParametersAsString().error();
    EXPECT_EQ(result, ConfigProviderError::kObjectCastingError);
}

TEST(SimpleParameterSetTest, GetParametersAsString_ParsingFailed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAsString()");
    RecordProperty("Description", "This test verifies GetParametersAsString method failed due to parsing failure");

    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has "foo")
    score::json::Object obj{};
    obj["foo"] = score::json::Any{true};
    score::json::Any set_json{std::move(obj)};
    ParameterSet parameter_set{std::move(set_json)};
    // Then expect GetParametersAsString would return parsing failed error
    auto result = parameter_set.GetParametersAsString().error();
    EXPECT_EQ(result, ConfigProviderError::kParsingFailed);
}

TEST(SimpleParameterSetTest, GetParametersAsString_ConvertJsonToStringFailed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAsString()");
    RecordProperty("Description",
                   "This test verifies GetParametersAsString method failed due to passing a JSON object with empty "
                   "parameter values");
    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has empty content)
    std::string text = R"(
    {
        "parameters": ""
    })";
    json::JsonParser json_parser{};
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(text).value())};
    // Then expect GetParametersAsString would return object casting error
    auto result = parameter_set.GetParametersAsString().error();
    EXPECT_EQ(result, ConfigProviderError::kObjectCastingError);
}

TEST(SimpleParameterSetTest, GetParameterAs_ObjectCastingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAsString()");
    RecordProperty("Description",
                   "This test verifies success of SetObjectCasting error handling for GetParameterAs method");
    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has no keyword)
    score::json::Any set_json{false};
    ParameterSet parameter_set{std::move(set_json)};
    auto result = parameter_set.GetParameterAs<int>("foo").error();
    // Then expect GetParameterAs would return object casting error
    EXPECT_EQ(result, ConfigProviderError::kObjectCastingError);
}

TEST(SimpleParameterSetTest, GetParameterAs_ParsingFailed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParametersAs()");
    RecordProperty("Description", "This test verifies error handling for GetParameterAs method");

    // Given a parameter set contains invalid format (The ParameterSet expects a structure with a "parameters" key, but
    // this only has "foo")
    score::json::Object obj{};
    obj["foo"] = score::json::Any{true};
    score::json::Any set_json{std::move(obj)};
    ParameterSet parameter_set{std::move(set_json)};
    // Then expect GetParameterAs would return parsing failed error when retrieving parameter as integer
    auto result = parameter_set.GetParameterAs<int>("foo").error();
    EXPECT_EQ(result, ConfigProviderError::kParsingFailed);
}

class ParameterSetTest : public ::testing::Test
{
  public:
    void SetUp() override
    {
        json::JsonParser json_parser{};
        auto string = GenerateDummyJsonString();
        auto json_result = json_parser.FromBuffer(string);

        ASSERT_TRUE(json_result.has_value());

        parameter_set_ = std::make_unique<ParameterSet>(std::move(json_result.value()));
    }

    ParameterSet& GetParameterSet()
    {
        return *parameter_set_;
    }

  private:
    std::unique_ptr<ParameterSet> parameter_set_;
};

template <typename T>
class IntegerTypedParameterSetTest : public ParameterSetTest
{
};

using IntegerTypes = ::testing::Types<std::int8_t,
                                      std::int16_t,
                                      std::int32_t,
                                      std::int64_t,
                                      std::uint8_t,
                                      std::uint16_t,
                                      std::uint32_t,
                                      std::uint64_t>;
TYPED_TEST_SUITE(IntegerTypedParameterSetTest, IntegerTypes, /* unused */);

TYPED_TEST(IntegerTypedParameterSetTest, GetParameterAs_IntegerTypes)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different integer types");

    auto result = this->GetParameterSet().template GetParameterAs<TypeParam>("integer");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), TypeParam{55});
}

TYPED_TEST(IntegerTypedParameterSetTest, GetParameterAsArray_IntegerTypes)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAsArray method with different integer types");

    auto result = this->GetParameterSet().template GetParameterAs<ParameterSet::Array<TypeParam>>("array");
    ASSERT_TRUE(result.has_value());
    const auto expected = ParameterSet::Array<TypeParam>{1, 2, 3, 4};
    EXPECT_EQ(result.value(), expected);
}

TYPED_TEST(IntegerTypedParameterSetTest, GetParameterAsTwoDimensionalArray_IntegerTypes)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty(
        "Description",
        "This test verifies success of GetParameterAsTwoDimensionalArray method with different integer types");

    auto result =
        this->GetParameterSet().template GetParameterAs<ParameterSet::TwoDimensionalArray<TypeParam>>("array2d");
    ASSERT_TRUE(result.has_value());
    ParameterSet::Array<TypeParam> first{1, 2, 3};
    ParameterSet::Array<TypeParam> second{4, 5, 6};
    ParameterSet::TwoDimensionalArray<TypeParam> expected_twodim{first, second};
    ASSERT_EQ(expected_twodim.size(), result.value().size());
    EXPECT_EQ(result.value(), expected_twodim);
}

template <typename T>
class FloatTypedParameterSetTest : public ParameterSetTest
{
};

using FloatTypes = ::testing::Types<float, double>;

TYPED_TEST_SUITE(FloatTypedParameterSetTest, FloatTypes, /* unused */);
TYPED_TEST(FloatTypedParameterSetTest, GetParameterAs_FloatTypesAsDecimal)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as decimal");

    json::JsonParser json_parser{};
    auto result = this->GetParameterSet().template GetParameterAs<TypeParam>("float_as_decimal");

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result.value(), TypeParam{42.0});
    EXPECT_EQ(result.value(), json_parser.FromBuffer("42.0").value().As<TypeParam>().value());
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAs_FloatTypesAsInteger)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as integer");

    json::JsonParser json_parser{};
    auto result = this->GetParameterSet().template GetParameterAs<TypeParam>("float_as_integer");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), TypeParam{42.0});
    EXPECT_EQ(result.value(), json_parser.FromBuffer("42.0").value().As<TypeParam>().value());
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAs_FloatTypesCompareIntegerAndDecimal)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when "
                         "comparing float presented as integer and decimal");

    json::JsonParser json_parser{};
    auto result_as_integer = this->GetParameterSet().template GetParameterAs<TypeParam>("float_as_integer");
    auto result_as_decimal = this->GetParameterSet().template GetParameterAs<TypeParam>("float_as_decimal");

    ASSERT_TRUE(result_as_integer.has_value());
    ASSERT_TRUE(result_as_decimal.has_value());
    EXPECT_EQ(result_as_integer.value(), json_parser.FromBuffer("42.0").value().As<TypeParam>().value());
    EXPECT_EQ(result_as_integer.value(), result_as_decimal.value());
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAs_FloatTypesBigInFloatType)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description", "This test verifies success of GetParameterAs method with big float number");
    json::JsonParser json_parser{};
    auto result = this->GetParameterSet().template GetParameterAs<TypeParam>("float_big_num");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), json_parser.FromBuffer("123456789123456789.0").value().As<TypeParam>().value());
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAsArray_FloatTypesAsDecimalForOneDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as one dimensional array of decimals");

    const std::string expected_array = R"([-3000.0, 2000.0, -12000.0, 500000.0, 0.0, 840000.0, 123456.0, 12345678.0])";

    auto result =
        this->GetParameterSet().template GetParameterAs<ParameterSet::Array<TypeParam>>("array_float_as_decimal");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(std::move(expected_array));

    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";
    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";

    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();
    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto result_value = result.value().at(i);
        const auto param_value = param_array[i].As<TypeParam>().value();
        EXPECT_EQ(result_value, param_value) << "Mismatch at index " << i;
    }
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAsArray_FloatTypesAsIntegerForOneDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as one dimensional array of integers");

    const std::string expected_array = R"([-3000.0, 2000.0, -12000.0, 500000.0, 0.0, 840000.0, 123456.0, 12345678.0])";

    auto result =
        this->GetParameterSet().template GetParameterAs<ParameterSet::Array<TypeParam>>("array_float_as_integer");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(std::move(expected_array));

    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";
    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";

    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();
    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto result_value = result.value().at(i);
        const auto param_value = param_array[i].As<TypeParam>().value();
        EXPECT_EQ(result_value, param_value) << "Mismatch at index " << i;
    }
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAsArray_FloatTypesWithMixedIntegerAndDecimalForOneDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as one dimensional array of mixed decimals and integers");

    const std::string expected_array = R"([-3000.0, 2000.0, -12000.0, 500000.0, 0.0, 840000.0, 123456.0, 12345678.0])";

    auto result = this->GetParameterSet().template GetParameterAs<ParameterSet::Array<TypeParam>>(
        "array_float_mixed_integer_and_decimal");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(std::move(expected_array));

    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";
    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";

    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();
    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto result_value = result.value().at(i);
        const auto param_value = param_array[i].As<TypeParam>().value();
        EXPECT_EQ(result_value, param_value) << "Mismatch at index " << i;
    }
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAsTwoDimensionalArray_FloatTypesAsDecimalForTwoDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as two dimensional array of decimals");

    const std::string expected_array = R"([[1.0, 2.0, 3555.0], [4.0, 5.0, 67777.0]])";

    auto result = this->GetParameterSet().template GetParameterAs<ParameterSet::TwoDimensionalArray<TypeParam>>(
        "array2d_float_as_decimal");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(expected_array);
    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";

    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";
    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();

    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto& result_inner_array = result.value().at(i);
        const auto& param_inner_array = param_array[i].As<score::json::List>().value().get();
        ASSERT_EQ(result_inner_array.size(), param_inner_array.size())
            << "Mismatch in size of inner arrays at index " << i;

        for (size_t j = 0; j < result_inner_array.size(); ++j)
        {
            const auto result_value = result_inner_array.at(j);
            const auto param_value = param_inner_array[j].As<TypeParam>().value();

            EXPECT_EQ(result_value, param_value) << "Mismatch at index (" << i << ", " << j << ")";
        }
    }
}

TYPED_TEST(FloatTypedParameterSetTest, GetParameterAsTwoDimensionalArray_FloatTypesAsIntegerForTwoDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as two dimensional array of integers");

    const std::string expected_array = R"([[1.0, 2.0, 3555.0], [4.0, 5.0, 67777.0]])";

    auto result = this->GetParameterSet().template GetParameterAs<ParameterSet::TwoDimensionalArray<TypeParam>>(
        "array2d_float_as_integer");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(expected_array);
    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";

    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";
    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();

    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto& result_inner_array = result.value().at(i);
        const auto& param_inner_array = param_array[i].As<score::json::List>().value().get();
        ASSERT_EQ(result_inner_array.size(), param_inner_array.size())
            << "Mismatch in size of inner arrays at index " << i;

        for (size_t j = 0; j < result_inner_array.size(); ++j)
        {
            const auto result_value = result_inner_array.at(j);
            const auto param_value = param_inner_array[j].As<TypeParam>().value();

            EXPECT_EQ(result_value, param_value) << "Mismatch at index (" << i << ", " << j << ")";
        }
    }
}

TYPED_TEST(FloatTypedParameterSetTest,
           GetParameterAsTwoDimensionalArray_FloatTypesWithMixedIntegerAndDecimalForTwoDimensionalArray)
{
    this->RecordProperty("Priority", "3");
    this->RecordProperty("TestType", "Interface test");
    this->RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    this->RecordProperty("DerivationTechnique", "Analysis of boundary values");
    this->RecordProperty("Description",
                         "This test verifies success of GetParameterAs method with different float types when float "
                         "presented as two dimensional array of mixed decimals and integers");

    const std::string expected_array = R"([[1.0, 2.0, 3555.0], [4.0, 5.0, 67777.0]])";

    auto result = this->GetParameterSet().template GetParameterAs<ParameterSet::TwoDimensionalArray<TypeParam>>(
        "array2d_float_mixed_integer_and_decimal");
    ASSERT_TRUE(result.has_value());

    json::JsonParser json_parser{};
    auto parse_result = json_parser.FromBuffer(expected_array);
    ASSERT_TRUE(parse_result.has_value()) << "Failed to parse JSON string";

    ASSERT_TRUE(parse_result.value().As<score::json::List>().has_value()) << "Parsed JSON is not a list";
    const score::json::List& param_array = parse_result.value().As<score::json::List>().value().get();

    ASSERT_EQ(result.value().size(), param_array.size()) << "Size mismatch between result and parsed JSON array";

    for (size_t i = 0; i < result.value().size(); ++i)
    {
        const auto& result_inner_array = result.value().at(i);
        const auto& param_inner_array = param_array[i].As<score::json::List>().value().get();
        ASSERT_EQ(result_inner_array.size(), param_inner_array.size())
            << "Mismatch in size of inner arrays at index " << i;

        for (size_t j = 0; j < result_inner_array.size(); ++j)
        {
            const auto result_value = result_inner_array.at(j);
            const auto param_value = param_inner_array[j].As<TypeParam>().value();

            EXPECT_EQ(result_value, param_value) << "Mismatch at index (" << i << ", " << j << ")";
        }
    }
}

TEST_F(ParameterSetTest, TestContainsSameContent)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("ASIL", "QM");
    RecordProperty("Verifies", "32231979");
    RecordProperty(
        "Description",
        "32231979: This test checks if current ParameterSet contains the same parameters content as the newly "
        "received ParameterSet."
        "This function would return true if the newly received ParameterSet has the same parameters "
        "content, regardless of its qualifier."
        "Otherwise, this function would return false.");

    json::JsonParser json_parser{};
    const auto* content_v1_qualifier_v1 = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.0]
        },
        "qualifier": 0
    }
    )";

    const auto* content_v1_qualifier_v2 = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.0]
        },
        "qualifier": 1
    }
    )";

    const auto* content_v2_qualifier_v1 = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.1]
        },
        "qualifier": 0
    }
    )";

    const auto* content_v2_qualifier_v2 = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.1]
        },
        "qualifier": 1
    }
    )";

    const auto* content_v1_without_qualifier = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.0]
        }
    }
    )";

    const auto* content_v2_without_qualifier = R"(
    {
        "parameters": {
            "string": "foo",
            "array_float": [-3000.123, 2000, -12000, 500000, 0, 840000.1]
        }
    }
    )";

    const auto* without_content_qualifier_v1 = R"(
    {
        "qualifier": 0
    }
    )";

    const auto* without_content_qualifier_v2 = R"(
    {
        "qualifier": 1
    }
    )";

    const auto* without_content_without_qualifier = R"(
    {
    }
    )";
    // Given multiple ParameterSet instances with different content and qualifier combinations
    // When calling ContainsSameContent method to compare them
    // Then expect the correct boolean result based on content comparison
    ParameterSet ps_content_v1_qualifier_v1{std::move(json_parser.FromBuffer(content_v1_qualifier_v1).value())};
    ParameterSet ps_content_v1_qualifier_v2{std::move(json_parser.FromBuffer(content_v1_qualifier_v2).value())};
    ParameterSet ps_content_v2_qualifier_v1{std::move(json_parser.FromBuffer(content_v2_qualifier_v1).value())};
    ParameterSet ps_content_v2_qualifier_v2{std::move(json_parser.FromBuffer(content_v2_qualifier_v2).value())};
    ParameterSet ps_content_v1_without_qualifier{
        std::move(json_parser.FromBuffer(content_v1_without_qualifier).value())};
    ParameterSet ps_content_v2_without_qualifier{
        std::move(json_parser.FromBuffer(content_v2_without_qualifier).value())};
    ParameterSet ps_without_content_qualifier_v1{
        std::move(json_parser.FromBuffer(without_content_qualifier_v1).value())};
    ParameterSet ps_without_content_qualifier_v2{
        std::move(json_parser.FromBuffer(without_content_qualifier_v2).value())};
    ParameterSet ps_without_content_without_qualifier{
        std::move(json_parser.FromBuffer(without_content_without_qualifier).value())};

    EXPECT_TRUE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v1_qualifier_v1));
    EXPECT_TRUE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v1_qualifier_v2));
    EXPECT_TRUE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v1_without_qualifier));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v2_qualifier_v1));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v2_qualifier_v2));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_content_v2_without_qualifier));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_without_content_qualifier_v1));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_without_content_qualifier_v2));
    EXPECT_FALSE(ps_content_v1_qualifier_v1.ContainsSameContent(ps_without_content_without_qualifier));

    EXPECT_TRUE(ps_content_v1_without_qualifier.ContainsSameContent(ps_content_v1_without_qualifier));
    EXPECT_TRUE(ps_content_v1_without_qualifier.ContainsSameContent(ps_content_v1_qualifier_v1));
    EXPECT_FALSE(ps_content_v1_without_qualifier.ContainsSameContent(ps_content_v2_without_qualifier));
    EXPECT_FALSE(ps_content_v1_without_qualifier.ContainsSameContent(ps_without_content_without_qualifier));

    EXPECT_FALSE(ps_without_content_qualifier_v1.ContainsSameContent(ps_without_content_qualifier_v1));
    EXPECT_FALSE(ps_without_content_qualifier_v1.ContainsSameContent(ps_content_v1_qualifier_v1));
    EXPECT_FALSE(ps_without_content_qualifier_v1.ContainsSameContent(ps_without_content_qualifier_v2));
    EXPECT_FALSE(ps_without_content_qualifier_v1.ContainsSameContent(ps_without_content_without_qualifier));
}

TEST_F(ParameterSetTest, GetParameterAs_String)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description", "This test verifies success of GetParameterAs method with string type");

    // Given the parameter "string" is of type string
    auto result = GetParameterSet().GetParameterAs<std::string>("string");

    // Then expect getting exact content correctly when trying to get it as string
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), std::string("foo"));
}

TEST_F(ParameterSetTest, GetParameterAsArray_String)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description", "This test verifies success of GetParameterAsArray method with string type");

    // Given the parameter "array_string" is of type array of strings
    auto result = GetParameterSet().GetParameterAs<ParameterSet::Array<std::string>>("array_string");
    ASSERT_TRUE(result.has_value());
    // Then expect getting exact content correctly when trying to get it as array of strings
    const auto expected = ParameterSet::Array<std::string>{"a", "b"};
    EXPECT_EQ(result.value(), expected);
}

TEST_F(ParameterSetTest, GetParameterAsTwoDimensionalArray_String)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description",
                   "This test verifies success of GetParameterAsTwoDimensionalArray method with string type");

    // Given the parameter "array2d_string" is of type two dimensional array of strings
    auto result = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<std::string>>("array2d_string");
    ASSERT_TRUE(result.has_value());
    ParameterSet::Array<std::string> first{"a", "b"};
    ParameterSet::Array<std::string> second{"c", "d"};
    ParameterSet::TwoDimensionalArray<std::string> expected_twodim{first, second};
    // Then expect getting exact content correctly when trying to get it as two dimensional array of strings
    ASSERT_EQ(expected_twodim.size(), result.value().size());
    EXPECT_EQ(result.value(), expected_twodim);
}

TEST_F(ParameterSetTest, GetParameterAsTwoDimensionalArray_Bool)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description",
                   "This test verifies success of GetParameterAsTwoDimensionalArray method with bool type");

    // Given the parameter "array2d_bool" is of type two dimensional array of bools
    auto result = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<bool>>("array2d_bool");
    ASSERT_TRUE(result.has_value());
    ParameterSet::Array<bool> first{true, false};
    ParameterSet::Array<bool> second{false, true};
    ParameterSet::TwoDimensionalArray<bool> expected_twodim{first, second};
    // Then expect getting exact content correctly when trying to get it as two dimensional array of bools
    ASSERT_EQ(expected_twodim.size(), result.value().size());
    EXPECT_EQ(result.value(), expected_twodim);
}

TEST_F(ParameterSetTest, GetParameterAs_ValueCastingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description", "This test verifies success of ValueCasting error handling");

    // GetParameterAs
    // Given the parameter "string" is of type string
    auto result = GetParameterSet().GetParameterAs<int>("string");
    ASSERT_FALSE(result.has_value());
    // Then expect ValueCasting error when trying to get it as int
    EXPECT_EQ(result.error(), ConfigProviderError::kValueCastingError);

    auto result_string_as_float = GetParameterSet().GetParameterAs<float>("string");
    ASSERT_FALSE(result_string_as_float.has_value());
    // Then expect ValueCasting error when trying to get it as float
    EXPECT_EQ(result_string_as_float.error(), ConfigProviderError::kValueCastingError);

    auto result_string_as_double = GetParameterSet().GetParameterAs<double>("string");
    ASSERT_FALSE(result_string_as_double.has_value());
    // Then expect ValueCasting error when trying to get it as double
    EXPECT_EQ(result_string_as_double.error(), ConfigProviderError::kValueCastingError);

    // GetParameterAsArray
    // Given the parameter "array_string" is of type array of strings
    auto result1 = GetParameterSet().GetParameterAs<ParameterSet::Array<int>>("array_string");
    ASSERT_FALSE(result1.has_value());
    // Then expect ValueCasting error when trying to get it as Array<int>
    EXPECT_EQ(result1.error(), ConfigProviderError::kValueCastingError);

    // Given the parameter "float_as_decimal" is of type float
    auto result2 = GetParameterSet().GetParameterAs<ParameterSet::Array<int>>("float_as_decimal");
    ASSERT_FALSE(result2.has_value());
    // Then expect ValueCasting error when trying to get it as Array<int>
    EXPECT_EQ(result2.error(), ConfigProviderError::kValueCastingError);

    // GetParameterAsTwoDimensionalArray
    // Given the parameter "array2d_string" is of type two dimensional array of strings
    auto result3 = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<int>>("array2d_string");
    ASSERT_FALSE(result3.has_value());
    // Then expect ValueCasting error when trying to get it as TwoDimensionalArray<int>
    EXPECT_EQ(result3.error(), ConfigProviderError::kValueCastingError);

    // Given the parameter "float_as_decimal" is of type float
    auto result4 = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<int>>("float_as_decimal");
    ASSERT_FALSE(result4.has_value());
    // Then expect ValueCasting error when trying to get it as TwoDimensionalArray<int>
    EXPECT_EQ(result4.error(), ConfigProviderError::kValueCastingError);

    // Given the parameter "array_string" is of type array of strings
    auto result5 = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<int>>("array_string");
    ASSERT_FALSE(result5.has_value());
    // Then expect ValueCasting error when trying to get it as TwoDimensionalArray<int>
    EXPECT_EQ(result5.error(), ConfigProviderError::kValueCastingError);
}

TEST_F(ParameterSetTest, GetParameterAs_ParameterNotFoundError)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("Description", "This test verifies success of ParameterNotFound error handling");

    // Given the parameter "foo" does not exist
    auto result = GetParameterSet().GetParameterAs<int>("foo");
    ASSERT_FALSE(result.has_value());
    // Then expect ParameterNotFound error
    EXPECT_EQ(result.error(), ConfigProviderError::kParameterNotFound);

    // Given the parameter "foo" does not exist
    auto result1 = GetParameterSet().GetParameterAs<ParameterSet::Array<int>>("foo");
    ASSERT_FALSE(result1.has_value());
    // Then expect ParameterNotFound error
    EXPECT_EQ(result1.error(), ConfigProviderError::kParameterNotFound);

    // Given the parameter "foo" does not exist
    auto result2 = GetParameterSet().GetParameterAs<ParameterSet::TwoDimensionalArray<int>>("foo");
    ASSERT_FALSE(result2.has_value());
    // Then expect ParameterNotFound error
    EXPECT_EQ(result2.error(), ConfigProviderError::kParameterNotFound);
}

TEST(SimpleParameterSetTest, GetParameterAs_ParametersNotAnObject)
{
    RecordProperty("Priority", "3");
    RecordProperty("Description", "Tests error handling when parameters isn't a JSON object.");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "::score::platform::config_provider::ParameterSet::GetParameterAs()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");

    // Given the parameters is not an JSON object
    std::string text = R"(
    {
        "parameters": 5,
        "qualifier": 0
    })";
    json::JsonParser json_parser{};
    ParameterSet parameter_set{std::move(json_parser.FromBuffer(text).value())};
    auto result = parameter_set.GetParameterAs<bool>("parameter").error();
    // Then expect ObjectCasting error
    EXPECT_EQ(result, ConfigProviderError::kObjectCastingError);
}

}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score

// Explicit template instantiations to catch signature regressions
template score::Result<int> score::platform::config_provider::ParameterSet::GetParameterAs<int>(
    const score::cpp::string_view&) const;
template score::Result<score::platform::config_provider::ParameterSet::Array<int>>
score::platform::config_provider::ParameterSet::GetParameterAs<score::platform::config_provider::ParameterSet::Array<int>>(
    const score::cpp::string_view&) const;
template score::Result<score::platform::config_provider::ParameterSet::TwoDimensionalArray<int>>
score::platform::config_provider::ParameterSet::GetParameterAs<
    score::platform::config_provider::ParameterSet::TwoDimensionalArray<int>>(const score::cpp::string_view&) const;
