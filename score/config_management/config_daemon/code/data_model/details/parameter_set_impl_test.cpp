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

#include "score/config_management/config_daemon/code/data_model/details/parameter_set_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"

#include "score/json/internal/model/any.h"
#include "score/json/json_parser.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

namespace test
{

using ::score::config_management::config_daemon::data_model::DataModelError;

class ParameterSetFixture : public ::testing::Test
{
  public:
    void SetUp() override
    {
        parameter_set = std::make_unique<ParameterSet>();

        std::ignore = parameter_set->Add("foo", score::json::Any{42U});
        std::ignore = parameter_set->Add("bar", score::json::Any{69420U});
        parameter_set->SetCalibratable(true);
    }

    std::unique_ptr<ParameterSet> parameter_set;
};

TEST_F(ParameterSetFixture, SetAndGetParameterSetQualifier)
{
    RecordProperty("lobster-tracing", "ConfigDaemon.ParameterSetServiceOffering");
    RecordProperty("Verifies", "22912892");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "Verifies that the parameter set qualifier can be set and read.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Priority", "2");

    EXPECT_EQ(ParameterSetQualifier::kUnqualified, parameter_set->GetQualifier());
    parameter_set->SetQualifier(ParameterSetQualifier::kModified);
    EXPECT_EQ(ParameterSetQualifier::kModified, parameter_set->GetQualifier());
}

TEST_F(ParameterSetFixture, GetParameterSetAsString_Pass)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::GetParameterSetAsString");
    RecordProperty("Description",
                   "Verifies that GetParameterSetAsString will return JSON formatted representation of parameter set");

    const auto* const expected = R"({"parameters":{"bar":69420,"foo":42},"qualifier":0})";

    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
}

TEST_F(ParameterSetFixture, GetParameterSetAsString_ContainsQualifier)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::GetParameterSetAsString");
    RecordProperty(
        "Description",
        "Verifies that GetParameterSetAsString emits the numeric underlying value of the currently set qualifier.");

    parameter_set->SetQualifier(ParameterSetQualifier::kQualifying);

    const auto* const expected = R"({"parameters":{"bar":69420,"foo":42},"qualifier":4})";

    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
}

TEST_F(ParameterSetFixture, Add_NoUpdateToExistingValue)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::Add");
    RecordProperty("Description", "Verifies that Add method won't update already existing parameter value");

    auto add_result = parameter_set->Add("foo", score::json::Any{43U});
    ASSERT_FALSE(add_result.has_value());
    EXPECT_EQ(
        add_result,
        score::MakeUnexpected(DataModelError::kParameterAlreadyExists, "Parameter already exist in parameter set"));
    const auto* const expected = R"({"parameters":{"bar":69420,"foo":42},"qualifier":0})";

    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
}

TEST_F(ParameterSetFixture, Update_Pass)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::Update");
    RecordProperty("Description",
                   "Verifies that Update method will update the parameters, and GetParameterSetAsString method will "
                   "return updated values");

    const std::string updated_set = R"({
    "bar": 31337,
    "foo": 2137
})";

    const score::json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    const std::string expected = R"({"parameters":{"bar":31337,"foo":2137},"qualifier":0})";

    EXPECT_TRUE(
        parameter_set->Update(std::move(parsing_result.value().As<score::json::Object>().value().get())).has_value());
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected.c_str());
}

TEST_F(ParameterSetFixture, Update_Fail_NotCalibratable)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::Update");
    RecordProperty("Description",
                   "Verifies that Update method will return an error for not calibratable parameter set");

    parameter_set->SetCalibratable(false);

    const std::string updated_set = R"({
    "bar": 31337,
    "foo": 2137
})";

    const std::string expected = R"({"parameters":{"bar":69420,"foo":42},"qualifier":0})";

    const score::json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    EXPECT_EQ(parameter_set->Update(std::move(parsing_result.value().As<score::json::Object>().value().get())).error(),
              score::MakeUnexpected(DataModelError::kParameterSetNotCalibratable, "ParameterSet is not calibratable")
                  .error());
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected.c_str());
}

TEST_F(ParameterSetFixture, Update_Fail_ParameterDoesNotExist)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::Update");
    RecordProperty("Description",
                   "Verifies that Update method will return an error for when parameter to be updated does not exist");

    const std::string updated_set = R"({
    "baz": 58008
})";

    const score::json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    const std::string expected = R"({"parameters":{"bar":69420,"foo":42},"qualifier":0})";

    EXPECT_EQ(parameter_set->Update(std::move(parsing_result.value().As<score::json::Object>().value().get())).error(),
              score::MakeUnexpected(DataModelError::kParametersNotFound, "Some parameters are not found").error());
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected.c_str());
}

TEST(ParameterSetTest, DefaultQualifierIsUnqualified)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::ParameterSet");
    RecordProperty("Description",
                   "Verifies that a newly created parameter set has the qualifier UNQUALIFIED. Sets that are created "
                   "implicitly by Insert() or InsertOrAssign() must never be QUALIFIED before their values are "
                   "written.");

    const ParameterSet parameter_set{};

    EXPECT_EQ(parameter_set.GetQualifier(), ParameterSetQualifier::kUnqualified);
    EXPECT_EQ(parameter_set.GetParameterCount(), 0U);
}

TEST_F(ParameterSetFixture, InsertOrAssign_InsertsNewParameter)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::InsertOrAssign");
    RecordProperty("Description",
                   "Verifies that InsertOrAssign inserts a parameter that doesn't exist yet and reports it as "
                   "inserted.");

    EXPECT_TRUE(parameter_set->InsertOrAssign("baz", score::json::Any{7U}));

    const auto* const expected = R"({"parameters":{"bar":69420,"baz":7,"foo":42},"qualifier":0})";
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
    EXPECT_EQ(parameter_set->GetParameterCount(), 3U);
}

TEST_F(ParameterSetFixture, InsertOrAssign_AssignsExistingParameter)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::InsertOrAssign");
    RecordProperty("Description",
                   "Verifies that InsertOrAssign replaces the value of an existing parameter and reports it as "
                   "assigned.");

    EXPECT_FALSE(parameter_set->InsertOrAssign("foo", score::json::Any{43U}));

    const auto* const expected = R"({"parameters":{"bar":69420,"foo":43},"qualifier":0})";
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
    EXPECT_EQ(parameter_set->GetParameterCount(), 2U);
}

TEST_F(ParameterSetFixture, InsertOrAssign_ReplacesTypeAndNestedContent)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::InsertOrAssign");
    RecordProperty("Description",
                   "Verifies that InsertOrAssign replaces the complete stored parameter entry: the JSON type changes "
                   "(integer to floating-point, scalar to nested list) and lists are replaced, not merged.");

    const score::json::JsonParser json_parser{};

    // integer -> floating-point
    EXPECT_FALSE(parameter_set->InsertOrAssign("foo", score::json::Any{1.5}));
    // integer -> nested list
    auto nested_list = json_parser.FromBuffer(R"([[1, 2], [3]])");
    ASSERT_TRUE(nested_list.has_value());
    EXPECT_FALSE(parameter_set->InsertOrAssign("bar", std::move(nested_list.value())));
    // nested list -> shorter list with a different element type: no merge with the previous content
    auto replacement_list = json_parser.FromBuffer(R"([true])");
    ASSERT_TRUE(replacement_list.has_value());
    EXPECT_FALSE(parameter_set->InsertOrAssign("bar", std::move(replacement_list.value())));

    const auto* const expected = R"({"parameters":{"bar":[true],"foo":1.5},"qualifier":0})";
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
    EXPECT_EQ(parameter_set->GetParameterCount(), 2U);
}

TEST_F(ParameterSetFixture, InsertOrAssign_KeepsQualifierAndCalibratableFlag)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::InsertOrAssign");
    RecordProperty("Description",
                   "Verifies that InsertOrAssign doesn't change the qualifier or the calibratable flag of the set.");

    parameter_set->SetQualifier(ParameterSetQualifier::kQualifying);

    EXPECT_FALSE(parameter_set->InsertOrAssign("foo", score::json::Any{1U}));
    EXPECT_TRUE(parameter_set->InsertOrAssign("baz", score::json::Any{2U}));

    EXPECT_EQ(parameter_set->GetQualifier(), ParameterSetQualifier::kQualifying);

    // Calibratable flag is still set: Update() is still accepted
    const score::json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(R"({"foo": 3})");
    EXPECT_TRUE(
        parameter_set->Update(std::move(parsing_result.value().As<score::json::Object>().value().get())).has_value());
}

TEST_F(ParameterSetFixture, InsertOrAssign_WorksOnNotCalibratableSet)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::InsertOrAssign");
    RecordProperty("Description",
                   "Verifies that InsertOrAssign doesn't depend on the calibratable flag and that it doesn't set the "
                   "flag.");

    parameter_set->SetCalibratable(false);

    EXPECT_FALSE(parameter_set->InsertOrAssign("foo", score::json::Any{1U}));

    const auto* const expected = R"({"parameters":{"bar":69420,"foo":1},"qualifier":0})";
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);

    // Calibratable flag is still not set: Update() is still rejected
    const score::json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(R"({"foo": 3})");
    EXPECT_EQ(parameter_set->Update(std::move(parsing_result.value().As<score::json::Object>().value().get())).error(),
              score::MakeUnexpected(DataModelError::kParameterSetNotCalibratable, "ParameterSet is not calibratable")
                  .error());
}

TEST_F(ParameterSetFixture, GetParameterCount_ReturnsNumberOfParameters)
{
    RecordProperty("Priority", "2");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::GetParameterCount");
    RecordProperty("Description", "Verifies that GetParameterCount returns the number of parameters in the set.");

    EXPECT_EQ(parameter_set->GetParameterCount(), 2U);
    std::ignore = parameter_set->Add("baz", score::json::Any{1U});
    EXPECT_EQ(parameter_set->GetParameterCount(), 3U);
}
}  // namespace test
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
