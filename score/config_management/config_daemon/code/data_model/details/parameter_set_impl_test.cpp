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

#include "score/json/i_json_writer_mock.h"
#include "score/json/internal/model/any.h"
#include "score/json/json_parser.h"
#include "score/json/json_writer.h"

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

using testing::_;
using testing::Matcher;
using testing::Return;

class ParameterSetFixture : public ::testing::Test
{
  public:
    void SetUp() override
    {
        auto json_writer = std::make_unique<json::IJsonWriterMock>();
        json_writer_mock = json_writer.get();
        ON_CALL(*json_writer_mock, ToBuffer(Matcher<const json::Object&>(_)))
            .WillByDefault([this](const json::Object& obj) -> Result<std::string> {
                return json_writer_actual.ToBuffer(obj);
            });
        parameter_set = std::make_unique<ParameterSet>(std::move(json_writer));

        parameter_set->Add("foo", json::Any{42U});
        parameter_set->Add("bar", json::Any{69420U});
        parameter_set->SetCalibratable(true);
    }

    std::unique_ptr<ParameterSet> parameter_set;
    json::IJsonWriterMock* json_writer_mock;
    json::JsonWriter json_writer_actual;
};

TEST_F(ParameterSetFixture, SetAndGetParameterSetQualifier)
{
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

    const auto* const expected = R"({
    "parameters": {
        "bar": 69420,
        "foo": 42
    },
    "qualifier": 0
})";

    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
}

TEST_F(ParameterSetFixture, Add_NoUpdateToExistingValue)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::Add");
    RecordProperty("Description", "Verifies that Add method won't update already existing parameter value");

    auto add_result = parameter_set->Add("foo", json::Any{43U});
    ASSERT_FALSE(add_result.has_value());
    EXPECT_EQ(add_result,
              MakeUnexpected(DataModelError::kParameterAlreadyExists, "Parameter already exist in parameter set"));
    const auto* const expected = R"({
    "parameters": {
        "bar": 69420,
        "foo": 42
    },
    "qualifier": 0
})";

    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected);
}

TEST_F(ParameterSetFixture, GetParameterSetAsString_Fail_Json)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSet::GetParameterSetAsString");
    RecordProperty("Description",
                   "Verifies that GetParameterSetAsString method will return an error, when JSON writer fails");

    EXPECT_CALL(*json_writer_mock, ToBuffer(Matcher<const json::Object&>(_)))
        .WillOnce(Return(MakeUnexpected<score::json::Error>(score::json::Error::kInvalidFilePath)));
    EXPECT_EQ(parameter_set->GetParameterSetAsString().error(),
              MakeUnexpected<DataModelError>(DataModelError::kConvertingError).error());
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

    const json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    const std::string expected = R"({
    "parameters": {
        "bar": 31337,
        "foo": 2137
    },
    "qualifier": 0
})";

    EXPECT_TRUE(parameter_set->Update(std::move(parsing_result.value().As<json::Object>().value().get())).has_value());
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

    const std::string expected = R"({
    "parameters": {
        "bar": 69420,
        "foo": 42
    },
    "qualifier": 0
})";

    const json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    EXPECT_EQ(parameter_set->Update(std::move(parsing_result.value().As<json::Object>().value().get())).error(),
              MakeUnexpected(DataModelError::kParameterSetNotCalibratable, "ParameterSet is not calibratable").error());
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

    const json::JsonParser json_parser{};
    auto parsing_result = json_parser.FromBuffer(updated_set);

    const std::string expected = R"({
    "parameters": {
        "bar": 69420,
        "foo": 42
    },
    "qualifier": 0
})";

    EXPECT_EQ(parameter_set->Update(std::move(parsing_result.value().As<json::Object>().value().get())).error(),
              MakeUnexpected(DataModelError::kParametersNotFound, "Some parameters are not found").error());
    EXPECT_STREQ(parameter_set->GetParameterSetAsString().value().c_str(), expected.c_str());
}
}  // namespace test
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
