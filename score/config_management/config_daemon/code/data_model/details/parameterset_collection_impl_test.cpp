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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"

#include "score/json/internal/model/any.h"
#include "score/json/json_parser.h"

#include <score/vector.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

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

class ParameterSetCollectionFixture : public ::testing::Test
{
    void SetUp() override
    {
        parameter_data_ = std::make_shared<ParameterSetCollection>();
        set_name_for_update_tests_ = "set_name_for_update_tests";

        // insert a parameter set to be used for ParameterSetUpdate test
        json::JsonParser parser{};
        std::string json_data{"[1,2,3]"};
        auto parsing_result = parser.FromBuffer(json_data);
        ASSERT_TRUE(parsing_result.has_value());
        auto insert_result =
            parameter_data_->Insert(set_name_for_update_tests_, "parameter_name", std::move(parsing_result.value()));
        ASSERT_TRUE(insert_result.has_value());
        auto set_calibratable_result = parameter_data_->SetCalibratable(set_name_for_update_tests_, true);
        ASSERT_TRUE(set_calibratable_result);
        auto set_qualifier_result = parameter_data_->SetParameterSetQualifier(
            set_name_for_update_tests_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified);
        ASSERT_TRUE(set_qualifier_result.has_value());
    }

  protected:
    std::shared_ptr<ParameterSetCollection> parameter_data_;
    std::string set_name_for_update_tests_;
};

const std::vector<std::string> kSetNames{{"test_set_name_1"},
                                         {"test_set_name_2"},
                                         {"test_set_name_3"},
                                         {"test_set_name_4"},
                                         {"test_set_name_5"},
                                         {"test_set_name_6"},
                                         {"test_set_name_7"},
                                         {"test_set_name_8"},
                                         {"test_set_name_9"},
                                         {"test_set_name_10"}};

const std::string kParameterNameUint64{"test_parameter_name_uint64"};
const std::string kParameterNameUint32{"test_parameter_name_uint32"};
const std::string kParameterNameUint16{"test_parameter_name_uint16"};
const std::string kParameterNameUint8{"test_parameter_name_uint8"};
const std::string kParameterNameInt64{"test_parameter_name_int64"};
const std::string kParameterNameInt32{"test_parameter_name_int32"};
const std::string kParameterNameInt16{"test_parameter_name_int16"};
const std::string kParameterNameInt8{"test_parameter_name_int8"};
const std::string kParameterNameFloat{"test_parameter_name_float"};
const std::string kParameterNameDouble{"test_parameter_name_double"};
const std::string kParameterNameByteArray{"test_parameter_name_byte_array"};

const std::string kByteArrayValue = R"({
    "list" : [ 1, 2, 3, 4, 5 ]
})";

score::cpp::pmr::string gExpectedParameterSet = R"({
    "parameters": {
        "test_parameter_name_byte_array": [
            1,
            2,
            3,
            4,
            5
        ],
        "test_parameter_name_double": 1.7976931348623157e+308,
        "test_parameter_name_float": 3.40282347e+38,
        "test_parameter_name_int16": -32768,
        "test_parameter_name_int32": -2147483648,
        "test_parameter_name_int64": -9223372036854775808,
        "test_parameter_name_int8": -128,
        "test_parameter_name_uint16": 65535,
        "test_parameter_name_uint32": 4294967295,
        "test_parameter_name_uint64": 18446744073709551615,
        "test_parameter_name_uint8": 255
    },
    "qualifier": 0
})";

TEST_F(ParameterSetCollectionFixture, ParameterSetCollectionComplexTest)
{
    RecordProperty("Verifies", "24399695, 24400736");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description",
                   "Expecting GetParameterSet will return proper data with Inserts from multiple threads");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Priority", "3");

    for (const auto& set_name : kSetNames)
    {
        EXPECT_FALSE(parameter_data_->GetParameterSet(set_name).has_value());
    }

    score::cpp::pmr::vector<std::thread> insert_threads;
    insert_threads.reserve(kSetNames.size() * 4);

    for (const auto& set_name : kSetNames)
    {
        std::thread thread_1([&]() noexcept {
            auto byte_array_value_res = score::json::JsonParser().FromBuffer(kByteArrayValue);
            EXPECT_TRUE(byte_array_value_res.has_value());
            json::Any list{std::move(byte_array_value_res.value().As<json::Object>().value().get()["list"])};
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameByteArray, std::move(list)).has_value());
        });
        std::thread thread_2([&]() noexcept {
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameUint64, json::Any{UINT64_MAX}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameUint32, json::Any{UINT32_MAX}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameUint16, json::Any{UINT16_MAX}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameUint8, json::Any{UINT8_MAX}).has_value());
        });
        std::thread thread_3([&]() noexcept {
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameInt64, json::Any{INT64_MIN}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameInt32, json::Any{INT32_MIN}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameInt16, json::Any{INT16_MIN}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameInt8, json::Any{INT8_MIN}).has_value());
        });
        std::thread thread_4([&]() noexcept {
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameFloat, json::Any{FLT_MAX}).has_value());
            EXPECT_TRUE(parameter_data_->Insert(set_name, kParameterNameDouble, json::Any{DBL_MAX}).has_value());
        });

        insert_threads.push_back(std::move(thread_1));
        insert_threads.push_back(std::move(thread_2));
        insert_threads.push_back(std::move(thread_3));
        insert_threads.push_back(std::move(thread_4));
    }
    for (auto& thread : insert_threads)
    {
        thread.join();
    }

    score::cpp::pmr::vector<std::thread> find_threads;
    find_threads.reserve(kSetNames.size());

    for (const auto& set_name : kSetNames)
    {
        std::thread thread([&]() noexcept {
            auto result = parameter_data_->GetParameterSet(set_name);
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(gExpectedParameterSet, result.value());
        });

        find_threads.push_back(std::move(thread));
    }
    for (auto& thread : find_threads)
    {
        thread.join();
    }
}

TEST_F(ParameterSetCollectionFixture, InsertParameterFailWhenParameterExist)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSetCollection::Insert");
    RecordProperty("Description", "Verifies that Insert will fail when the parameter already exists");

    score::cpp::string_view set_name_for_insert_tests = "set_name_for_insert_tests";
    score::cpp::string_view param_name_for_insert_tests = "parameter_name_for_insert_tests";

    ASSERT_TRUE(
        parameter_data_->Insert(set_name_for_insert_tests, param_name_for_insert_tests, json::Any{1}).has_value());

    auto insert_result = parameter_data_->Insert(set_name_for_insert_tests, param_name_for_insert_tests, json::Any{2});
    ASSERT_FALSE(insert_result.has_value());
    ASSERT_EQ(insert_result.error(), MakeError(DataModelError::kParameterAlreadyExists));
}

TEST_F(ParameterSetCollectionFixture, TargetUpdatedParameterSetNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty("Description",
                   "Verifies that UpdateParameterSet method will return an error for nonexistent parameter set");

    auto update_result = parameter_data_->UpdateParameterSet("not_found_parameter_set", "{}");
    ASSERT_FALSE(update_result.has_value());
    ASSERT_EQ(update_result.error().UserMessage(), "Parameter set is not found");
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterSetFailDueToInvalidFormatForInputSetData)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty(
        "Description",
        "Verifies that UpdateParameterSet method will return an error for parameter set data with invalid format");

    json::JsonParser parser{};
    auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, "[");
    ASSERT_FALSE(update_result.has_value());
    ASSERT_EQ(update_result.error().UserMessage(), "Can't parse input set data as json format");
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterSetFailDueToInputSetDataNotObject)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty("Description",
                   "Verifies that UpdateParameterSet method will return an error for parameter set data with JSON list "
                   "instead of an object");

    json::JsonParser parser{};
    std::string valid_json_but_not_object_format = R"(
        [1,2,4]
    )";

    auto update_result =
        parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_json_but_not_object_format);
    ASSERT_FALSE(update_result.has_value());
    ASSERT_EQ(update_result.error().UserMessage(), "Set data expected to be object json formatted");
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterSucceed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty("Description",
                   "Verifies that UpdateParameterSet method will update the parameter set without an error and "
                   "GetParameterSet will return an updated value");

    json::JsonParser parser{};
    score::cpp::pmr::string expected_string_value = R"({
    "parameters": {
        "parameter_name": [
            3,
            4,
            5
        ]
    },
    "qualifier": 0
})";

    std::string json_data{"[1,2,3]"};
    std::string valid_set_object = R"({
        "parameter_name" : [3,4,5]
    })";

    // update parameter set with valid input data
    auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_set_object);
    ASSERT_TRUE(update_result.has_value());

    // check if parameter set updated with the target values successfully
    auto result = parameter_data_->GetParameterSet(set_name_for_update_tests_);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(expected_string_value, result.value());
}

TEST_F(ParameterSetCollectionFixture, GetParameterFromSetSucceed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::GetParameterFromSet");
    RecordProperty("Description", "Verifies that GetParameterFromSet will return expected values list");

    const std::vector<std::uint16_t> expected_values{1, 2, 3};

    // check for initial value
    auto result = parameter_data_->GetParameterFromSet(set_name_for_update_tests_, "parameter_name");
    EXPECT_TRUE(result.has_value());
    auto result_value = result.value().As<json::List>();
    EXPECT_TRUE(result_value.has_value());
    size_t value_id{0};
    for (const auto& value : result_value.value().get())
    {
        EXPECT_EQ(expected_values[value_id], value.As<std::uint16_t>().value());
        value_id++;
    }
}

TEST_F(ParameterSetCollectionFixture, GetParameterFromSetFailsMissingParameter)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::GetParameterFromSet");
    RecordProperty("Description",
                   "Verifies that GetParameterFromSet will return DataModelError::kParameterMissedError error in case "
                   "of invalid parameter name");

    auto result = parameter_data_->GetParameterFromSet(set_name_for_update_tests_, "parameter_name_x");
    EXPECT_FALSE(result.has_value());
    ASSERT_EQ(result.error(), DataModelError::kParameterMissedError);
}

TEST_F(ParameterSetCollectionFixture, GetParameterFromSetFailsMissingParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::GetParameterFromSet");
    RecordProperty("Description",
                   "Verifies that GetParameterFromSet will return DataModelError::kParameterSetNotFound error in case "
                   "of invalid parameter_set");

    auto result = parameter_data_->GetParameterFromSet("random_parameterset", "parameter_name");
    EXPECT_FALSE(result.has_value());
    ASSERT_EQ(result.error(), DataModelError::kParameterSetNotFound);
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterShallFailForUnCalibratableParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty("Description",
                   "Verifies that UpdateParameterSet method will return an error for uncalibratable parameter set");

    json::JsonParser parser{};
    score::cpp::pmr::string expected_string_value = R"({
    "parameters": {
        "parameter_name": [
            1,
            2,
            3
        ]
    },
    "qualifier": 0
})";

    std::string valid_set_object = R"({
        "parameter_name" : [3,4,5]
    })";
    // set parameter set not calibratable
    auto set_calibratable_result = parameter_data_->SetCalibratable(set_name_for_update_tests_, false);
    ASSERT_TRUE(set_calibratable_result);
    // update parameter set with valid input data
    auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_set_object);
    ASSERT_FALSE(update_result.has_value());
    ASSERT_EQ(update_result.error(), DataModelError::kParameterSetNotCalibratable);

    // check if parameter set has not been updated with the target values (valid_set_object).
    auto result = parameter_data_->GetParameterSet(set_name_for_update_tests_);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(expected_string_value, result.value());
}

TEST_F(ParameterSetCollectionFixture, SetCalibratable_Fail_NoParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::ParameterSetCollection::SetCalibratable");
    RecordProperty("Description", "Testing that SetCalibratable returns false for nonexisting parameter_set");

    auto set_calibratable_result = parameter_data_->SetCalibratable("not_existing", false);
    EXPECT_FALSE(set_calibratable_result);
    // update parameter set with valid input data
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterFailedDueToParametersNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty(
        "Description",
        "Testing that UpdateParameterSet should return error if input set data contains not found parameters");

    json::JsonParser parser{};
    std::string json_data{"[1,2,3]"};

    std::string valid_set_object = R"({
        "parameter_name": [3,4,5],
        "parameter_name_not_found": 1
    })";
    auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_set_object);
    ASSERT_FALSE(update_result.has_value());
    ASSERT_EQ(update_result.error().UserMessage(), "Some parameters are not found");
}

TEST_F(ParameterSetCollectionFixture, UpdateParameterSucceedInMultiThreadingUse)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::UpdateParameterSet");
    RecordProperty("Description",
                   "Testing that UpdateParameterSet can update parameter set with input json parsable data without "
                   "data race when it's used concurrently");

    std::vector<std::thread> threads;
    json::JsonParser parser{};

    score::cpp::pmr::string expected_string_value_by_thread2 = R"({
    "parameters": {
        "parameter_name": [
            5,
            6,
            7,
            8
        ]
    },
    "qualifier": 0
})";

    score::cpp::pmr::string expected_string_value_by_thread1 = R"({
    "parameters": {
        "parameter_name": [
            9,
            10,
            11,
            12
        ]
    },
    "qualifier": 0
})";

    std::string json_data{"[1,2,3]"};

    // update parameters in seperate thread
    std::thread thread1([this]() {
        std::string valid_set_object = R"({
            "parameter_name" : [9,10,11,12]
        })";
        auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_set_object);
        ASSERT_TRUE(update_result.has_value());
    });
    threads.push_back(std::move(thread1));

    // update parameters in seperate thread
    std::thread thread2([this]() {
        std::string valid_set_object = R"({
            "parameter_name" : [5,6,7,8]
        })";
        auto update_result = parameter_data_->UpdateParameterSet(set_name_for_update_tests_, valid_set_object);
        ASSERT_TRUE(update_result.has_value());
    });
    threads.push_back(std::move(thread2));

    for (auto& thread : threads)
    {
        thread.join();
    }

    // check if parameter set updated with the target values successfully without data race
    // check if the parameter values have the values were updated with last thread
    auto result = parameter_data_->GetParameterSet(set_name_for_update_tests_);
    EXPECT_TRUE(result.has_value());
    // check if the data is not corrupted when it's updated by two threads as the same time
    // by checking that the updated value is equal to data updated by first thread or second one
    EXPECT_TRUE((expected_string_value_by_thread1 == result.value()) ||
                (expected_string_value_by_thread2 == result.value()));
}

TEST_F(ParameterSetCollectionFixture, SetParameterSetQualifier_Success)
{
    RecordProperty("Verifies", "22912892");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "Verifies that the parameter set qualifier can be set.");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Priority", "2");

    auto get_qualifier_result = parameter_data_->GetParameterSetQualifier(set_name_for_update_tests_);
    ASSERT_TRUE(get_qualifier_result.has_value());
    ASSERT_EQ(get_qualifier_result.value(), score::config_management::config_daemon::ParameterSetQualifier::kUnqualified);

    auto set_qualifier_result = parameter_data_->SetParameterSetQualifier(
        set_name_for_update_tests_, score::config_management::config_daemon::ParameterSetQualifier::kQualified);
    ASSERT_TRUE(set_qualifier_result.has_value());

    get_qualifier_result = parameter_data_->GetParameterSetQualifier(set_name_for_update_tests_);
    ASSERT_TRUE(get_qualifier_result.has_value());
    ASSERT_EQ(get_qualifier_result.value(), score::config_management::config_daemon::ParameterSetQualifier::kQualified);
}

TEST_F(ParameterSetCollectionFixture, GetSetParameterSetQualifier_NonExistentSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::data_model::ParameterSetCollection::GetParameterSetQualifier");
    RecordProperty("Description", "Verifies the error handling if a parameter set doesn't exist.");

    std::string non_existent_set_name{"nonExistentSetName"};

    auto get_qualifier_result = parameter_data_->GetParameterSetQualifier(non_existent_set_name);
    ASSERT_FALSE(get_qualifier_result.has_value());
    ASSERT_EQ(get_qualifier_result.error(), DataModelError::kParameterSetNotFound);

    auto set_qualifier_result = parameter_data_->SetParameterSetQualifier(
        non_existent_set_name, score::config_management::config_daemon::ParameterSetQualifier::kQualified);
    ASSERT_FALSE(set_qualifier_result.has_value());
    ASSERT_EQ(set_qualifier_result.error(), DataModelError::kParameterSetNotFound);
}

}  // namespace test
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
