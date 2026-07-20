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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details/parameter_loader_impl.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping_mock.h"
#include "score/json/json_parser.h"
#include "score/result/error_code.h"
#include "score/result/result.h"

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_score_types.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter_mock.h"
#include "platform/aas/mw/diag/dtc/dtc_mock.h"
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{
namespace test
{

const score::cpp::string_view kSetNameA{"param_set_name_a"};
const score::cpp::string_view kSetNameB{"param_set_name_b"};
const score::cpp::string_view kParameterNameA{"param_name_a"};
const score::cpp::string_view kParameterNameB{"param_name_b"};

const std::int64_t kParameterValue{11};

using testing::_;
using testing::AnyNumber;
using testing::ByMove;
using testing::Invoke;
using testing::Return;
using FaultEventId = score::config_management::config_daemon::fault_event_reporter::FaultEventId;

class ParameterLoaderImplTest : public ::testing::Test
{
  public:
    inline static std::unique_ptr<Result<json::Any>> StringToJsonResult(const std::string& file_contents)
    {
        return std::make_unique<Result<json::Any>>(json::JsonParser().FromBuffer(file_contents));
    }

  protected:
    void SetUp() override
    {
        calibration_data_ = Result<json::Any>{};
        parameter_data_handler_mock_ = std::make_shared<data_model::ParameterSetCollectionMock>();
        param_set_mapping_mock_ = std::make_shared<score::config_management::config_daemon::coding::ParamSetMappingMock>();
        dtc_integrity_error_mock_ = std::make_unique<score::mw::diag::DTCMock>();
        dtc_default_values_in_use_mock_ = std::make_unique<score::mw::diag::DTCMock>();
        fault_event_reporter_mock_ =
            std::make_shared<score::config_management::config_daemon::fault_event_reporter::FaultEventReporterMock>();

        // Default: pre-insert existence check returns "not found" so Insert proceeds normally.
        // Test-specific expectations defined later in each test override this for matching args.
        EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(_, _))
            .Times(AnyNumber())
            .WillRepeatedly(Invoke([](const score::cpp::string_view, const score::cpp::string_view) -> Result<json::Any> {
                return score::MakeUnexpected<json::Any>(data_model::DataModelError::kParametersNotFound);
            }));
    }

    void TearDown() override
    {
        // delete old mocks by decrementing the reference count (which should be 1) of the shared pointers
        parameter_data_handler_mock_.reset();
        param_set_mapping_mock_.reset();
        param_loader_.reset();
    }

    void SetUpParameterLoader(std::unique_ptr<Result<json::Any>> calibration_data)
    {
        param_loader_ = std::make_shared<ParameterLoaderImpl>(std::move(calibration_data),
                                                              param_set_mapping_mock_,
                                                              fault_event_reporter_mock_,
                                                              std::move(dtc_integrity_error_mock_),
                                                              std::move(dtc_default_values_in_use_mock_));
    }

    /* Add expectation on parameter_data handler mock to check that it was called with the correct parameters.
    It will make the mock run a lambda which checks the integer value inside a json::Any object, to
    check if it is the expected value. This is needed, because json::Any is move-only, and GTest
    argument matchers do not work with move-only types.*/
    void ExpectParameterDataInsert(const score::cpp::string_view set_name,
                                   const score::cpp::string_view parameter_name,
                                   std::int64_t value)
    {
        EXPECT_CALL(*parameter_data_handler_mock_, Insert(set_name, parameter_name, _))
            .WillOnce(Invoke([value](const score::cpp::string_view, const score::cpp::string_view, json::Any&& provided_value) {
                EXPECT_EQ(provided_value.As<std::int64_t>().value(), value);
                return Result<void>();
            }));
    }

    Result<json::Any> calibration_data_;
    std::shared_ptr<data_model::ParameterSetCollectionMock> parameter_data_handler_mock_;
    std::shared_ptr<score::config_management::config_daemon::coding::ParamSetMappingMock> param_set_mapping_mock_;
    std::unique_ptr<score::mw::diag::DTCMock> dtc_integrity_error_mock_;
    std::unique_ptr<score::mw::diag::DTCMock> dtc_default_values_in_use_mock_;
    std::shared_ptr<score::config_management::config_daemon::fault_event_reporter::FaultEventReporterMock>
        fault_event_reporter_mock_;
    std::shared_ptr<ParameterLoaderImpl> param_loader_;
};

TEST(SimpleParameterLoaderTest, testLoadingParameterFailedDueToParameterSetMappingIsNullptr)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies that LoadParameterData marks the parameter as unqualified and triggers a DTC "
                   "integrity error due to the failure in loading the coding-dependent parameter, which occurs because "
                   "ParameterSetMapping is nullptr.");

    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();
    auto fault_event_reporter_mock =
        std::make_shared<score::config_management::config_daemon::fault_event_reporter::FaultEventReporterMock>();
    auto dtc_integrity_error_mock = std::make_unique<score::mw::diag::DTCMock>();
    auto dtc_default_values_in_use_mock = std::make_unique<score::mw::diag::DTCMock>();

    std::string json_coding_data = R"(
        { "parameterSets": {
        "param_set_name_a": {
            "containsDefaultValue": false,
             "parameters": {
                "param_name_a": {
                    "initValue": 1,
                    "codingDependency": {
                        "codingParamName": "coding_param_name",
                        "codingParamValues": {
                        "1": 11
                        }
                    }
                }
            }
        }
        } }
    )";

    EXPECT_CALL(*dtc_integrity_error_mock, Failed()).Times(1);

    auto param_loader =
        std::make_shared<ParameterLoaderImpl>(ParameterLoaderImplTest::StringToJsonResult(json_coding_data),
                                              nullptr,
                                              fault_event_reporter_mock,
                                              std::move(dtc_integrity_error_mock),
                                              std::move(dtc_default_values_in_use_mock));

    EXPECT_CALL(*parameter_data_handler_mock,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);

    // Default: pre-insert existence check returns "not found" so Insert proceeds normally.
    EXPECT_CALL(*parameter_data_handler_mock, GetParameterFromSet(_, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](const score::cpp::string_view, const score::cpp::string_view) -> Result<json::Any> {
            return score::MakeUnexpected<json::Any>(data_model::DataModelError::kParametersNotFound);
        }));

    EXPECT_CALL(*parameter_data_handler_mock, Insert(_, _, _)).Times(1);

    auto res = param_loader->LoadParameterData(parameter_data_handler_mock);
    EXPECT_EQ(res, true);
}

/**
 * Test: Given a valid json calibration data file, the data is read correctly and inserted into the data model via
 * IParameterData.
 */
TEST_F(ParameterLoaderImplTest, testLoadingParameterSucceeds)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539581, 13356426");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies that both coding-dependent and non-coding-dependent parameters are parsed correctly and "
        "inserted into the data model. It also verifies that the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        {
            "parameterSets": {
                "param_set_name_a": {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_a": {
                            "initValue": 1,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "codingParamValues": {
                                    "1": 11,
                                    "2": 22,
                                    "3": 33,
                                    "4": 44
                                }
                            }
                        },
                        "param_name_c": {
                            "initValue": 1000
                        },
                        "param_name_d": {
                            "initValue": 11,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "codingParamValues": {
                                    "1": 111,
                                    "2": 222,
                                    "3": 333,
                                    "4": 444
                                }
                            }
                        }
                    }
                },
                "param_set_name_b": {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_b": {
                            "initValue": 42
                        },
                        "param_name_e": {
                            "initValue": 420
                        }
                    }
                }
        } }
    )";
    EXPECT_CALL(*dtc_integrity_error_mock_, Succeeded()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Succeeded()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view coding_param_name = "coding_param_name";

    score::cpp::string_view coding_set_name = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillRepeatedly(Return(coding_set_name));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(coding_set_name, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(std::uint16_t{1}))))
        .WillOnce(Return(ByMove(score::json::Any(std::uint16_t{3}))));

    EXPECT_CALL(*parameter_data_handler_mock_, SetCalibratable(_, true)).WillRepeatedly(Return(true));
    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterSetQualifier(_))
        .WillRepeatedly(Return(ParameterSetQualifier::kQualified));
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kQualified))
        .Times(AnyNumber());
    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), false))
        .Times(1)
        .WillOnce(Return(false));

    auto expected_value_param_a{11};
    auto expected_value_param_b{42};
    auto expected_value_param_c{1000};
    auto expected_value_param_d{333};
    auto expected_value_param_e{420};

    ExpectParameterDataInsert(kSetNameA, "param_name_a", expected_value_param_a);
    ExpectParameterDataInsert(kSetNameB, "param_name_b", expected_value_param_b);
    ExpectParameterDataInsert(kSetNameA, "param_name_c", expected_value_param_c);
    ExpectParameterDataInsert(kSetNameA, "param_name_d", expected_value_param_d);
    ExpectParameterDataInsert(kSetNameB, "param_name_e", expected_value_param_e);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testSucceedsWithCalibrationParameter)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539581, 13356426");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies loading parameter succeeds with non-coding-dependent calibration parameter");
    RecordProperty("Priority", "2");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_b": {
                        "initValue": 11
                    }
                }
            }
        }}
    )";

    SetUpParameterLoader(StringToJsonResult(json_data));
    ExpectParameterDataInsert(kSetNameB, kParameterNameB, kParameterValue);
    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingParameterFailedDueToFailingToUpdateTheCalibrationFlag)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("ASIL", "B");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies that LoadParameterData method returns true when failing to update the "
                   "is_calibratable flag of a parameter set through `SetCalibratable`");

    std::string json_coding_data = R"(
        {
            "parameterSets": {
                "param_set_name_a": {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_a": {
                        "initValue": 1,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "codingParamValues": {
                                "1": 11
                                }
                            }
                        }
                    }
                }
        }   }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 1;

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    EXPECT_CALL(*parameter_data_handler_mock_, SetCalibratable(_, true)).WillRepeatedly(Return(false));

    ExpectParameterDataInsert(kSetNameA, kParameterNameA, kParameterValue);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, loadingParameterFailsDueToJsonObjIsInvalid)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("ASIL", "B");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test verifies LoadParameterData returns 'false' due to invalid JSON object");

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(false));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(std::make_unique<Result<json::Any>>(MakeUnexpected(json::Error::kInvalidFilePath)));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, false);
}

TEST_F(ParameterLoaderImplTest, loadingParameterFailsDueToNullptrCalibrationData)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("ASIL", "B");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("Description",
                   "This test verifies LoadParameterData returns 'false' due to nullptr calibration_data");

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(false));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(nullptr);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, false);
}

TEST_F(ParameterLoaderImplTest, testFailsDueToLoadingJsonListNotObject)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies LoadParameterData returns 'false' when json is not an object");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"([])";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, false);
}

TEST_F(ParameterLoaderImplTest, testFailsDueToparameterSetsKeyMissing)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData returns 'false' when 'parameterSets' key is missing");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({})";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, false);
}

TEST_F(ParameterLoaderImplTest, testFailsDueToValueOfparameterSetsNotObject)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData returns 'false' when value of 'parameterSets' is not an object");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({
        "parameterSets": []
        })";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, false);
}

TEST_F(ParameterLoaderImplTest, testSettingIntegrityErrorForNonObjectParameterSet)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies integrity error dtcs' are set when a parameter set is not a JSON object");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({
        "parameterSets": {
            "parameter_set_name_a": "invalid object"
        }
        })";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testFailsDueToSetContainsDefaultValueMissing)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData doesn't insert parameter when 'containsDefaultValue' key is missing");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({
        "parameterSets": {
            "parameter_set_name_a": {
                "parameters": {
                    "param_name_a": 1
                }
            }
        }
        })";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testFailsConvertSetContainsDefaultValueToBoolean)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData doesn't insert parameter when value  of "
                   "'containsDefaultValue' is not a boolean");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({
        "parameterSets": {
            "parameter_set_name_a": {
                "containsDefaultValue": "foo",
                "parameters": {
                    "param_name_a": 1
                }
            }
        }
        })";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testSetContainsDefaultValueTrue)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "22913199, 13356426, 20540843");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData inserts parameter with a default value. It also verifies that "
                   "the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": true,
                "parameters": {
                    "param_name_b": {
                        "initValue": 11
                    }
                }
            }
        }}
    )";

    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);
    SetUpParameterLoader(StringToJsonResult(json_data));

    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kQualified))
        .Times(1);

    ExpectParameterDataInsert(kSetNameB, kParameterNameB, 11);
    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, TestParametersWillNotParsedDueToParametersKeyNotFound)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData will not insert parameters if 'parameters' key is not found"
                   "It also verifies that the DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters!": {
                    "param_name_b": {
                        "initValue": 11
                    }
                }
            }
        }}
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, TestParametersWillNotParsedDueToParametersNotObject)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData will not insert parameters if parameters is not a JSON object"
                   "It also verifies that the DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters": [{
                    "param_name_b": {
                        "initValue": 11
                    }
                }]
            }
        }}
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingNonObjectParamSetFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData doesn't insert parameter when parameter set is not an object");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "non_object_element": 1
    } }
    )";

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingNonObjectParamFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389, 20606484, 20540832, 13356426");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData doesn't insert parameter when value of parameter is not an "
                   "object. It also verifies that the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": 1
            }
        }
    }
     })";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingParamMissingInitValueFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389, 20606484, 20540832, 13356426");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData doesn't insert parameter when 'initValue' is missing. It also "
                   "verifies that the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_b": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_b": {
                "xinitValue": 11
                }
            }
        }
    } }
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingParamMissingCodingParamNameFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389, 20606484, 20540832");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData doesn't insert parameter when 'codingParamName' is missing");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        {
            "parameterSets": {
                "param_set_name_a": {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_a": {
                            "initValue": 1,
                            "codingDependency": {
                                "xcodingParamName": "coding_param_name",
                                "codingParamValues": {
                                    "1": 11
                                }
                            }
                        }
                    }
                }
            }
        }
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(param_set_name, param_name, _)).Times(1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingParamMissingCodingParamValuesFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData fails to load coding-dependent parameter due to missing "
                   "'codingParamValues' key");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        {
            "parameterSets":
            {
                "param_set_name_a":
                {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_a": {
                            "initValue": 1,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "xcodingParamValues": {
                                    "1": 11
                                }
                            }
                        }
                    }
                }
            }
        }
    )";
    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 1;

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(param_set_name, param_name, _)).Times(1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingNonObjectCodingParamValuesFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData fails to load coding-dependent parameter due to value of "
                   "'codingParamValues' is not an object");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": {
                "initValue": 1,
                    "codingDependency": {
                        "codingParamName": "coding_param_name",
                        "codingParamValues": 1
                    }
                }
            }
        }
    } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 1;

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(param_set_name, param_name, _)).Times(1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingNonObjectCodingDependencyFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389, 20540832, 13356518");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData fails to load coding-dependent parameter due to value of "
        "'codingDependency' is not an object. It also verifies that the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": {
                    "initValue": 1,
                    "codingDependency": 1
                }
            }
        }
    } }
    )";

    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadingParamWithNonStringCodingParamNameFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData doesn't insert parameter with incorrect type of 'codingParamName'");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": {
                    "initValue": 1,
                    "codingDependency": {
                        "codingParamName": 1,
                        "codingParamValues": {
                        "1": 11
                        }
                    }
                }
            }
        }
    } }
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(param_set_name, param_name, _)).Times(1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testInvalidReturnFromParameterSetForParameterFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "13356389, 20539638, 15804708");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies that LoadParameterData inserts the default value when receiving empty string from"
        "GetParameterSetForParameter");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
        "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": {
                    "initValue": 1,
                    "codingDependency": {
                        "codingParamName": "coding_param_name",
                        "codingParamValues": {
                        "1": 11
                        }
                    }
                }
            }
        }
        } }
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string;

    EXPECT_CALL(*param_set_mapping_mock_, GetParameterSetForParameter(score::cpp::pmr::string{"coding_param_name"}))
        .WillOnce(Return(test_string));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    ExpectParameterDataInsert(param_set_name, param_name, 1);
    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testGetParameterSetReturningNonexistentParamValueFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539638, 15804708");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies that LoadParameterData inserts the default value if it fails to load "
                   "coding-dependent parameter because GetParameterSet returns non-exising param value");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 1,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 2;

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));
    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterSetQualifier(_))
        .WillOnce(Return(ParameterSetQualifier::kQualified));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(param_set_name, ParameterSetQualifier::kQualified))
        .Times(1);
    ExpectParameterDataInsert(param_set_name, param_name, 1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testGetParameterSetReturnsObjectWithNonNumberValueFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539638, 15804708");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies that LoadParameterData inserts the default value if it fails to load coding "
                   "dependent parameter because GetParameterSet returns object with non number value");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 1,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::string coding_param_set_object;

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    ExpectParameterDataInsert(param_set_name, param_name, 1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testLoadDefaultValueAfterLoadCodingDependentParameterFromJsonFailed)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540843, 13356535, 15804708");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies LoadParameterData loads default value after loading coding dependent parameter "
                   "failed. It also verifies that the qualifier and DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 100,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::string coding_param_set_object = R"( {} )";

    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    ExpectParameterDataInsert(kSetNameA, kParameterNameA, 100);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testFailsLoadDefaultValueAfterLoadCodingDependentParameterFromJsonFailed)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540843, 13356535");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData doesn't insert a default parameter value after loading coding-dependent "
        "parameter failed due to missing init value. It also verifies that DTCs are set correctly");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "xinitValue": 100,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::string coding_param_set_object = R"( {} )";

    EXPECT_CALL(*dtc_default_values_in_use_mock_, Succeeded()).Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _)).Times(0);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testGetParameterFromSetFails)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539638, 15804708");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description",
                   "This test verifies that LoadParameterData inserts the default value if it fails to load coding "
                   "dependent parameter because GetParameterFromSet fails");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 1,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::MakeUnexpected<json::Any>(
            score::config_management::config_daemon::data_model::DataModelError::kParameterSetNotFound))));

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    const auto set_qualifier = ParameterSetQualifier::kUnqualified;
    EXPECT_CALL(*parameter_data_handler_mock_, SetParameterSetQualifier(param_set_name, set_qualifier)).Times(1);
    ExpectParameterDataInsert(param_set_name, param_name, 1);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testSetParameterUnQualified)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies LoadParameterData sets parameter set as 'Unqualified' due to incorrect "
                   "parameter name value");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": 1
            }
        }
    } }
    )";

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);

    const score::cpp::string_view param_set_name{"param_set_name_a"};
    const score::cpp::string_view param_name{"param_name_a"};
    EXPECT_CALL(*parameter_data_handler_mock_, Insert(param_set_name, param_name, _)).Times(0);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testSetParameterSetQualifierFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies LoadParameterData fails to set parameter set as 'Unqualified' due to "
                   "SetParameterSetQualifier returns kParameterSetNotCalibratable");

    std::string json_coding_data = R"({ "parameterSets": {
    "param_set_name_a": {
            "containsDefaultValue": false,
            "parameters": {
                "param_name_a": 1
            }
        }
    } }
    )";

    SetUpParameterLoader(StringToJsonResult(json_coding_data));
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .WillOnce(Return(Unexpected{MakeError(data_model::DataModelError::kParameterSetNotCalibratable)}));
    EXPECT_CALL(*parameter_data_handler_mock_, SetCalibratable(_, _)).Times(0);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testGetParameterSetQualifierFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty(
        "Description",
        "This test verifies LoadParameterData sets parameter set qualifier as 'Unqualified' when "
        "GetParameterSetQualifier returns kParameterSetNotCalibratable. It also verifies that DTCs are set correctly");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 1,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 1;

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), false))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*dtc_integrity_error_mock_, Succeeded()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Succeeded()).Times(1);

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    EXPECT_CALL(*parameter_data_handler_mock_, SetCalibratable(_, true)).WillRepeatedly(Return(true));
    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterSetQualifier(_))
        .WillOnce(Return(Unexpected{MakeError(data_model::DataModelError::kParameterSetNotCalibratable)}));
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    ExpectParameterDataInsert(kSetNameA, kParameterNameA, kParameterValue);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testInsertFailsWithCodingDependentParameter)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies LoadParameterData fails to insert coding-dependent parameter due to Insert "
                   "returns kParentParameterDataNotfound");

    std::string json_coding_data = R"(
        { "parameterSets": {
            "param_set_name_a": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_a": {
                        "initValue": 1,
                        "codingDependency": {
                            "codingParamName": "coding_param_name",
                            "codingParamValues": {
                            "1": 11
                            }
                        }
                    }
                }
            },
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_b": {
                        "initValue": 11
                    }
                }
            }
        } }
    )";

    score::cpp::string_view coding_param_name = "coding_param_name";
    std::uint16_t coding_param_set_object = 1;

    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view test_string = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillOnce(Return(test_string));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(test_string, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(coding_param_set_object))));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _))
        .WillRepeatedly(Return(Unexpected{MakeError(data_model::DataModelError::kParentParameterDataNotfound)}));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testInsertFailsWithCalibrationParameter)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ParameterLoader::LoadParameterData()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies LoadParameterData fails to insert non-coding-dependent parameter due to Insert "
                   "returns kParentParameterDataNotfound");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_b": {
                        "initValue": 11
                    }
                }
            }
        }}
    )";

    EXPECT_CALL(*dtc_integrity_error_mock_, Failed()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_data));

    EXPECT_CALL(*parameter_data_handler_mock_, Insert(_, _, _))
        .WillRepeatedly(Return(Unexpected{MakeError(data_model::DataModelError::kParentParameterDataNotfound)}));

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, testQualifierWhenCodingParameterNotQualified)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "ParameterLoader::LoadCodingDependentParameterFromJson()");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty(
        "Description",
        "This test verifies that the qualifier is unqualified when depending on a set which is not qualified.");
    RecordProperty("Priority", "2");

    std::string json_coding_data = R"(
        {
            "parameterSets": {
                "param_set_name_a": {
                    "containsDefaultValue": false,
                    "parameters": {
                        "param_name_a": {
                            "initValue": 1,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "codingParamValues": {
                                    "1": 11,
                                    "2": 22,
                                    "3": 33,
                                    "4": 44
                                }
                            }
                        },
                        "param_name_d": {
                            "initValue": 11,
                            "codingDependency": {
                                "codingParamName": "coding_param_name",
                                "codingParamValues": {
                                    "1": 111,
                                    "2": 222,
                                    "3": 333,
                                    "4": 444
                                }
                            }
                        }
                    }
                }
        } }
    )";
    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), false))
        .Times(1)
        .WillOnce(Return(false));
    EXPECT_CALL(*dtc_integrity_error_mock_, Succeeded()).Times(1);
    EXPECT_CALL(*dtc_default_values_in_use_mock_, Succeeded()).Times(1);

    SetUpParameterLoader(StringToJsonResult(json_coding_data));

    score::cpp::string_view coding_param_name = "coding_param_name";
    score::cpp::string_view coding_set_name = {"set"};

    EXPECT_CALL(*param_set_mapping_mock_,
                GetParameterSetForParameter(score::cpp::pmr::string{coding_param_name.data(), coding_param_name.size()}))
        .WillRepeatedly(Return(coding_set_name));

    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterFromSet(coding_set_name, coding_param_name))
        .WillOnce(Return(ByMove(score::json::Any(std::uint16_t{1}))))
        .WillOnce(Return(ByMove(score::json::Any(std::uint16_t{3}))));

    EXPECT_CALL(*parameter_data_handler_mock_, SetCalibratable(_, true)).WillRepeatedly(Return(true));
    EXPECT_CALL(*parameter_data_handler_mock_, GetParameterSetQualifier(_))
        .WillRepeatedly(Return(ParameterSetQualifier::kUnqualified));
    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);

    auto expected_value_param_a{11};
    auto expected_value_param_d{333};

    ExpectParameterDataInsert(kSetNameA, "param_name_a", expected_value_param_a);
    ExpectParameterDataInsert(kSetNameA, "param_name_d", expected_value_param_d);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, ReportsCalibrationPluginSwErrorAsPassedOnSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "::score::config_management::config_daemon::fault_event_reporter::IFaultEventReporter::Report()");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty(
        "Description",
        "This test verifies that Report is called with is_fault_present=false when LoadParameterData succeeds.");

    std::string json_data = R"(
        {"parameterSets": {
            "param_set_name_b": {
                "containsDefaultValue": false,
                "parameters": {
                    "param_name_b": {
                        "initValue": 42
                    }
                }
            }
        }}
    )";
    SetUpParameterLoader(StringToJsonResult(json_data));

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), false))
        .Times(1)
        .WillOnce(Return(true));

    ExpectParameterDataInsert(kSetNameB, kParameterNameB, 42);

    auto res = param_loader_->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

TEST_F(ParameterLoaderImplTest, ReportsCalibrationPluginSwErrorAsFailedOnIntegrityError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault scenarios");
    RecordProperty("Verifies", "::score::config_management::config_daemon::fault_event_reporter::IFaultEventReporter::Report()");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty(
        "Description",
        "This test verifies that Report is called with is_fault_present=true when LoadParameterData encounters "
        "an integrity error. The integrity error in this test is caused by passing nullptr as ParameterSetMapping "
        "while loading a coding-dependent parameter, which prevents resolving the coding value and marks the set "
        "as unqualified.");

    std::string json_coding_data = R"(
        { "parameterSets": {
        "param_set_name_a": {
            "containsDefaultValue": false,
             "parameters": {
                "param_name_a": {
                    "initValue": 1,
                    "codingDependency": {
                        "codingParamName": "coding_param_name",
                        "codingParamValues": {
                        "1": 11
                        }
                    }
                }
            }
        }
        } }
    )";

    auto param_loader = std::make_shared<ParameterLoaderImpl>(
        StringToJsonResult(json_coding_data), nullptr, fault_event_reporter_mock_);

    EXPECT_CALL(*fault_event_reporter_mock_,
                Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(_, score::config_management::config_daemon::ParameterSetQualifier::kUnqualified))
        .Times(1);

    auto res = param_loader->LoadParameterData(parameter_data_handler_mock_);
    EXPECT_EQ(res, true);
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
