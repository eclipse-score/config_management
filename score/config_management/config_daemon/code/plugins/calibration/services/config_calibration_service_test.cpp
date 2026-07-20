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

#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service.h"

#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service_reactor_mock.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/error/update_parameter_set_error_domain.h"

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

using testing::Return;

namespace
{
ConfigCalibrationSkeleton::ConstructionToken GetPreconstructionToken()
{
    ::mw::core::InstanceSpecifier instance_specifier{"/some/instance/specifier"};
    return ConfigCalibrationSkeleton::Preconstruct(instance_specifier).Value();
}
}  // namespace

class ConfigCalibrationServiceTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        config_calibration_service_reactor_mock_ = std::make_shared<ConfigCalibrationServiceReactorMock>();

        config_calibration_service_ = std::make_shared<ConfigCalibrationService>(
            GetPreconstructionToken(), config_calibration_service_reactor_mock_);
    }

    void TearDown() override
    {
        // delete old mocks by decrementing the reference count (which should be 1) of the shared pointers
        config_calibration_service_reactor_mock_.reset();
        config_calibration_service_.reset();
    }

    void UpdateParameterSetErrorTypeTest(UpdateParameterSetError update_parameter_set_error,
                                         UpdateParameterSetResult update_parameter_set_result)
    {
        const ::ara::diag::string param_set_name = {"set"};
        const ::ara::diag::string coding_param_set_object = R"(
            {
            "param_name_a": 1,
            "param_name_b: 2
            }
        )";

        EXPECT_CALL(*config_calibration_service_reactor_mock_,
                    UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
            .WillOnce(Return(Unexpected{update_parameter_set_error}));

        auto res = config_calibration_service_->UpdateParameterSet(param_set_name, coding_param_set_object);
        EXPECT_EQ(res.GetResult().Value().result, update_parameter_set_result);
    }

    std::shared_ptr<ConfigCalibrationServiceReactorMock> config_calibration_service_reactor_mock_;
    std::shared_ptr<ConfigCalibrationService> config_calibration_service_;
};

/**
 * Test: Given a valid json calibration data file, the data is read correctly and inserted into the data model via
 * IParameterData.
 */

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetSucceeds)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test verifies success of UpdateParameterSet");

    const ::ara::diag::string param_set_name = {"set"};
    const ::ara::diag::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    EXPECT_CALL(*config_calibration_service_reactor_mock_,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .WillOnce(Return(Result<void>{}));

    auto res = config_calibration_service_->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_EQ(res.GetResult().Value().result, UpdateParameterSetResult::kOk);
}

TEST_F(ConfigCalibrationServiceTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetReturnskParameterSetNotCalibratable)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty(
        "Description",
        "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParameterSetNotCalibratable.");
    UpdateParameterSetErrorTypeTest(UpdateParameterSetError::kParameterSetNotCalibratable,
                                    UpdateParameterSetResult::kParameterSetNotCalibratable);
}

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetFailsDueToUpdateParameterSetReturnskParsingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParsingError.");
    UpdateParameterSetErrorTypeTest(UpdateParameterSetError::kParsingError, UpdateParameterSetResult::kParsingError);
}

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetFailsDueToUpdateParameterSetReturnskParameterSetNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParameterSetNotFound.");
    UpdateParameterSetErrorTypeTest(UpdateParameterSetError::kParameterSetNotFound,
                                    UpdateParameterSetResult::kParameterSetNotFound);
}

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetFailsDueToUpdateParameterSetReturnskParametersNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParametersNotFound.");
    UpdateParameterSetErrorTypeTest(UpdateParameterSetError::kParametersNotFound,
                                    UpdateParameterSetResult::kParametersNotFound);
}

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetFailsDueToUpdateParameterSetReturnsUnknownError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns unknown error.");
    UpdateParameterSetErrorTypeTest(static_cast<UpdateParameterSetError>(0xff),
                                    UpdateParameterSetResult::kUnknownError);
}

TEST_F(ConfigCalibrationServiceTest, testUpdateParameterSetFailsDuetoSendLastUpdatedParameterSetFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationService::UpdateParameterSetResult()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "UpdateParameterSet fails because SendLastUpdatedParameterSet return false.");

    const ::ara::diag::string param_set_name = {"set"};
    const ::ara::diag::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    UpdateParameterSetErrorTypeTest(UpdateParameterSetError::kSendLastUpdatedParameterSetFailed,
                                    UpdateParameterSetResult::kSendLastUpdatedParameterSetFailed);
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
