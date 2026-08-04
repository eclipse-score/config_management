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

#include "score/config_management/config_daemon/code/plugins/calibration/services/details/config_calibration_service_reactor_impl.h"

#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/error/update_parameter_set_error_domain.h"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer_mock.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"

#include <iostream>

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

class ConfigCalibrationServiceReactorImplTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        calibration_update_observer_mock_ = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
        parameter_data_handler_mock_ = std::make_shared<data_model::ParameterSetCollectionMock>();
        config_calibration_service_reactor_ =
            std::make_shared<ConfigCalibrationServiceReactorImpl>(parameter_data_handler_mock_,
                                                                  last_updated_parameter_set_sender_.AsStdFunction(),
                                                                  calibration_update_observer_mock_);
    }

    void TearDown() override
    {
        // delete old mocks by decrementing the reference count (which should be 1) of the shared pointers
        calibration_update_observer_mock_.reset();
        parameter_data_handler_mock_.reset();
        config_calibration_service_reactor_.reset();
    }

    void UpdateParameterSetErrorTypeTest(data_model::DataModelError data_model_error,
                                         UpdateParameterSetError update_parameter_set_error)
    {
        const std::string param_set_name = {"set"};
        const std::string coding_param_set_object = R"(
            {
            "param_name_a": 1,
            "param_name_b: 2
            }
        )";

        EXPECT_CALL(*calibration_update_observer_mock_, ReportParameterUpdate()).WillOnce(Return(true));
        EXPECT_CALL(*parameter_data_handler_mock_,
                    UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
            .WillOnce(Return(Unexpected{data_model_error}));

        auto res = config_calibration_service_reactor_->UpdateParameterSet(param_set_name, coding_param_set_object);
        EXPECT_FALSE(res.has_value());
        EXPECT_EQ(res.error(), update_parameter_set_error);
    }

    std::shared_ptr<runtime_calibration::CalibrationUpdateObserverMock> calibration_update_observer_mock_;
    std::shared_ptr<data_model::ParameterSetCollectionMock> parameter_data_handler_mock_;
    testing::MockFunction<bool(const std::string_view)> last_updated_parameter_set_sender_;
    std::shared_ptr<ConfigCalibrationServiceReactorImpl> config_calibration_service_reactor_;
};

/**
 * Test: Given a valid json calibration data file, the data is read correctly and inserted into the data model via
 * IParameterData.
 */

TEST_F(ConfigCalibrationServiceReactorImplTest, testUpdateParameterSetSucceeds)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540927, 22913269, 21353746, 20540865");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies success of UpdateParameterSet");
    RecordProperty("Priority", "2");

    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(score::cpp::string_view{param_set_name},
                                         score::config_management::config_daemon::ParameterSetQualifier::kModified))
        .Times(1);

    EXPECT_CALL(*calibration_update_observer_mock_, ReportParameterUpdate()).WillOnce(Return(true));

    EXPECT_CALL(*parameter_data_handler_mock_,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .WillOnce(Return(Result<void>{}));
    EXPECT_CALL(last_updated_parameter_set_sender_, Call(param_set_name)).WillOnce(Return(true));

    auto res = config_calibration_service_reactor_->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_EQ(res.has_value(), true);
}

TEST_F(ConfigCalibrationServiceReactorImplTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetFromParameterDataReturnsParsingError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParsingError.");
    UpdateParameterSetErrorTypeTest(data_model::DataModelError::kParsingError, UpdateParameterSetError::kParsingError);
}

TEST_F(ConfigCalibrationServiceReactorImplTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetFromParameterDataReturnsParameterSetNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParameterSetNotFound.");
    UpdateParameterSetErrorTypeTest(data_model::DataModelError::kParameterSetNotFound,
                                    UpdateParameterSetError::kParameterSetNotFound);
}

TEST_F(ConfigCalibrationServiceReactorImplTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetFromParameterDataReturnsParametersNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description",
                   "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParametersNotFound.");
    UpdateParameterSetErrorTypeTest(data_model::DataModelError::kParametersNotFound,
                                    UpdateParameterSetError::kParametersNotFound);
}

TEST_F(ConfigCalibrationServiceReactorImplTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetFromParameterDataReturnsParameterSetNotCalibratable)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty(
        "Description",
        "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParameterSetNotCalibratable.");
    UpdateParameterSetErrorTypeTest(data_model::DataModelError::kParameterSetNotCalibratable,
                                    UpdateParameterSetError::kParameterSetNotCalibratable);
}

TEST_F(ConfigCalibrationServiceReactorImplTest,
       testUpdateParameterSetFailsDueToUpdateParameterSetFromParameterDataReturnsUnknownError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty(
        "Description",
        "UpdateParameterSet fails because ParameterData::UpdateParameterSet returns kParameterSetNotCalibratable.");
    UpdateParameterSetErrorTypeTest(data_model::DataModelError::kConvertingError,
                                    UpdateParameterSetError::kUnknownError);
}

TEST_F(ConfigCalibrationServiceReactorImplTest, testUpdateParameterSetFailsDueToSendLastUpdatedParameterSetReturnsFalse)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description", "UpdateParameterSet fails because SendLastUpdatedParameterSet() returns false.");
    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    EXPECT_CALL(*calibration_update_observer_mock_, ReportParameterUpdate()).WillOnce(Return(false));
    EXPECT_CALL(*parameter_data_handler_mock_,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .WillOnce(Return(Result<void>{}));
    EXPECT_CALL(last_updated_parameter_set_sender_, Call(param_set_name)).WillOnce(Return(false));

    auto res = config_calibration_service_reactor_->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), UpdateParameterSetError::kSendLastUpdatedParameterSetFailed);
}

TEST_F(ConfigCalibrationServiceReactorImplTest, testSetCalibrationValuesChangedPrimaryDtcCalledOnce)
{
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540927, 22913269, 21353746, 20540865");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty(
        "Description",
        "This test verifies SetCalibrationValuesChangedPrimaryDtc() is called only once per UpdateParameterSet call");
    RecordProperty("Priority", "2");

    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    EXPECT_CALL(*parameter_data_handler_mock_,
                SetParameterSetQualifier(score::cpp::string_view{param_set_name},
                                         score::config_management::config_daemon::ParameterSetQualifier::kModified))
        .Times(2);

    EXPECT_CALL(*calibration_update_observer_mock_, ReportParameterUpdate()).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*parameter_data_handler_mock_,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .Times(2)
        .WillRepeatedly(Return(Result<void>{}));
    EXPECT_CALL(last_updated_parameter_set_sender_, Call(param_set_name)).Times(2).WillRepeatedly(Return(true));

    auto res = config_calibration_service_reactor_->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_TRUE(res.has_value());
    res = config_calibration_service_reactor_->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_TRUE(res.has_value());
}

TEST(SimpleConfigCalibrationServiceTest, testCalibrationUpdateObserverNotReportedOnCreation)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::"
                   "ConfigCalibrationServiceReactor()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description",
                   "This test verifies that ConfigCalibrationService construction does not report DTC state changes.");
    auto calibration_update_observer_mock = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
    EXPECT_CALL(*calibration_update_observer_mock, ReportParameterUpdate()).Times(0);
    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };

    auto config_calibration_service_reactor = std::make_shared<ConfigCalibrationServiceReactorImpl>(
        parameter_data_handler_mock, std::move(last_updated_parameter_set_sender), calibration_update_observer_mock);
}

TEST(SimpleConfigCalibrationServiceTest, testParameterDataIsNullptr)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty(
        "Description",
        "This test ensures UpdateParameterSet returns kUnknownError when IParameterSetCollection is nullptr");
    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    auto calibration_update_observer_mock = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };
    auto config_calibration_service_reactor = std::make_shared<ConfigCalibrationServiceReactorImpl>(
        nullptr, std::move(last_updated_parameter_set_sender), calibration_update_observer_mock);

    auto res = config_calibration_service_reactor->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_EQ(res.error(), UpdateParameterSetError::kUnknownError);
}

TEST(SimpleConfigCalibrationServiceTest, testInternalConfigProviderIsNullptr)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty(
        "Description",
        "This test ensures UpdateParameterSet returns kUnknownError when LastUpdateParameterSetSender is empty");
    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    auto calibration_update_observer_mock = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();
    auto config_calibration_service_reactor = std::make_shared<ConfigCalibrationServiceReactorImpl>(
        parameter_data_handler_mock, LastUpdatedParameterSetSender{}, calibration_update_observer_mock);

    auto res = config_calibration_service_reactor->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_EQ(res.error(), UpdateParameterSetError::kUnknownError);
}

TEST(SimpleConfigCalibrationServiceTest, testConfigCalibrationServiceReactorSuccessfullyCreatedWithObserverIsNullptr)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::"
                   "ConfigCalibrationServiceReactor()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test ensures ConfigCalibrationServiceReactor is created successfully when "
                   "CalibrationUpdateObserver is nullptr");
    const std::string param_set_name = {"set"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };

    auto config_calibration_service_reactor = std::make_shared<ConfigCalibrationServiceReactorImpl>(
        parameter_data_handler_mock, std::move(last_updated_parameter_set_sender), nullptr);

    EXPECT_CALL(*parameter_data_handler_mock,
                SetParameterSetQualifier(score::cpp::string_view{param_set_name},
                                         score::config_management::config_daemon::ParameterSetQualifier::kModified))
        .Times(1);
    EXPECT_CALL(*parameter_data_handler_mock,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .WillOnce(Return(Result<void>{}));

    auto res = config_calibration_service_reactor->UpdateParameterSet(param_set_name, coding_param_set_object);
    // UpdateParameterSet should work properly even when CalibrationUpdateObserver is nullptr
    EXPECT_EQ(res.has_value(), true);
}

TEST(SimpleConfigCalibrationServiceTest, testUpdateParameterSetFailsDueToSetParameterSetQualifierFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::ConfigCalibrationServiceReactor::"
                   "UpdateParameterSet()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test ensures UpdateParameterSet fails when SetParameterSetQualifier fails");
    const std::string param_set_name = {"NotFound"};
    const std::string coding_param_set_object = R"(
        {
        "param_name_a": 1,
        "param_name_b: 2
        }
    )";

    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };

    auto config_calibration_service_reactor = std::make_shared<ConfigCalibrationServiceReactorImpl>(
        parameter_data_handler_mock, std::move(last_updated_parameter_set_sender), nullptr);

    EXPECT_CALL(*parameter_data_handler_mock,
                SetParameterSetQualifier(score::cpp::string_view{param_set_name},
                                         score::config_management::config_daemon::ParameterSetQualifier::kModified))
        .WillOnce(Return(Unexpected{MakeError(data_model::DataModelError::kParameterSetNotFound)}));
    EXPECT_CALL(*parameter_data_handler_mock,
                UpdateParameterSet(score::cpp::string_view{param_set_name}, score::cpp::string_view{coding_param_set_object}))
        .Times(0);

    auto update_result =
        config_calibration_service_reactor->UpdateParameterSet(param_set_name, coding_param_set_object);
    EXPECT_FALSE(update_result.has_value());
    EXPECT_EQ(update_result.error(), MakeError(data_model::DataModelError::kParameterSetNotFound));
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
