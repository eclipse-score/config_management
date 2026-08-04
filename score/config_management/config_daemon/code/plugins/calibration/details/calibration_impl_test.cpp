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

#include "score/result/result.h"

#include "score/config_management/config_daemon/code/plugins/calibration/details/calibration_impl.h"
#include "score/mw/service/backend/ara/adaptive_immediate_instantiation_strategy.h"
#include "score/mw/service/backend/ara/immediate_instantiation_strategy.h"

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_manager_mock.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter_mock.h"
#include "score/config_management/config_daemon/code/plugins/calibration/error/error.h"
#include "score/config_management/config_daemon/code/plugins/calibration/factory/details/factory_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/factory/factory.h"
#include "score/config_management/config_daemon/code/plugins/calibration/factory/mock_factory.h"
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/service_toggler_mock.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping_mock.h"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer_mock.h"
#include "score/config_management/config_daemon/code/proxies/error/error.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/secure_debug.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/secure_debug_mock.h"
#include "score/mw/log/logger.h"
#include "score/mw/log/logging.h"
#include "score/mw/log/recorder_mock.h"
#include "score/mw/service/proxy_needs_factory.h"

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

using testing::ByMove;
using testing::Return;
using namespace score::config_management::config_daemon::fault_event_reporter;

template <typename T>
class MockFactoryProxy
{
  public:
    std::unique_ptr<T> operator()()
    {
        return std::make_unique<T>();
    }
};
class CalibrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        mw::log::SetLogRecorder(&recorder_mock_);
        factory_mock_ = std::make_unique<MockFactory>();
        calibration_service_toggler_mock_ = std::make_shared<ServiceTogglerMock>();
        calibration_service_toggler_handler_ =
            std::make_unique<CalibrationImpl::ServiceTogglerHandler>(calibration_service_toggler_mock_);
        calibration_enabled_handler_ =
            std::make_unique<CalibrationImpl::CalibrationEnabledHandler>(calibration_service_toggler_mock_);
        parameter_set_collection_mock_ = std::make_shared<data_model::ParameterSetCollectionManagerMock>();
        calibration_update_observer_mock_ = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
        param_set_mapping_mock_ = std::make_shared<score::config_management::config_daemon::coding::ParamSetMappingMock>();
        fault_event_reporter_mock_ = std::make_shared<FaultEventReporterMock>();

        using SecureDebugProxyStrategy =
            mw::service::ImmediateInstantiationStrategy<ISecureDebug,
                                                        MockFactoryProxy<config_daemon::test::SecureDebugMock>>;
        ON_CALL(*factory_mock_, CreateCalibrationProxies())
            .WillByDefault(Return(
                ByMove(score::mw::service::ProxyNeedsFactory<CalibrationProxies>::Create<SecureDebugProxyStrategy>())));
        ON_CALL(*param_set_mapping_mock_, LoadParameterSetConfig()).WillByDefault(Return(Result<void>{}));
        ON_CALL(*factory_mock_, CreateParamSetMapping()).WillByDefault(Return(param_set_mapping_mock_));
        ON_CALL(*factory_mock_, CreateCalibrationUpdateObserver())
            .WillByDefault(Return(calibration_update_observer_mock_));
        ON_CALL(*factory_mock_, CreateServiceToggler).WillByDefault(Return(calibration_service_toggler_mock_));
    }

    void TearDown() override {}

    std::int32_t DefaultRunCall()
    {
        LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set = [](const std::string_view) noexcept {
            return false;
        };
        InitialQualifierStateSender cbk_update_initial_qualifier_state =
            [](const config_daemon::InitialQualifierState) noexcept {};
        score::cpp::stop_source source;
        source.request_stop();

        return calibration_plugin_->Run(parameter_set_collection_mock_,
                                        std::move(cbk_send_last_updated_parameter_set),
                                        std::move(cbk_update_initial_qualifier_state),
                                        source.get_token(),
                                        fault_event_reporter_mock_);
    }

    std::unique_ptr<CalibrationImpl> calibration_plugin_;
    std::unique_ptr<MockFactory> factory_mock_;
    std::shared_ptr<ServiceTogglerMock> calibration_service_toggler_mock_;
    std::unique_ptr<CalibrationImpl::ServiceTogglerHandler> calibration_service_toggler_handler_;
    std::unique_ptr<CalibrationImpl::CalibrationEnabledHandler> calibration_enabled_handler_;
    mw::log::RecorderMock recorder_mock_{};
    std::shared_ptr<data_model::ParameterSetCollectionManagerMock> parameter_set_collection_mock_;
    std::shared_ptr<runtime_calibration::CalibrationUpdateObserverMock> calibration_update_observer_mock_;
    std::shared_ptr<score::config_management::config_daemon::coding::ParamSetMappingMock> param_set_mapping_mock_;
    std::shared_ptr<FaultEventReporterMock> fault_event_reporter_mock_;
};

TEST_F(CalibrationTest, LoadParameterSetConfigFail)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::Calibration::Initialize()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty(
        "Description",
        "This test verifies Calibration plugin Initialize returns false error since LoadParameterSetConfig failed");

    EXPECT_CALL(*param_set_mapping_mock_, LoadParameterSetConfig())
        .WillOnce(Return(Result<void>{score::MakeUnexpected(score::json::Error::kParsingError, "")}));

    calibration_plugin_ = std::make_unique<CalibrationImpl>(std::move(factory_mock_));
    auto initialize_result = calibration_plugin_->Initialize();
    EXPECT_FALSE(initialize_result.has_value());
}

TEST_F(CalibrationTest, LoadParameterDataAndInitServiceSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20539581");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies that the Calibration plugin is initialized correctly");

    calibration_plugin_ = std::make_unique<CalibrationImpl>(std::move(factory_mock_));
    auto intialize_result = calibration_plugin_->Initialize();
    EXPECT_TRUE(intialize_result.has_value());

    auto run_result = DefaultRunCall();
    calibration_plugin_->Deinitialize();
    EXPECT_EQ(run_result, EXIT_SUCCESS);
}

TEST_F(CalibrationTest, InitializeCalibrationAndSetServiceTogglerHandlerSuccessfully)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::Calibration::Initialize()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description",
                   "This test verifies that the ServiceTogglerHandler successfully passed to SecureDebug");

    std::unique_ptr<config_daemon::test::SecureDebugMock> secure_debug =
        std::make_unique<config_daemon::test::SecureDebugMock>();
    // We are expecting SecureDebug to be available by checking if GetCalibrationEnabled is called by
    // ServiceTogglerHandler
    EXPECT_CALL(*secure_debug, GetCalibrationEnabled()).Times(1);
    score::concurrency::InterruptiblePromise<std::unique_ptr<ISecureDebug>> promise{};
    promise.SetValue(std::move(secure_debug));
    auto future = promise.GetInterruptibleFuture();
    ASSERT_TRUE(future.has_value());

    mw::service::OptionalProxyData<ISecureDebug> proxy_data{std::move(future.value())};
    ON_CALL(*factory_mock_, CreateSecureDebugFuture).WillByDefault(Return(ByMove(std::move(proxy_data))));
    calibration_plugin_ = std::make_unique<CalibrationImpl>(std::move(factory_mock_));

    auto intialize_result = calibration_plugin_->Initialize();
    EXPECT_TRUE(intialize_result.has_value());

    auto res = DefaultRunCall();
    calibration_plugin_->Deinitialize();
    EXPECT_EQ(res, EXIT_SUCCESS);
}

TEST_F(CalibrationTest, CalibrationCanNotInitializeDueToNullPtrFactory)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::Calibration::Initialize()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies Calibration plugin returns kNullPtrFactoryError error due to nullptr factory");

    calibration_plugin_ = std::make_unique<CalibrationImpl>(nullptr);

    auto res = calibration_plugin_->Initialize();
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), CalibrationError::kNullPtrFactoryError);
}

TEST_F(CalibrationTest, CalibrationRunFailureDueToNullPtrFactory)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::Calibration::Initialize()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test verifies Run method return EXIT_FAILURE due to nullptr factory");

    calibration_plugin_ = std::make_unique<CalibrationImpl>(nullptr);

    auto run_result = DefaultRunCall();
    calibration_plugin_->Deinitialize();
    EXPECT_EQ(run_result, EXIT_FAILURE);
}

TEST_F(CalibrationTest, CalibrationFailedToCreateDtcManager)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::Calibration::Run()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies Calibration plugin Run method returns EXIT_FAILURE due to nullptr dtcManager");

    EXPECT_CALL(*factory_mock_, CreateCalibrationUpdateObserver()).WillOnce(Return(nullptr));
    calibration_plugin_ = std::make_unique<CalibrationImpl>(std::move(factory_mock_));
    auto intialize_result = calibration_plugin_->Initialize();
    EXPECT_TRUE(intialize_result.has_value());

    auto res = DefaultRunCall();
    calibration_plugin_->Deinitialize();
    EXPECT_EQ(res, EXIT_FAILURE);
}

TEST_F(CalibrationTest, ServiceTogglerHandlerShallToggleInterface)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540927, 20540962");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies ServiceTogglerHandler toggles calibration interface");

    std::unique_ptr<config_daemon::test::SecureDebugMock> secure_debug_mock{
        std::make_unique<config_daemon::test::SecureDebugMock>()};
    EXPECT_CALL(*secure_debug_mock, SetCalibrationEnabledCallback(testing::An<score::cpp::callback<void(bool)>>())).Times(1);

    const score::Result<bool> calibration_enabled{true};
    EXPECT_CALL(*secure_debug_mock, GetCalibrationEnabled()).WillOnce(Return(calibration_enabled));
    EXPECT_CALL(*calibration_service_toggler_mock_, ToggleInterface(calibration_enabled.value())).Times(1);

    score::Result<std::unique_ptr<ISecureDebug>> secure_debug(std::move(secure_debug_mock));
    (*calibration_service_toggler_handler_)(secure_debug);
}

TEST_F(CalibrationTest, ServiceTogglerHandlerShallNotToggleInterfaceInCalibrationEnabledError)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::Calibration::ServiceTogglerHandler::operator()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test verifies ServiceTogglerHandler doesn't toggle calibration interface if "
                   "GetCalibrationEnabled returns kMiddlewareError");

    std::unique_ptr<config_daemon::test::SecureDebugMock> secure_debug_mock{
        std::make_unique<config_daemon::test::SecureDebugMock>()};
    EXPECT_CALL(*secure_debug_mock, SetCalibrationEnabledCallback(testing::An<score::cpp::callback<void(bool)>>())).Times(1);

    const score::Result<bool> calibration_enabled =
        MakeUnexpected(score::config_management::config_daemon::ProxyError::kMiddlewareError);
    EXPECT_CALL(*secure_debug_mock, GetCalibrationEnabled()).WillOnce(Return(calibration_enabled));
    EXPECT_CALL(*calibration_service_toggler_mock_, ToggleInterface).Times(0);

    score::Result<std::unique_ptr<ISecureDebug>> secure_debug(std::move(secure_debug_mock));
    (*calibration_service_toggler_handler_)(secure_debug);
}

TEST_F(CalibrationTest, CalibrationEnabledHandlerShallPassTrueToToggleInterface)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::Calibration::CalibrationEnabledHandler::operator()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description", "This test verifies CalibrationEnabledHandler passes 'true' to ServiceToggler");

    EXPECT_CALL(*calibration_service_toggler_mock_, ToggleInterface(true)).Times(1);
    (*calibration_enabled_handler_)(true);
}

TEST_F(CalibrationTest, CalibrationEnabledHandlerShallPassFalseToToggleInterface)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "score::config_management::config_daemon::calibration::Calibration::CalibrationEnabledHandler::operator()");
    RecordProperty("DerivationTechnique", "Analyzing architecture and design");
    RecordProperty("Description", "This test verifies CalibrationEnabledHandler passes 'false' to ServiceToggler");

    EXPECT_CALL(*calibration_service_toggler_mock_, ToggleInterface(false)).Times(1);
    (*calibration_enabled_handler_)(false);
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
