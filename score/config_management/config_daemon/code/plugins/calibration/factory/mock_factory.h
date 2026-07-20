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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_MOCK_FACTORY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_MOCK_FACTORY_H

#include "score/config_management/config_daemon/code/plugins/calibration/factory/factory.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class MockFactory final : public Factory
{
  public:
    /* KW_SUPPRESS_START:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE: false positive */
    /* KW_SUPPRESS_START:MISRA.MEMB.NOT_PRIVATE: it's a mocked function not a field */
    /* KW_SUPPRESS_START:MISRA.USE.EXPANSION: used to create mocked function */
    MOCK_METHOD(
        std::unique_ptr<score::mw::service::ProvidedServicesBase>,
        CreateCalibrationService,
        (const std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameter_data,
         LastUpdatedParameterSetSender last_updated_parameter_set_sender,
         const std::shared_ptr<CalibrationUpdateObserver> calibration_update_observer),
        (const, override));
    MOCK_METHOD(std::shared_ptr<ServiceToggler>,
                CreateServiceToggler,
                (std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service),
                (const, override));
    MOCK_METHOD(std::shared_ptr<CalibrationUpdateObserver>, CreateCalibrationUpdateObserver, (), (const, override));
    MOCK_METHOD(CalibrationProxies, CreateCalibrationProxies, (), (const, override));
    MOCK_METHOD(std::shared_ptr<ParameterLoader>,
                CreateParameterLoader,
                (std::unique_ptr<score::Result<json::Any>> calibration_data,
                 const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
                 std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter,
                 std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error,
                 std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use),
                (const, override));
    MOCK_METHOD(mw::service::OptionalProxyData<ISecureDebug>,
                CreateSecureDebugFuture,
                (CalibrationProxies::Container & proxy_container),
                (override));
    MOCK_METHOD(std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping>,
                CreateParamSetMapping,
                (),
                (const, override));
    MOCK_METHOD(std::unique_ptr<score::mw::diag::DTC>, CreateClearableDtcIntegrityError, (), (const, override));
    MOCK_METHOD(std::unique_ptr<score::mw::diag::DTC>, CreateClearableDtcDefaultValuesInUse, (), (const, override));
    /* KW_SUPPRESS_END:MISRA.USE.EXPANSION: used to create mocked function */
    /* KW_SUPPRESS_END:MISRA.MEMB.NOT_PRIVATE: it's a mocked function not a field */
    /* KW_SUPPRESS_END:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE: false positive */
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_MOCK_FACTORY_H
