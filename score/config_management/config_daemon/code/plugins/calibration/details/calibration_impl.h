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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_DETAILS_CALIBRATION_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_DETAILS_CALIBRATION_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/plugins/calibration/factory/factory.h"
#include "score/config_management/config_daemon/code/plugins/plugin.h"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/i_secure_debug.h"
#include "score/language/safecpp/scoped_function/scope.h"
#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include "score/mw/service/proxy_data.h"

#include <optional>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class CalibrationImpl final : public IPlugin
{
  public:
    class ServiceTogglerHandler
    {
      public:
        explicit ServiceTogglerHandler(const std::shared_ptr<ServiceToggler> calibration_service_toggler);
        void operator()(score::Result<std::unique_ptr<ISecureDebug>>& secure_debug);

      private:
        std::shared_ptr<ServiceToggler> calibration_service_toggler_;
    };

    class CalibrationEnabledHandler
    {
      public:
        explicit CalibrationEnabledHandler(const std::shared_ptr<ServiceToggler> calibration_service_toggler);
        void operator()(const bool enabled);

      private:
        std::shared_ptr<ServiceToggler> calibration_service_toggler_;
    };

    explicit CalibrationImpl(std::unique_ptr<calibration::Factory> factory) noexcept;

    CalibrationImpl(CalibrationImpl&&) = delete;
    CalibrationImpl(const CalibrationImpl&) = delete;

    CalibrationImpl& operator=(CalibrationImpl&&) = delete;
    CalibrationImpl& operator=(const CalibrationImpl&) = delete;

    Result<void> Initialize() override;
    void Deinitialize() noexcept override;

    ~CalibrationImpl() noexcept override = default;

    std::int32_t Run(std::shared_ptr<data_model::IParameterSetCollectionManager> parameterset_collection_manager,
                     LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set,
                     InitialQualifierStateSender cbk_update_initial_qualifier_state,
                     score::cpp::stop_token stop_token,
                     std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter) override;

    Result<void> ParameterSetCollectionUpdateStart(
        data_model::IParameterSetCollection& parameter_set_collection) override;

  private:
    std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameterset_collection_;
    LastUpdatedParameterSetSender last_updated_parameter_set_sender_;
    mw::service::OptionalProxyData<ISecureDebug> secure_debug_proxy_data_;
    std::shared_ptr<CalibrationUpdateObserver> calibration_update_observer_;
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter_;
    std::unique_ptr<score::config_management::config_daemon::calibration::Factory> factory_;
    std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping_;
    mw::log::Logger& logger_;
    CalibrationProxies calibration_proxies_;
    // Scope needs to be last attribute in the class.
    score::safecpp::Scope<> scope_;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_DETAILS_CALIBRATION_IMPL_H
