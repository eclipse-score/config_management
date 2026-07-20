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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_DETAILS_SERVICE_TOGGLER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_DETAILS_SERVICE_TOGGLER_IMPL_H

#include <memory>

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/service_toggler.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include "score/mw/service/provided_service_container.h"

/* KW_SUPPRESS_START:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE: false positive */
namespace score
/* KW_SUPPRESS_END:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE */
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ServiceTogglerImpl final : public ServiceToggler
{
  public:
    explicit ServiceTogglerImpl(std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) noexcept;
    ~ServiceTogglerImpl() noexcept override = default;

    ServiceTogglerImpl(ServiceTogglerImpl&&) noexcept = delete;
    ServiceTogglerImpl(const ServiceTogglerImpl&) noexcept = delete;

    ServiceTogglerImpl& operator=(ServiceTogglerImpl&&) noexcept = delete;
    ServiceTogglerImpl& operator=(const ServiceTogglerImpl&) noexcept = delete;

    void ToggleInterface(const bool calibration_enabled) noexcept override;

  private:
    bool calibration_enabled_previous_;
    std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service_;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_DETAILS_SERVICE_TOGGLER_IMPL_H
