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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_SERVICE_TOGGLER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_SERVICE_TOGGLER_H

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ServiceToggler
{
  public:
    ServiceToggler() noexcept;
    virtual ~ServiceToggler() noexcept;

    ServiceToggler(ServiceToggler&&) noexcept = delete;
    ServiceToggler(const ServiceToggler&) noexcept = delete;

    ServiceToggler& operator=(ServiceToggler&&) noexcept = delete;
    ServiceToggler& operator=(const ServiceToggler&) noexcept = delete;

    virtual void ToggleInterface(const bool calibration_enabled) noexcept = 0;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICE_TOGGLER_SERVICE_TOGGLER_H
