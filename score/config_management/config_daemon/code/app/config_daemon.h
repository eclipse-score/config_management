// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_APP_CONFIG_DAEMON_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_APP_CONFIG_DAEMON_H

#include "platform/aas/mw/lifecycle/application.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

class IConfigDaemon : public score::mw::lifecycle::Application
{
  public:
    IConfigDaemon() noexcept = default;
    IConfigDaemon(IConfigDaemon&&) = delete;
    IConfigDaemon(const IConfigDaemon&) = delete;
    IConfigDaemon& operator=(IConfigDaemon&&) = delete;
    IConfigDaemon& operator=(const IConfigDaemon&) = delete;
    virtual ~IConfigDaemon() noexcept = default;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_APP_CONFIG_DAEMON_H
