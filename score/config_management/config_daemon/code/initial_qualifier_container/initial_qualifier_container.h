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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_H

#include "score/config_management/config_daemon/code/types/initial_qualifier_state/initial_qualifier_state.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
class InitialQualifierContainer
{
  public:
    virtual void SetInitialQualifierState(
        const ::score::config_management::config_daemon::InitialQualifierState state) noexcept = 0;
    virtual ::score::config_management::config_daemon::InitialQualifierState GetInitialQualifierState()
        const noexcept = 0;

    virtual ~InitialQualifierContainer() = default;
    InitialQualifierContainer() = default;
    InitialQualifierContainer(InitialQualifierContainer&&) = delete;
    InitialQualifierContainer(const InitialQualifierContainer&) = delete;
    InitialQualifierContainer& operator=(InitialQualifierContainer&&) = delete;
    InitialQualifierContainer& operator=(const InitialQualifierContainer&) = delete;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_H
