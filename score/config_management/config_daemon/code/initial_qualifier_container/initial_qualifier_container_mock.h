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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_MOCK_H

#include "score/config_management/config_daemon/code/initial_qualifier_container/initial_qualifier_container.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
class InitialQualifierContainerMock : public InitialQualifierContainer
{
  public:
    MOCK_METHOD(void,
                SetInitialQualifierState,
                (const ::score::config_management::config_daemon::InitialQualifierState),
                (noexcept, override));
    MOCK_METHOD(::score::config_management::config_daemon::InitialQualifierState,
                GetInitialQualifierState,
                (),
                (const, noexcept, override));

    ~InitialQualifierContainerMock() override = default;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_INITIAL_QUALIFIER_CONTAINER_MOCK_H
