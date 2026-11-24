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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_DETAILS_INITIAL_QUALIFIER_CONTAINER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_DETAILS_INITIAL_QUALIFIER_CONTAINER_IMPL_H

#include "score/config_management/config_daemon/code/initial_qualifier_container/initial_qualifier_container.h"

#include "score/mw/log/logger.h"

#include <mutex>

namespace score
{
namespace config_management
{
namespace config_daemon
{
class InitialQualifierContainerImpl final : public InitialQualifierContainer
{
  public:
    InitialQualifierContainerImpl();
    ~InitialQualifierContainerImpl() override = default;
    InitialQualifierContainerImpl(const InitialQualifierContainerImpl&) = delete;
    InitialQualifierContainerImpl(InitialQualifierContainerImpl&&) = delete;
    InitialQualifierContainerImpl& operator=(const InitialQualifierContainerImpl&) = delete;
    InitialQualifierContainerImpl& operator=(InitialQualifierContainerImpl&&) = delete;

    void SetInitialQualifierState(
        const ::score::config_management::config_daemon::InitialQualifierState state) noexcept override;
    ::score::config_management::config_daemon::InitialQualifierState GetInitialQualifierState() const noexcept override;

  private:
    score::mw::log::Logger& logger_;
    mutable std::mutex state_mutex_;
    ::score::config_management::config_daemon::InitialQualifierState state_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_INITIAL_QUALIFIER_CONTAINER_DETAILS_INITIAL_QUALIFIER_CONTAINER_IMPL_H
