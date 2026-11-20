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
#include "score/config_management/config_daemon/code/initial_qualifier_container/details/initial_qualifier_container_impl.h"

#include "score/mw/log/logging.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
InitialQualifierContainerImpl::InitialQualifierContainerImpl()
    : InitialQualifierContainer{},
      logger_{score::mw::log::CreateLogger(std::string_view{"App"})},
      state_mutex_{},
      state_{InitialQualifierState::kUndefined}
{
}

void InitialQualifierContainerImpl::SetInitialQualifierState(const InitialQualifierState state) noexcept
{
    const std::lock_guard<std::mutex> lock{state_mutex_};
    state_ = state;
    logger_.LogDebug() << "InitialQualifierContainer::" << __func__ << "state=" << score::cpp::to_underlying(state);
}

InitialQualifierState InitialQualifierContainerImpl::GetInitialQualifierState() const noexcept
{
    const std::lock_guard<std::mutex> lock{state_mutex_};
    logger_.LogDebug() << "InitialQualifierContainer::" << __func__ << "state=" << score::cpp::to_underlying(state_);
    return state_;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
