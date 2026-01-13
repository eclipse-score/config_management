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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_H

#include "score/config_management/config_provider/code/config_provider/initial_qualifier_state_types.h"

#include "score/json/internal/model/any.h"

#include <score/callback.hpp>
#include <score/optional.hpp>
#include <score/stop_token.hpp>
#include <score/string_view.hpp>

#include <chrono>

namespace score
{
namespace config_management
{
namespace config_provider
{
using IsAvailableNotificationCallback = score::cpp::callback<void()>;

class IInternalConfigProvider
{
  public:
    using OnChangedParameterSetCallback = score::cpp::callback<void(const score::cpp::string_view set_name)>;
    IInternalConfigProvider() = default;
    virtual ~IInternalConfigProvider() noexcept = default;

    IInternalConfigProvider(const IInternalConfigProvider&) = delete;
    IInternalConfigProvider(IInternalConfigProvider&&) = delete;

    IInternalConfigProvider& operator=(const IInternalConfigProvider&) & = delete;
    IInternalConfigProvider& operator=(IInternalConfigProvider&&) = delete;

    virtual Result<json::Any> GetParameterSet(const score::cpp::string_view set_name,
                                              const std::chrono::milliseconds timeout) const = 0;
    virtual bool TrySubscribeToLastUpdatedParameterSetEvent(const score::cpp::stop_token& stop_token,
                                                            OnChangedParameterSetCallback&& callback) = 0;

    virtual InitialQualifierState GetInitialQualifierState(const std::chrono::milliseconds timeout) const = 0;

    virtual void StartParameterSetUpdatePollingRoutine(
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval) = 0;
    virtual void StopParameterSetUpdatePollingRoutine() noexcept = 0;

    virtual void CheckParameterSetUpdates() noexcept = 0;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_H
