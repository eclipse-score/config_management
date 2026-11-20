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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_H

#include "score/config_management/config_provider/code/config_provider/config_provider.h"
#include "score/config_management/config_provider/code/persistency/persistency.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"

#include "score/mw/service/find_service_strategy.h"

#include <score/callback.hpp>
#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/stop_token.hpp>
#include <score/vector.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>

namespace score
{
namespace config_management
{
namespace config_provider
{

/// @brief Fluent settings of the `ConfigProvider` that `Build()` creates. Clients depend on this interface, so
/// that unit tests can substitute `ConfigProviderBuilderMock`. The production implementation is
/// `ConfigProviderBuilderImpl<InternalConfigProviderPort>` (config_provider_builder_impl.h).
class ConfigProviderBuilder
{
  public:
    /// @brief Interface of the strategy used to discover the `IInternalConfigProvider` service.
    using Strategy = mw::service::FindServiceStrategy<IInternalConfigProvider>;

    /// @brief Factory callback building the `Strategy` instance once the additional shared-memory size required
    /// for `get_parameter_set` has been determined.
    using StrategyFactory = score::cpp::callback<std::unique_ptr<Strategy>(std::size_t additional_shm_size_bytes)>;

    ConfigProviderBuilder() = default;

    ConfigProviderBuilder(ConfigProviderBuilder&&) = delete;
    ConfigProviderBuilder(const ConfigProviderBuilder&) = delete;

    ConfigProviderBuilder& operator=(ConfigProviderBuilder&&) & = delete;
    ConfigProviderBuilder& operator=(const ConfigProviderBuilder&) & = delete;

    virtual ~ConfigProviderBuilder() noexcept = default;

    /// @brief How long `Build()` waits for the connection to the service.
    virtual ConfigProviderBuilder& WithConnectionTimeout(std::chrono::milliseconds timeout) = 0;

    /// @brief Sizes the shared-memory buffer for the given parameter sets only.
    virtual ConfigProviderBuilder& WithRequiredParameterSets(
        score::cpp::pmr::vector<std::string_view> initial_parameter_set_name_list) = 0;

    virtual ConfigProviderBuilder& WithMaxSamplesLimit(std::size_t max_samples_limit) = 0;

    virtual ConfigProviderBuilder& WithPollingCycleInterval(std::chrono::milliseconds polling_cycle_interval) = 0;

    virtual ConfigProviderBuilder& WithPersistency(score::cpp::pmr::unique_ptr<Persistency> persistency) = 0;

    virtual ConfigProviderBuilder& WithMemoryResource(score::cpp::pmr::memory_resource* const memory_resource) = 0;

    virtual ConfigProviderBuilder& WithAvailabilityNotificationCallback(AvailabilityNotificationCallback callback) = 0;

    /// @brief Builds the ConfigProvider from the configured settings. Implementations may be single use.
    virtual score::cpp::pmr::unique_ptr<ConfigProvider> Build(score::cpp::stop_token token) = 0;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_H
