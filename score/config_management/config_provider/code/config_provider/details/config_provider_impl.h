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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_DETAILS_CONFIG_PROVIDER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_DETAILS_CONFIG_PROVIDER_IMPL_H

#include "score/config_management/config_provider/code/config_provider/config_provider.h"
#include "score/config_management/config_provider/code/config_provider/initial_qualifier_state_types.h"
#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"
#include "score/config_management/config_provider/code/persistency/persistency.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"

#include "score/memory/string_comparison_adaptor.h"
#include "score/mw/log/logger.h"

#include "score/concurrency/condition_variable.h"
#include "platform/aas/mw/service/proxy_future.h"

#include <score/jthread.hpp>
#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/unordered_map.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{

using ParameterMap = score::cpp::pmr::unordered_map<score::cpp::pmr::string, std::shared_ptr<const ParameterSet>>;
using ClientHandlersMap = score::cpp::pmr::unordered_map<score::cpp::pmr::string, OnChangedParameterSetCallback>;

class ConfigProviderImpl final : public ConfigProvider
{
  public:
    constexpr static std::chrono::milliseconds kDefaultResponseTimeout{1000};

    ~ConfigProviderImpl() override;
    ConfigProviderImpl(ConfigProviderImpl&&) noexcept = delete;
    ConfigProviderImpl(const ConfigProviderImpl&) noexcept = delete;

    ConfigProviderImpl& operator=(ConfigProviderImpl&&) & noexcept = delete;
    ConfigProviderImpl& operator=(const ConfigProviderImpl&) & noexcept = delete;

    /**
     * Gets the parameter set by the set's name
     */
    using ConfigProvider::GetParameterSet;
    Result<std::shared_ptr<const ParameterSet>> GetParameterSet(const score::cpp::string_view set_name) override;

    Result<std::shared_ptr<const ParameterSet>> GetParameterSet(
        const score::cpp::string_view set_name,
        const std::optional<std::chrono::milliseconds> timeout) override;

    ParameterSetMap GetParameterSetsByNameList(const score::cpp::pmr::vector<score::cpp::string_view>& set_names,
                                               const std::optional<std::chrono::milliseconds> timeout) override;
    /**
     * Set callback for InitialQualifierState change notification
     */
    ResultBlank OnChangedInitialQualifierState(InitialQualifierStateNotifierCallbackType&& callback) noexcept override;

    ResultBlank OnChangedParameterSet(const std::string& set_name,
                                      OnChangedParameterSetCallback&& callback) noexcept override;

    ResultBlank OnChangedParameterSetCbk(std::string_view set_name,
                                         OnChangedParameterSetCallback&& callback) noexcept override;

    using ConfigProvider::GetInitialQualifierState;
    InitialQualifierState GetInitialQualifierState() noexcept override;
    InitialQualifierState GetInitialQualifierState(const std::optional<std::chrono::milliseconds> timeout) noexcept override;

    using ConfigProvider::GetInitialQualifierState;
    InitialQualifierState GetInitialQualifierState(
        const std::optional<std::chrono::milliseconds> timeout) noexcept override;

    /// @brief Checks if any ParameterSet updates is available and stimulate polling routine.
    ResultBlank CheckParameterSetUpdates() noexcept override;

    bool WaitUntilConnected(const std::chrono::milliseconds timeout,
                            const score::cpp::stop_token& stop_token) noexcept override;

    std::size_t GetCachedParameterSetsCount() const noexcept override;

    bool IsAwaitingProxyConnection() const noexcept;

    ConfigProviderImpl(
        mw::service::ProxyFuture<std::unique_ptr<IInternalConfigProvider>> internal_config_provider_future,
        score::cpp::stop_token user_stop_token,
        score::cpp::pmr::memory_resource* const memory_resource,
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
        IsAvailableNotificationCallback callback,
        score::cpp::pmr::unique_ptr<Persistency> persistency);

  private:
    void SetupInternalConfigProvider(std::shared_ptr<IInternalConfigProvider> internal_config_provider,
                                     IsAvailableNotificationCallback is_available_notification_callback,
                                     const score::cpp::stop_token& stop_token);
    void CacheInitialQualifierState(const InitialQualifierState initial_qualifier_state) noexcept;
    void LastUpdatedParameterSetReceiveHandler(const score::cpp::string_view set_name);
    Result<std::shared_ptr<const ParameterSet>> GetParameterSetFromInternalConfigProvider(
        const score::cpp::string_view set_name,
        const IInternalConfigProvider& internal_config_provider,
        const std::chrono::milliseconds timeout);
    ParameterMap FetchInitialParameterSetValuesFrom(const IInternalConfigProvider& internal_config_provider);
    ResultBlank RegisterUpdateHandlerForParameterSetName(const score::cpp::string_view set_name,
                                                         OnChangedParameterSetCallback&& callback);
    void RegisterCallbacksForPersistedParameterSetNames();
    void WriteInitialParameterSetValuesToPersistentCache(ParameterMap updated_parameter_sets);

    mw::log::Logger& logger_;
    ParameterMap parameter_sets_;
    InitialQualifierState initial_qualifier_state_;
    score::cpp::pmr::memory_resource* const memory_resource_;
    std::shared_ptr<IInternalConfigProvider> internal_config_provider_;
    mutable std::mutex mutex_;
    concurrency::InterruptibleConditionalVariable internal_config_provider_cv_;
    score::cpp::pmr::unique_ptr<Persistency> persistency_;
    ClientHandlersMap client_handlers_;
    score::cpp::optional<std::size_t> max_samples_limit_;
    score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval_;
    score::cpp::optional<score::cpp::jthread> proxy_available_thread_;
    score::cpp::optional<score::cpp::stop_callback> stop_callback_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_DETAILS_CONFIG_PROVIDER_IMPL_H
