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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H

#include "score/config_management/config_provider/code/config_provider/details/config_provider_impl.h"
#include "score/config_management/config_provider/code/config_provider/factory/buffer_size_report.h"
#include "score/config_management/config_provider/code/config_provider/factory/semi_dynamic_single_instantiation_strategy.h"
#include "score/config_management/config_provider/code/persistency/details/persistency_impl.h"
#include "score/config_management/config_provider/code/proxies/details/internal_config_provider_impl.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include "score/json/json_parser.h"
#include "score/mw/log/logger.h"
#include "score/mw/service/backend/mw_com/single_instantiation_strategy.h"
#include "score/mw/service/proxy_needs.h"
#include "score/mw/service/proxy_needs_factory.h"

#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/vector.hpp>

#include <memory>
#include <string>

namespace score
{
namespace config_management
{
namespace config_provider
{

using Proxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;

constexpr std::size_t kParameterSetNameNullTerminatorSize{1U};
constexpr std::size_t kParameterSetPayloadNullTerminatorSize{1U};
class ConfigProviderFactory final
{
  public:
    ConfigProviderFactory();

    ~ConfigProviderFactory() = default;
    ConfigProviderFactory(ConfigProviderFactory&&) = delete;
    ConfigProviderFactory(const ConfigProviderFactory&) = delete;

    ConfigProviderFactory& operator=(ConfigProviderFactory&&) & = delete;
    ConfigProviderFactory& operator=(const ConfigProviderFactory&) & = delete;

    /// @param buffer_size_report_path Overrides where buffer_size_report.json is read from (see
    /// BufferSizeReport::GetMaxBufferSizeInfo()). Only needed by callers that can't rely on the production
    /// default (kDefaultBufferSizeReportPath) resolving correctly - e.g. in-process SCT test bindings that run
    /// outside of sctf's sandboxed mount namespace and must instead point at their own deployed copy.
    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        std::chrono::milliseconds timeout,
        const score::cpp::pmr::vector<std::string_view>& initial_parameter_set_name_list,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {},  // LCOV_EXCL_LINE tooling issue
        std::string_view buffer_size_report_path = kDefaultBufferSizeReportPath) const
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          timeout,
                                                          score::cpp::nullopt,
                                                          score::cpp::nullopt,
                                                          memory_resource,
                                                          std::move(callback),
                                                          score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource),
                                                          initial_parameter_set_name_list,
                                                          buffer_size_report_path);
    }

    /// @param buffer_size_report_path See the other Create() overload's parameter of the same name.
    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        score::cpp::pmr::unique_ptr<Persistency> persistency,
        const score::cpp::pmr::vector<std::string_view>& initial_parameter_set_name_list,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {},  // LCOV_EXCL_LINE tooling issue
        std::string_view buffer_size_report_path = kDefaultBufferSizeReportPath) const
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          std::chrono::milliseconds(0U),
                                                          score::cpp::nullopt,
                                                          score::cpp::nullopt,
                                                          memory_resource,
                                                          std::move(callback),
                                                          std::move(persistency),
                                                          initial_parameter_set_name_list,
                                                          buffer_size_report_path);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "SPP_DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead. "
        "Without it, the shared-memory buffer is sized for the largest parameter set in "
        "buffer_size_report.json instead of just the ones actually used.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        std::chrono::milliseconds timeout,
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          timeout,
                                                          max_samples_limit,
                                                          polling_cycle_interval,
                                                          memory_resource,
                                                          std::move(callback),
                                                          score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource),
                                                          score::cpp::nullopt,
                                                          kDefaultBufferSizeReportPath);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "SPP_DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead. "
        "Without it, the shared-memory buffer is sized for the largest parameter set in "
        "buffer_size_report.json instead of just the ones actually used.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        score::cpp::pmr::unique_ptr<Persistency> persistency,
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          std::chrono::milliseconds(0U),
                                                          max_samples_limit,
                                                          polling_cycle_interval,
                                                          memory_resource,
                                                          std::move(callback),
                                                          std::move(persistency),
                                                          score::cpp::nullopt,
                                                          kDefaultBufferSizeReportPath);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "SPP_DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead. "
        "Without it, the shared-memory buffer is sized for the largest parameter set in "
        "buffer_size_report.json instead of just the ones actually used.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        std::chrono::milliseconds timeout,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          timeout,
                                                          score::cpp::nullopt,
                                                          score::cpp::nullopt,
                                                          memory_resource,
                                                          std::move(callback),
                                                          score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource),
                                                          score::cpp::nullopt,
                                                          kDefaultBufferSizeReportPath);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "SPP_DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead. "
        "Without it, the shared-memory buffer is sized for the largest parameter set in "
        "buffer_size_report.json instead of just the ones actually used.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token token,
        score::cpp::pmr::unique_ptr<Persistency> persistency,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& callback = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return CreateInternal<InternalConfigProviderPort>(token,
                                                          std::chrono::milliseconds(0U),
                                                          score::cpp::nullopt,
                                                          score::cpp::nullopt,
                                                          memory_resource,
                                                          std::move(callback),
                                                          std::move(persistency),
                                                          score::cpp::nullopt,
                                                          kDefaultBufferSizeReportPath);
    }

  private:
    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> CreateInternal(
        score::cpp::stop_token token,
        std::chrono::milliseconds timeout,
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
        score::cpp::pmr::memory_resource* const memory_resource,
        IsAvailableNotificationCallback&& callback,
        score::cpp::pmr::unique_ptr<Persistency> persistency,
        score::cpp::optional<score::cpp::pmr::vector<std::string_view>> initial_parameter_set_name_list,
        std::string_view buffer_size_report_path) const
    {
        using InternalConfigProviderStrategy =
            SemiDynamicSingleInstantiationStrategy<IInternalConfigProvider,
                                                   InternalConfigProvider,
                                                   InternalConfigProvider::InternalMwComProxy,
                                                   InternalConfigProviderPort>;
        logger_.LogDebug() << "ConfigProviderFactory::" << __func__;

        using RequiredProxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;

        // Parameter set names have no small universal bound - e.g.
        // score::config_management::config_daemon::mw_com_icp_types::kMaxParameterSetNameSize only bounds the fixed-size
        // last_updated_parameter_set EVENT for calibration sets, not the semi-dynamic get_parameter_set METHOD,
        // whose coding parameter set names routinely exceed it - so this must be computed from
        // buffer_size_report.json rather than a fixed constant.
        const auto shm_sizing_result = BufferSizeReport::GetMaxBufferSizeInfo(initial_parameter_set_name_list,
                                                                              memory_resource,
                                                                              std::make_shared<json::JsonParser>(),
                                                                              buffer_size_report_path);
        // Falling back to conservative default sizes (rather than returning nullptr) keeps ConfigProvider usable
        // even if buffer_size_report.json is missing or malformed. kMinParameterSetContentBufferSize is a true
        // floor - always big enough for the skeleton's sentinel content - but there is no equivalent bound for
        // the name: as noted above, kMaxParameterSetNameSize only bounds the fixed-size event and real
        // get_parameter_set names routinely exceed it, so using it here would give false confidence. Defaulting
        // the name length to 0 instead reserves no guessed space for it, so GetParameterSet() calls will fail
        // cleanly and gracefully per-call (handled by the existing proxy error path) instead of the whole
        // ConfigProvider failing to come up.
        AdditionalShmSizing shm_sizing{config_daemon::mw_com_icp_types::kMinParameterSetContentBufferSize, 0U};
        if (!shm_sizing_result.has_value())
        {
            logger_.LogError() << "ConfigProviderFactory::" << __func__
                               << ": Failed to determine parameter set buffer size from buffer_size_report.json, "
                                  "falling back to default buffer sizes: "
                               << shm_sizing_result.error().UserMessage();
        }
        else
        {
            shm_sizing = shm_sizing_result.value();
        }

        // The additional shared-memory pool backing the semi-dynamic `get_parameter_set` method call must fit both
        // dynamically-sized arguments allocated from it: the requested parameter set name (arg1) and the returned
        // payload (arg2). Reserving only the payload size leaves no room for the name buffer, causing a fatal
        // "Cannot allocate shared memory block" error once the name buffer has consumed part of the reserved pool.
        // One extra byte per string budgets for a null terminator, in case either buffer's contents ever end up
        // null-terminated (neither is today - see internal_config_provider_impl.cpp - but this keeps the same
        // conservative safety margin against SHM allocator overhead that both strings historically had.

        auto proxy_needs = mw::service::ProxyNeedsFactory<RequiredProxies>::Create(InternalConfigProviderStrategy{
            shm_sizing.max_payload_size + shm_sizing.max_name_length + kParameterSetNameNullTerminatorSize +
            kParameterSetPayloadNullTerminatorSize});

        auto proxy_container = proxy_needs.InitiateServiceDiscovery(token).GetProxyContainer();

        logger_.LogDebug() << "ConfigProviderFactory:: Create ConfigProviderImpl";
        auto config_provider = score::cpp::pmr::make_unique<ConfigProviderImpl>(
            memory_resource,
            proxy_container.template Extract<mw::service::Optional<IInternalConfigProvider>>(),
            token,
            memory_resource,
            max_samples_limit,
            polling_cycle_interval,
            std::move(callback),
            std::move(persistency),
            std::move(initial_parameter_set_name_list),
            shm_sizing);

        score::cpp::ignore = config_provider->WaitUntilConnected(timeout, token);
        return config_provider;
    }

    mw::log::Logger& logger_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H
