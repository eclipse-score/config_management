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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_IMPL_H

#include "score/config_management/config_provider/code/config_provider/builder/config_provider_builder.h"
#include "score/config_management/config_provider/code/config_provider/details/config_provider_impl.h"
#include "score/config_management/config_provider/code/config_provider/factory/buffer_size_report.h"
#include "score/config_management/config_provider/code/config_provider/factory/semi_dynamic_single_instantiation_strategy.h"
#include "score/config_management/config_provider/code/persistency/details/persistency_impl.h"
#include "score/config_management/config_provider/code/proxies/details/internal_config_provider_impl.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include "score/mw/service/backend/mw_com/single_instantiation_strategy.h"
#include "score/mw/service/proxy_needs.h"
#include "score/mw/service/proxy_needs_factory.h"

#include "score/json/json_parser.h"
#include "score/mw/log/logger.h"

#include <score/assert.hpp>
#include <score/callback.hpp>
#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/vector.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace score
{
namespace config_management
{
namespace config_provider
{

using Proxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;
using FactoryStrategy = mw::service::FindServiceStrategy<IInternalConfigProvider>;

constexpr std::size_t kParameterSetNameNullTerminatorSize{1U};
constexpr std::size_t kParameterSetPayloadNullTerminatorSize{1U};

/// @brief Production `ConfigProviderBuilder`. Unset settings default to no wait for the connection (timeout 0),
/// empty persistency, the default memory resource, a no-op notification callback, the semi-dynamic mw::com
/// strategy, `kDefaultBufferSizeReportPath`, no parameter set names, no sample limit and no polling interval.
/// @note A builder instance is single use. `Build()` consumes the settings and terminates (assertion) when called a
/// second time, so create a new builder for each
/// `ConfigProvider`. The builder must not outlive the report path passed to `WithBufferSizeReportPath()`.
template <typename InternalConfigProviderPort>
class ConfigProviderBuilderImpl final : public ConfigProviderBuilder
{
  public:
    ConfigProviderBuilderImpl() : logger_{score::mw::log::CreateLogger(std::string_view("CfgP"))} {}

    ~ConfigProviderBuilderImpl() noexcept override = default;

    /// @brief How long `Build()` waits for the connection to the service.
    ConfigProviderBuilder& WithConnectionTimeout(std::chrono::milliseconds timeout) override
    {
        timeout_ = timeout;
        return *this;
    }

    /// @brief Sizes the shared-memory buffer for the given parameter sets only. Without it, the buffer is sized
    /// for the largest parameter set in buffer_size_report.json.
    ConfigProviderBuilder& WithRequiredParameterSets(
        score::cpp::pmr::vector<std::string_view> initial_parameter_set_name_list) override
    {
        initial_parameter_set_name_list_ = std::move(initial_parameter_set_name_list);
        return *this;
    }

    ConfigProviderBuilder& WithMaxSamplesLimit(std::size_t max_samples_limit) override
    {
        max_samples_limit_ = max_samples_limit;
        return *this;
    }

    ConfigProviderBuilder& WithPollingCycleInterval(std::chrono::milliseconds polling_cycle_interval) override
    {
        polling_cycle_interval_ = polling_cycle_interval;
        return *this;
    }

    ConfigProviderBuilder& WithPersistency(score::cpp::pmr::unique_ptr<Persistency> persistency) override
    {
        persistency_ = std::move(persistency);
        return *this;
    }

    /// @brief Replaces the mw::com strategy, so that a unit test can inject a fake without creating a real
    /// mw::com runtime, skeleton, or `mw_com_config.json`.
    ConfigProviderBuilderImpl& WithStrategyFactory(StrategyFactory make_strategy)
    {
        make_strategy_ = std::move(make_strategy);
        return *this;
    }

    ConfigProviderBuilder& WithMemoryResource(score::cpp::pmr::memory_resource* const memory_resource) override
    {
        memory_resource_ = memory_resource;
        return *this;
    }

    ConfigProviderBuilder& WithAvailabilityNotificationCallback(AvailabilityNotificationCallback callback) override
    {
        callback_ = std::move(callback);
        return *this;
    }

    /// @brief Overrides where buffer_size_report.json is read from (see
    /// BufferSizeReport::GetMaxBufferSizeInfo()). Only needed by callers that can't rely on the production
    /// default resolving correctly - e.g. in-process SCT test bindings that run outside of sctf's sandboxed
    /// mount namespace and must instead point at their own deployed copy.
    ConfigProviderBuilderImpl& WithBufferSizeReportPath(std::string_view buffer_size_report_path)
    {
        buffer_size_report_path_ = buffer_size_report_path;
        return *this;
    }

    score::cpp::pmr::unique_ptr<ConfigProvider> Build(score::cpp::stop_token token) override
    {
        if (already_built_)
        {
            logger_.LogError()
                << "ConfigProviderBuilderImpl::" << __func__
                << "Failed to build. ConfigProviderBuilderImpl is single use, Build() was already called";
            return nullptr;
        }
        already_built_ = true;
        if (persistency_ == nullptr)
        {
            persistency_ = score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource_);
        }
        if (make_strategy_ == nullptr)
        {
            make_strategy_ = MakeDefaultStrategyFactory();
        }
        return CreateInternal(token);
    }

    /// @brief Builds the `StrategyFactory` used by production code: constructs a
    /// `SemiDynamicSingleInstantiationStrategy` which discovers the real mw::com service. `Build()` uses this as
    /// the default `StrategyFactory`, i.e. the exact factory `Build()` invokes unless
    /// `WithStrategyFactory()` replaces it.
    /// @note Exposed as the supported interface for unit tests to verify which concrete `Strategy`
    /// `Build()` creates by default, without needing a real mw::com runtime/skeleton/
    /// `mw_com_config.json`. Only the returned `Strategy`'s constructor runs here - never `StartFind()` - which
    /// matters because `SemiDynamicSingleInstantiationStrategy::StartFind()` reaches
    /// `score::mw::com::impl::Runtime::getInstance()`, whose default (lazy, first-use) initialization parses a
    /// config from the hardcoded path `./etc/mw_com_config.json` and calls `std::terminate()` if that's missing or
    /// invalid - i.e. actually calling `Build()`/`StartFind()` here would risk crashing the whole test binary
    /// (gtest runs all tests of a binary in one process), not just failing a single test.
    static StrategyFactory MakeDefaultStrategyFactory()
    {
        using InternalConfigProviderStrategy =
            SemiDynamicSingleInstantiationStrategy<IInternalConfigProvider,
                                                   InternalConfigProvider,
                                                   InternalConfigProvider::InternalMwComProxy,
                                                   InternalConfigProviderPort>;
        return [](std::size_t additional_shm_size_bytes) -> std::unique_ptr<Strategy> {
            return std::make_unique<InternalConfigProviderStrategy>(additional_shm_size_bytes);
        };
    }

  private:
    score::cpp::pmr::unique_ptr<ConfigProvider> CreateInternal(score::cpp::stop_token token)
    {
        logger_.LogDebug() << "ConfigProviderBuilderImpl::" << __func__;

        using RequiredProxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;

        // Parameter set names have no small universal bound - e.g.
        // score::config_management::config_daemon::mw_com_icp_types::kMaxParameterSetNameSize only bounds the fixed-size
        // last_updated_parameter_set EVENT for calibration sets, not the semi-dynamic get_parameter_set METHOD,
        // whose coding parameter set names routinely exceed it - so this must be computed from
        // buffer_size_report.json rather than a fixed constant.
        const auto shm_sizing_result =
            BufferSizeReport::GetMaxBufferSizeInfo(initial_parameter_set_name_list_,
                                                   memory_resource_,
                                                   std::make_shared<score::json::JsonParser>(),
                                                   buffer_size_report_path_);
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
            logger_.LogError() << "ConfigProviderBuilderImpl::" << __func__
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

        auto strategy = make_strategy_(shm_sizing.max_payload_size + shm_sizing.max_name_length +
                                       kParameterSetNameNullTerminatorSize + kParameterSetPayloadNullTerminatorSize);
        auto proxy_needs = mw::service::ProxyNeedsFactory<RequiredProxies>::Create(std::move(strategy));

        auto proxy_container = proxy_needs.InitiateServiceDiscovery(token).GetProxyContainer();

        logger_.LogDebug() << "ConfigProviderBuilderImpl:: Create ConfigProviderImpl";
        auto config_provider = score::cpp::pmr::make_unique<ConfigProviderImpl>(
            memory_resource_,
            proxy_container.template Extract<mw::service::Optional<IInternalConfigProvider>>(),
            token,
            memory_resource_,
            max_samples_limit_,
            polling_cycle_interval_,
            std::move(callback_),
            std::move(persistency_),
            std::move(initial_parameter_set_name_list_),
            shm_sizing);

        score::cpp::ignore = config_provider->WaitUntilConnected(timeout_, token);
        return config_provider;
    }

    score::mw::log::Logger& logger_;
    score::cpp::optional<score::cpp::pmr::vector<std::string_view>> initial_parameter_set_name_list_{};
    score::cpp::optional<std::size_t> max_samples_limit_{};
    score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval_{};
    std::chrono::milliseconds timeout_{0U};
    score::cpp::pmr::unique_ptr<Persistency> persistency_{};
    StrategyFactory make_strategy_{};
    score::cpp::pmr::memory_resource* memory_resource_{score::cpp::pmr::get_default_resource()};
    AvailabilityNotificationCallback callback_{[]() noexcept {}};  // LCOV_EXCL_LINE tooling issue
    std::string_view buffer_size_report_path_{kDefaultBufferSizeReportPath};
    bool already_built_{false};
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_IMPL_H
