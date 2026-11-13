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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FAKE_FACTORY_MW_COM_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FAKE_FACTORY_MW_COM_H

// Fake variant of `factory_mw_com.h`, exposed under the same include path by the `factory_mw_com_for_unit_test`
// target. Unit tests of ConfigProviderFactory users link it instead of the real factory and thus neither depend on
// the factory's internals (mw::com, persistency, buffer size report) nor need to set any compile definition.
// The `Create()` overloads and the `Strategy`/`StrategyFactory` aliases mirror the real `ConfigProviderFactory`; the
// fake ignores all arguments and never connects to a service. `MakeDefaultStrategyFactory()` is omitted on purpose,
// as it would pull in the real mw::com strategy. The created
// `ConfigProviderMock` behaves like an unconnected provider by default, but a unit test can retrieve it via
// `ConfigProviderMock::GetLastCreated()` and define its behavior with `ON_CALL`/`EXPECT_CALL`.

#include "score/config_management/config_provider/code/config_provider/config_provider.h"
#include "score/config_management/config_provider/code/config_provider/config_provider_mock.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"
#include "score/config_management/config_provider/code/config_provider/factory/buffer_size_report.h"
#include "score/config_management/config_provider/code/persistency/persistency.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"

#include "score/mw/service/find_service_strategy.h"

#include <score/callback.hpp>
#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/stop_token.hpp>
#include <score/vector.hpp>

#include <gmock/gmock.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace score
{
namespace config_management
{
namespace config_provider
{

class ConfigProviderFactory final
{
  public:
    using Strategy = mw::service::FindServiceStrategy<IInternalConfigProvider>;
    using StrategyFactory = score::cpp::callback<std::unique_ptr<Strategy>(std::size_t additional_shm_size_bytes)>;

    ConfigProviderFactory() = default;

    ~ConfigProviderFactory() = default;
    ConfigProviderFactory(ConfigProviderFactory&&) = delete;
    ConfigProviderFactory(const ConfigProviderFactory&) = delete;

    ConfigProviderFactory& operator=(ConfigProviderFactory&&) & = delete;
    ConfigProviderFactory& operator=(const ConfigProviderFactory&) & = delete;

    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        std::chrono::milliseconds,
        const score::cpp::pmr::vector<std::string_view>&,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {},  // LCOV_EXCL_LINE tooling issue
        std::string_view = kDefaultBufferSizeReportPath) const
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        std::chrono::milliseconds,
        score::cpp::pmr::unique_ptr<Persistency>,
        const score::cpp::pmr::vector<std::string_view>&,
        StrategyFactory = {},
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {},  // LCOV_EXCL_LINE tooling issue
        std::string_view = kDefaultBufferSizeReportPath) const
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        score::cpp::pmr::unique_ptr<Persistency>,
        const score::cpp::pmr::vector<std::string_view>&,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {},  // LCOV_EXCL_LINE tooling issue
        std::string_view = kDefaultBufferSizeReportPath) const
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        std::chrono::milliseconds,
        score::cpp::optional<std::size_t>,
        score::cpp::optional<std::chrono::milliseconds>,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        score::cpp::pmr::unique_ptr<Persistency>,
        score::cpp::optional<std::size_t>,
        score::cpp::optional<std::chrono::milliseconds>,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        std::chrono::milliseconds,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return MakeFake(memory_resource);
    }

    template <typename InternalConfigProviderPort>
    [[deprecated(
        "DEPRECATION: Use the Create() overload with an initial_parameter_set_name_list parameter instead.")]]
    score::cpp::pmr::unique_ptr<ConfigProvider> Create(
        score::cpp::stop_token,
        score::cpp::pmr::unique_ptr<Persistency>,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        IsAvailableNotificationCallback&& = []() noexcept {}) const  // LCOV_EXCL_LINE tooling issue
    {
        return MakeFake(memory_resource);
    }

  private:
    static score::cpp::pmr::unique_ptr<ConfigProvider> MakeFake(score::cpp::pmr::memory_resource* const memory_resource)
    {
        auto mock = score::cpp::pmr::make_unique<ConfigProviderMock>(memory_resource);
        const auto not_connected = [] {
            return score::Result<std::shared_ptr<const ParameterSet>>{
                score::MakeUnexpected(ConfigProviderError::kProxyNotReady, "Fake config provider is not connected")};
        };
        ON_CALL(*mock, GetParameterSet(::testing::_)).WillByDefault([not_connected](const std::string_view) {
            return not_connected();
        });
        ON_CALL(*mock, GetParameterSet(::testing::_, ::testing::_))
            .WillByDefault([not_connected](const std::string_view, const std::optional<std::chrono::milliseconds>) {
                return not_connected();
            });
        return mock;
    }
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FAKE_FACTORY_MW_COM_H
