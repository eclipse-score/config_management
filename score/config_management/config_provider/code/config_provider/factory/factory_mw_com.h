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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H

#include "score/config_management/config_provider/code/config_provider/details/config_provider_impl.h"
#include "score/config_management/config_provider/code/persistency/details/persistency_empty.h"
#include "score/config_management/config_provider/code/proxies/details/mw_com/internal_config_provider_impl.h"

#include "score/mw/log/logger.h"
#include "platform/aas/mw/service/backend/mw_com/single_instantiation_strategy.h"
#include "platform/aas/mw/service/proxy_needs.h"
#include "platform/aas/mw/service/proxy_needs_factory.h"

#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/optional.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{

using Proxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;

class ConfigProviderFactory final
{
  public:
    ConfigProviderFactory();
    ~ConfigProviderFactory() = default;
    ConfigProviderFactory(ConfigProviderFactory&&) = delete;
    ConfigProviderFactory(const ConfigProviderFactory&) = delete;

    ConfigProviderFactory& operator=(ConfigProviderFactory&&) & = delete;
    ConfigProviderFactory& operator=(const ConfigProviderFactory&) & = delete;

    template <typename InternalConfigProviderPort>
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
                                                          score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource));
    }

    template <typename InternalConfigProviderPort>
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
                                                          std::move(persistency));
    }

    template <typename InternalConfigProviderPort>
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
                                                          score::cpp::pmr::make_unique<PersistencyImpl>(memory_resource));
    }

    template <typename InternalConfigProviderPort>
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
                                                          std::move(persistency));
    }

  private:
    template <typename InternalConfigProviderPort>
    score::cpp::pmr::unique_ptr<ConfigProvider> CreateInternal(score::cpp::stop_token token,
                                                        std::chrono::milliseconds timeout,
                                                        score::cpp::optional<std::size_t> max_samples_limit,
                                                        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
                                                        score::cpp::pmr::memory_resource* const memory_resource,
                                                        IsAvailableNotificationCallback&& callback,
                                                        score::cpp::pmr::unique_ptr<Persistency> persistency) const
    {
        using InternalConfigProviderStrategy =
            mw::service::backend::mw_com::SingleInstantiationStrategy<IInternalConfigProvider,
                                                                      InternalConfigProvider,
                                                                      InternalConfigProvider::InternalMwComProxy,
                                                                      InternalConfigProviderPort>;
        logger_.LogDebug() << "ConfigProviderFactory::" << __func__;

        using RequiredProxies = mw::service::ProxyNeeds<mw::service::Optional<IInternalConfigProvider>>;

        auto proxy_needs = mw::service::ProxyNeedsFactory<RequiredProxies>::Create<InternalConfigProviderStrategy>();
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
            std::move(persistency));

        score::cpp::ignore = config_provider->WaitUntilConnected(timeout, token);
        return config_provider;
    }

    mw::log::Logger& logger_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_FACTORY_FACTORY_MW_COM_H
