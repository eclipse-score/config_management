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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_SEMI_DYNAMIC_SINGLE_INSTANTIATION_STRATEGY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_SEMI_DYNAMIC_SINGLE_INSTANTIATION_STRATEGY_H

#include "score/mw/service/find_service_strategy.h"
#include "score/mw/service/proxy_builder_base.h"
#include "score/mw/com/types.h"

#include "score/mw/log/logging.h"

#include <score/assert.hpp>
#include <score/utility.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace score::config_management::config_provider
{

namespace detail
{
template <typename T, typename = void>
struct CanInvokeGet : std::false_type
{
};

template <typename T>
struct CanInvokeGet<T, std::void_t<decltype(T::Get())>> : std::true_type
{
};

template <typename T>
constexpr bool IsValidPortIdentifierType() noexcept
{
    if constexpr (CanInvokeGet<T>::value)
    {
        return std::is_convertible_v<decltype(T::Get()), std::string>;
    }
    else
    {
        return false;
    }
}

}  // namespace detail

/// @brief Single-instance discovery strategy which supplies an additional shared-memory size when constructing a
///         mw::com proxy.
///
/// @note This strategy is specific to `ConfigProvider`'s "semi-dynamic" `get_parameter_set` method which requires an
///       additional, pre-allocated shared-memory pool. It therefore lives alongside `ConfigProviderFactory` instead
///       of the generic `mw::service::backend::mw_com` strategies.
template <typename ProxyBase, typename ProxyImpl, typename MwComProxy, typename PortIdentifier = void>
class SemiDynamicSingleInstantiationStrategy final : public mw::service::FindServiceStrategy<ProxyBase>
{
    static_assert(std::is_void_v<PortIdentifier> || detail::IsValidPortIdentifierType<PortIdentifier>(),
                  "template parameter `PortIdentifier` lacks a static method "
                  "named `Get` which's result can be converted to std::string");

    using HandleType = typename MwComProxy::HandleType;

  public:
    using typename mw::service::FindServiceStrategy<ProxyBase>::OnServiceFoundCallback;

    template <typename PortIdentifierProvider = PortIdentifier,
              std::enable_if_t<std::is_void_v<PortIdentifierProvider>, bool> = true>
    explicit SemiDynamicSingleInstantiationStrategy(std::string port_identifier,
                                                    std::size_t additional_shm_size_bytes) noexcept
        : port_identifier_{std::move(port_identifier)}, additional_shm_size_bytes_{additional_shm_size_bytes}
    {
    }

    template <typename PortIdentifierProvider = PortIdentifier,
              std::enable_if_t<not(std::is_void_v<PortIdentifierProvider>), bool> = true>
    explicit SemiDynamicSingleInstantiationStrategy(std::size_t additional_shm_size_bytes)
        : port_identifier_{PortIdentifier::Get()}, additional_shm_size_bytes_{additional_shm_size_bytes}
    {
    }

    SemiDynamicSingleInstantiationStrategy(SemiDynamicSingleInstantiationStrategy&& other) noexcept
        : port_identifier_{std::move(other.port_identifier_)},
          additional_shm_size_bytes_{other.additional_shm_size_bytes_},
          find_service_handle_{std::move(other.find_service_handle_)}
    {
    }

    ~SemiDynamicSingleInstantiationStrategy() noexcept override
    {
        StopFind();
    }

    SemiDynamicSingleInstantiationStrategy(const SemiDynamicSingleInstantiationStrategy&) = delete;
    SemiDynamicSingleInstantiationStrategy& operator=(const SemiDynamicSingleInstantiationStrategy&) = delete;
    SemiDynamicSingleInstantiationStrategy& operator=(SemiDynamicSingleInstantiationStrategy&&) = delete;

    const auto& GetPortIdentifier() const noexcept
    {
        return port_identifier_;
    }

    void StartFind(std::unique_ptr<OnServiceFoundCallback> on_found) override
    {
        const std::lock_guard lock{mutex_};

        const auto instance_specifier_result = score::mw::com::InstanceSpecifier::Create(port_identifier_);
        SCORE_LANGUAGE_FUTURECPP_ASSERT_PRD(instance_specifier_result.has_value());

        class CallbackState
        {
          public:
            CallbackState(std::unique_ptr<OnServiceFoundCallback>&& callback, const std::size_t additional_shm_size)
                : on_found{std::move(callback)}, additional_shm_size_bytes{additional_shm_size}
            {
            }

            std::unique_ptr<OnServiceFoundCallback> on_found;
            std::size_t additional_shm_size_bytes;
        };

        auto on_service_found_callback = [callback_state_ptr = std::make_unique<CallbackState>(
                                              std::move(on_found), additional_shm_size_bytes_),
                                          this](const score::mw::com::ServiceHandleContainer<HandleType>& handles,
                                                const score::mw::com::FindServiceHandle find_handle) noexcept {
            std::unique_lock lock_of_callback{mutex_};
            find_service_handle_ = find_handle;

            for (const auto& handle : handles)
            {
                auto proxy_result = score::mw::com::impl::ProxyWithSemiDynamicMethodFactory<MwComProxy>::Create(
                    handle, callback_state_ptr->additional_shm_size_bytes);
                if (not(proxy_result.has_value()))
                {
                    mw::log::LogError() << "Failed to create proxy with additional_shm_size="
                                        << callback_state_ptr->additional_shm_size_bytes
                                        << " error:" << proxy_result.error();
                    continue;
                }

                lock_of_callback.unlock();
                std::invoke(*callback_state_ptr->on_found,
                            std::make_unique<ProxyImpl>(std::make_unique<MwComProxy>(std::move(proxy_result).value())));
                lock_of_callback.lock();
            }
        };

        const auto start_result =
            MwComProxy::StartFindService(std::move(on_service_found_callback), instance_specifier_result.value());

        if (not(start_result.has_value()))
        {
            mw::log::LogError() << "StartFindService failed for '" << port_identifier_ << "'";
            return;
        }

        if (not(find_service_handle_.has_value()))
        {
            score::cpp::ignore = find_service_handle_.emplace(start_result.value());
        }
    }

    void StopFind() noexcept override
    {
        const std::lock_guard lock{mutex_};
        if (find_service_handle_.has_value())
        {
            score::cpp::ignore = MwComProxy::StopFindService(find_service_handle_.value());
            find_service_handle_.reset();
        }
    }

  private:
    std::string port_identifier_;
    std::size_t additional_shm_size_bytes_;
    std::optional<score::mw::com::FindServiceHandle> find_service_handle_{};
    mutable std::recursive_mutex mutex_;
};

}  // namespace score::config_management::config_provider

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_SEMI_DYNAMIC_SINGLE_INSTANTIATION_STRATEGY_H
