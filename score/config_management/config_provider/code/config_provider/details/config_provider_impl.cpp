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
#include "score/config_management/config_provider/code/config_provider/details/config_provider_impl.h"
#include "score/concurrency/future/interruptible_promise.h"
#include "score/json/json_parser.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "score/config_management/config_provider/code/config_provider/initial_qualifier_state_types.h"
#include <score/memory.hpp>
#include <score/memory_resource.hpp>
#include <score/utility.hpp>
#include <iostream>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace
{
// Helper function to get parameter set value string only, if Debug log level is enabled, as getting the value as string
// might be computationally expensive
std::string GetParameterSetValue(mw::log::Logger& logger, const ParameterSet& param_set)
{
    if (logger.IsEnabled(mw::log::LogLevel::kDebug))
    {
        if (auto param_set_str_result = param_set.GetParametersAsString(); param_set_str_result.has_value())
        {
            return param_set_str_result.value();
        }
    }
    return "";
}

InitialQualifierState ConvertInitialQualifierStateToInitialQualifierState(InitialQualifierState initial_qualifier_state)
{
    InitialQualifierState result = InitialQualifierState::kUndefined;

    switch (initial_qualifier_state)
    {
        case InitialQualifierState::kDefault:
            result = InitialQualifierState::kDefault;
            break;
        case InitialQualifierState::kInProgress:
            result = InitialQualifierState::kInProgress;
            break;
        case InitialQualifierState::kQualified:
            result = InitialQualifierState::kQualified;
            break;
        case InitialQualifierState::kUnqualified:
            result = InitialQualifierState::kUnqualified;
            break;
        case InitialQualifierState::kQualifying:
            result = InitialQualifierState::kQualifying;
            break;
        case InitialQualifierState::kUndefined:
            result = InitialQualifierState::kUndefined;
            break;
        default:
            result = InitialQualifierState::kUndefined;
            break;
    }

    return result;
}
}  // namespace

ConfigProviderImpl::ConfigProviderImpl(
    mw::service::ProxyFuture<std::unique_ptr<IInternalConfigProvider>> internal_config_provider_future,
    score::cpp::stop_token user_stop_token,
    score::cpp::pmr::memory_resource* const memory_resource,
    score::cpp::optional<std::size_t> max_samples_limit,
    score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval,
    IsAvailableNotificationCallback callback,
    score::cpp::pmr::unique_ptr<Persistency> persistency)
    : ConfigProvider(),
      logger_{mw::log::CreateLogger(std::string_view{"CfgP"})},
      parameter_sets_{ParameterMap::allocator_type{memory_resource}},  // LCOV_EXCL_LINE optimized by compiler
      initial_qualifier_state_{InitialQualifierState::kUndefined},
      memory_resource_{memory_resource},
      internal_config_provider_{},
      persistency_{std::move(persistency)},
      client_handlers_{ClientHandlersMap::allocator_type{memory_resource}},  // LCOV_EXCL_LINE optimized by compiler
      max_samples_limit_{max_samples_limit},
      polling_cycle_interval_{polling_cycle_interval},
      proxy_available_thread_{},
      stop_callback_{}
{
    logger_.LogDebug() << __func__;
    const score::filesystem::FilesystemFactory filesystem_factory{};  // LCOV_EXCL_LINE optimized by compiler
    persistency_->ReadCachedParameterSets(parameter_sets_, memory_resource, filesystem_factory.CreateInstance());

    score::cpp::ignore = proxy_available_thread_.emplace(
        [this](const score::cpp::stop_token jthread_stop_token,
               decltype(callback) notification_callback,
               decltype(internal_config_provider_future) proxy_future) mutable {
            auto proxy_holder = proxy_future.Get(jthread_stop_token);
            if (proxy_holder.has_value())
            {
                logger_.LogInfo() << "ProxyAvailableThread: InternalConfigProvider proxy is connected";
                SetupInternalConfigProvider(
                    std::move(proxy_holder).value(), std::move(notification_callback), jthread_stop_token);
            }
            else
            {
                logger_.LogInfo() << "ProxyAvailableThread: No proxy found: " << proxy_holder.error().Message();
            }
        },
        std::move(callback),
        std::move(internal_config_provider_future));

    score::cpp::ignore = stop_callback_.emplace(user_stop_token, [this]() {
        score::cpp::ignore = proxy_available_thread_->request_stop();
    });
}

bool ConfigProviderImpl::WaitUntilConnected(const std::chrono::milliseconds timeout,
                                            const score::cpp::stop_token& stop_token) noexcept
{
    std::unique_lock<std::mutex> lock{mutex_};
    const auto result = internal_config_provider_cv_.wait_for(lock, stop_token, timeout, [this]() noexcept -> bool {
        return internal_config_provider_ != nullptr;
    });
    if (stop_token.stop_requested())
    {
        logger_.LogWarn() << __func__ << ": Stop token requested";
        return false;
    }
    else if (not result)
    {
        logger_.LogWarn() << __func__ << ": Wait time of" << timeout.count() << "ms exceeded";
        return false;
    }
    return true;
}

bool ConfigProviderImpl::IsAwaitingProxyConnection() const noexcept
{
    std::lock_guard<std::mutex> lock{mutex_};
    return ((internal_config_provider_ == nullptr) && (proxy_available_thread_.has_value())) &&
           (not(proxy_available_thread_->get_stop_token().stop_requested()));
}

ConfigProviderImpl::~ConfigProviderImpl()
{
    logger_.LogDebug() << __func__;
    // Keep in mind that the order of reset() calls below *is* relevant!
    // Otherwise the `stop_callback_` might attempt to access the
    // `proxy_available_thread_` after it got already destroyed.
    // At the same time, `proxy_available_thread_` must get reset
    // prior to any other member of ConfigProviderImpl so that the
    // destructor of `score::cpp::jthread` waits for its callable to finish.
    // Only then it is guaranteed that no more concurrent accesses to
    // any member or method of ConfigProviderImpl can occur.
    stop_callback_.reset();
    proxy_available_thread_.reset();
    if (internal_config_provider_ != nullptr)
    {
        internal_config_provider_->StopParameterSetUpdatePollingRoutine();
    }
    internal_config_provider_.reset();
}

void ConfigProviderImpl::SetupInternalConfigProvider(std::shared_ptr<IInternalConfigProvider> internal_config_provider,
                                                     IsAvailableNotificationCallback is_available_notification_callback,
                                                     const score::cpp::stop_token& stop_token)
{
    if (not(internal_config_provider->TrySubscribeToLastUpdatedParameterSetEvent(
            stop_token, [this](const score::cpp::string_view set) {
                this->LastUpdatedParameterSetReceiveHandler(set);
            })))
    {
        logger_.LogError() << __func__ << ": Failed to subscribe to LastUpdatedParameterSet event";
        return;
    }
    logger_.LogDebug() << __func__ << ": Subscribed to LastUpdatedParameterSet event.";
    auto new_parameter_set_values = FetchInitialParameterSetValuesFrom(*internal_config_provider);
    WriteInitialParameterSetValuesToPersistentCache(std::move(new_parameter_set_values));
    CacheInitialQualifierState(internal_config_provider->GetInitialQualifierState(kDefaultResponseTimeout));
    RegisterCallbacksForPersistedParameterSetNames();

    std::unique_lock<std::mutex> lock{mutex_};
    internal_config_provider_ = std::move(internal_config_provider);
    internal_config_provider_->StartParameterSetUpdatePollingRoutine(max_samples_limit_, polling_cycle_interval_);
    lock.unlock();

    if (not(is_available_notification_callback.empty()))
    {
        is_available_notification_callback();
    }
    internal_config_provider_cv_.notify_all();
}

void ConfigProviderImpl::CacheInitialQualifierState(const InitialQualifierState initial_qualifier_state) noexcept
{
    // Suppress "AUTOSAR C++14 A5-2-6" rule, which states: "The operands of a logical && or || shall be parenthesized if
    // the operands contain binary operators"
    // Rationale: This is false positive, operands of a logical || are already parenthesized.
    // coverity[autosar_cpp14_a5_2_6_violation]
    if ((initial_qualifier_state == InitialQualifierState::kQualified) ||
        (initial_qualifier_state == InitialQualifierState::kUnqualified) ||
        (initial_qualifier_state == InitialQualifierState::kDefault))
    {
        logger_.LogInfo() << __func__ << ": Caching the final state:"
                          << static_cast<std::underlying_type_t<InitialQualifierState>>(initial_qualifier_state);
        initial_qualifier_state_ = initial_qualifier_state;
    }
    else
    {
        logger_.LogError() << __func__ << ": A non final state received from proxy:"
                           << static_cast<std::underlying_type_t<InitialQualifierState>>(initial_qualifier_state);
    }
}

Result<std::shared_ptr<const ParameterSet>> ConfigProviderImpl::GetParameterSet(const score::cpp::string_view set_name)
{
    return GetParameterSet(set_name, std::nullopt);
}

Result<std::shared_ptr<const ParameterSet>> ConfigProviderImpl::GetParameterSet(
    const score::cpp::string_view set_name,
    const std::optional<std::chrono::milliseconds> timeout)
{
    const auto actual_timeout = timeout.value_or(kDefaultResponseTimeout);

    std::lock_guard<std::mutex> lock{mutex_};
    const auto it =
        std::find_if(parameter_sets_.begin(), parameter_sets_.end(), [&set_name](const auto& param_set_pair) noexcept {
            return score::cpp::string_view{param_set_pair.first} == set_name;
        });

    if (it != parameter_sets_.end())
    {
        logger_.LogDebug() << __func__ << " [" << set_name
                           << "]: value: " << GetParameterSetValue(logger_, *it->second);
        return {it->second};
    }

    if (internal_config_provider_ == nullptr)
    {
        logger_.LogError() << __func__ << "Proxy is not ready";
        return MakeUnexpected(ConfigProviderError::kProxyNotReady, "Proxy is not ready");
    }

    const auto param_set =
        GetParameterSetFromInternalConfigProvider(set_name, *internal_config_provider_, actual_timeout);
    if (not param_set.has_value())
    {
        return param_set;
    }

    logger_.LogInfo() << __func__ << " [" << set_name << "]: Adding new parameter set to cache as "
                      << parameter_sets_.size() << " element";
    logger_.LogDebug() << __func__ << " [" << set_name
                       << "]: New parameter set with value: " << GetParameterSetValue(logger_, *param_set.value());
    score::cpp::pmr::string param_set_key{set_name.data(), set_name.size(), memory_resource_};
    persistency_->CacheParameterSet(parameter_sets_, param_set_key, param_set.value(), true);
    score::cpp::ignore = parameter_sets_.try_emplace(param_set_key, param_set.value());
    // Register update handler to keep this newly cached parameter set up-to-date.
    // We ignore returned value because we always pass empty callback here which
    // can't trigger error branch inside RegisterUpdateHandlerForParameterSet method
    score::cpp::ignore = RegisterUpdateHandlerForParameterSetName(param_set_key, {});
    return param_set;
}

ParameterSetMap ConfigProviderImpl::GetParameterSetsByNameList(const score::cpp::pmr::vector<score::cpp::string_view>& set_names,
                                                               const std::optional<std::chrono::milliseconds> timeout)
{
    const auto actual_timeout = timeout.value_or(kDefaultResponseTimeout);
    // Ensure the result map uses the same memory resource to avoid default-heap allocations
    ParameterSetMap parameter_set_map{ParameterSetMap::allocator_type{memory_resource_}};
    {
        for (const auto& set_name : set_names)
        {
            std::lock_guard<std::mutex> lock{mutex_};
            // Always use score::cpp::pmr::string as key for parameter_sets_ and parameter_set_map
            score::cpp::pmr::string set_name_key{set_name.data(), set_name.size(), memory_resource_};
            const auto it = std::find_if(
                parameter_sets_.begin(), parameter_sets_.end(), [&set_name_key](const auto& param_set_pair) noexcept {
                    return param_set_pair.first == set_name_key;
                });

            if (it != parameter_sets_.end())
            {
                logger_.LogDebug() << __func__ << " [" << set_name
                                   << "]: cached value: " << GetParameterSetValue(logger_, *it->second);
                score::cpp::ignore = parameter_set_map.try_emplace(set_name_key, it->second);
                continue;
            }
            if (internal_config_provider_ == nullptr)
            {
                logger_.LogDebug() << __func__ << " [" << set_name << "]: Proxy is not ready";
                score::cpp::ignore = parameter_set_map.try_emplace(
                    set_name_key, MakeUnexpected(ConfigProviderError::kProxyNotReady, "Proxy is not ready"));
                continue;
            }

            const auto param_set =
                GetParameterSetFromInternalConfigProvider(set_name, *internal_config_provider_, actual_timeout);
            if (not param_set.has_value())
            {
                logger_.LogError() << __func__ << " [" << set_name
                                   << "]: Failed to get parameter set from internal config provider: "
                                   << param_set.error();
                score::cpp::ignore = parameter_set_map.try_emplace(
                    set_name_key,
                    MakeUnexpected(ConfigProviderError::kParameterSetNotFound, "Parameter set not found"));
                continue;
            }

            score::cpp::pmr::string param_set_key{set_name.data(), set_name.size(), memory_resource_};
            score::cpp::ignore = parameter_set_map.try_emplace(set_name_key, param_set.value());
            logger_.LogDebug() << __func__ << " [" << set_name << "]: New parameter set with value: "
                               << GetParameterSetValue(logger_, *param_set.value());
            persistency_->CacheParameterSet(parameter_sets_, param_set_key, param_set.value(), false);
            score::cpp::ignore = parameter_sets_.try_emplace(param_set_key, param_set.value());
            // Register update handler to keep this newly cached parameter set up-to-date.
            // We ignore returned value because we always pass empty callback here which
            // can't trigger error branch inside RegisterUpdateHandlerForParameterSet method
            score::cpp::ignore = RegisterUpdateHandlerForParameterSetName(param_set_key, {});
        }
        persistency_->SyncToStorage();
    }

    return parameter_set_map;
}

Result<std::shared_ptr<const ParameterSet>> ConfigProviderImpl::GetParameterSetFromInternalConfigProvider(
    const score::cpp::string_view set_name,
    const IInternalConfigProvider& internal_config_provider,
    const std::chrono::milliseconds timeout)
{
    // NOTE: we assume here that `mutex_` got already acquired by the caller!
    logger_.LogDebug() << __func__ << " [" << set_name << "]: timeout: " << timeout;

    auto parameter_set_result = internal_config_provider.GetParameterSet(set_name, timeout);
    if (not(parameter_set_result.has_value()))
    {
        logger_.LogError() << __func__ << " [" << set_name
                           << "]: Failed to get ParameterSet from InternalConfigProvider proxy: "
                           << parameter_set_result.error();
        return Unexpected{parameter_set_result.error()};
    }

    return {score::cpp::pmr::make_shared<const ParameterSet>(
        memory_resource_, std::move(parameter_set_result).value(), memory_resource_)};
}

ResultBlank ConfigProviderImpl::OnChangedInitialQualifierState(InitialQualifierStateNotifierCallbackType&& /*callback*/) noexcept
{
    return MakeUnexpected(ConfigProviderError::kMethodNotSupported,
                          "ConfigProviderImpl::OnChangedInitialQualifierState() is no longer supported");
}

InitialQualifierState ConfigProviderImpl::GetInitialQualifierState() noexcept
{
    return ConvertInitialQualifierStateToInitialQualifierState(GetInitialQualifierState(std::nullopt));
}

InitialQualifierState ConfigProviderImpl::GetInitialQualifierState(const std::optional<std::chrono::milliseconds> timeout) noexcept
{
    return ConvertInitialQualifierStateToInitialQualifierState(GetInitialQualifierState(timeout));
}

InitialQualifierState ConfigProviderImpl::GetInitialQualifierState(
    const std::optional<std::chrono::milliseconds> timeout) noexcept
{
    logger_.LogDebug() << __func__ << ": InitialQualifierState:"
                       << static_cast<std::underlying_type_t<InitialQualifierState>>(initial_qualifier_state_);
    if (initial_qualifier_state_ != InitialQualifierState::kUndefined)
    {
        logger_.LogInfo() << __func__ << ": Providing the cached state:"
                          << static_cast<std::underlying_type_t<InitialQualifierState>>(initial_qualifier_state_);
        return initial_qualifier_state_;
    }

    const auto actual_timeout = timeout.value_or(kDefaultResponseTimeout);
    logger_.LogDebug() << __func__ << ": timeout:" << actual_timeout;

    std::lock_guard<std::mutex> lock{mutex_};

    if (internal_config_provider_ == nullptr)
    {
        logger_.LogError() << __func__ << ": Proxy is not ready, returning state:"
                           << static_cast<std::underlying_type_t<InitialQualifierState>>(initial_qualifier_state_);
        return initial_qualifier_state_;
    }
    const auto initial_qualifier_state = internal_config_provider_->GetInitialQualifierState(actual_timeout);
    CacheInitialQualifierState(initial_qualifier_state);
    return initial_qualifier_state;
}

std::size_t ConfigProviderImpl::GetCachedParameterSetsCount() const noexcept
{
    std::lock_guard<std::mutex> lock{mutex_};
    return parameter_sets_.size();
}

void ConfigProviderImpl::LastUpdatedParameterSetReceiveHandler(const score::cpp::string_view set_name)
{
    logger_.LogDebug() << __func__ << " [" << set_name << "]";
    std::lock_guard<std::mutex> lock{mutex_};

    const score::cpp::pmr::string set_name_amp{set_name.data(), set_name.size(), memory_resource_};
    if (auto client_handler_it = client_handlers_.find(set_name_amp); client_handler_it == client_handlers_.end())
    {
        return;
    }

    // LCOV_EXCL_BR_START (internal_config_provider_ cannot be nullptr in current implementation)
    if (internal_config_provider_ == nullptr)
    {
        // LCOV_EXCL_START (not reachable in the implementation)
        logger_.LogError() << __func__ << " [" << set_name << "]: Proxy is not ready";
        return;
        // LCOV_EXCL_STOP
    }
    // LCOV_EXCL_BR_STOP
    const auto parameter_set =
        GetParameterSetFromInternalConfigProvider(set_name, *internal_config_provider_, kDefaultResponseTimeout);

    if (parameter_set.has_value())
    {
        persistency_->CacheParameterSet(parameter_sets_, set_name_amp, parameter_set.value(), true);
        const auto result = parameter_sets_.insert_or_assign(set_name_amp, parameter_set.value());

        if (result.second)
        {
            logger_.LogDebug() << __func__ << " [" << set_name << "]: New parameter set inserted, value: "
                               << GetParameterSetValue(logger_, *parameter_set.value());
        }
        else
        {
            logger_.LogDebug() << __func__ << " [" << set_name << "]: Existing parameter set updated, value: "
                               << GetParameterSetValue(logger_, *parameter_set.value());
        }
        if (auto client_handler_it = client_handlers_.find(set_name_amp);
            client_handler_it != client_handlers_.end() && not client_handler_it->second.empty())
        {
            client_handler_it->second(parameter_set.value());
        }
    }
}

ResultBlank ConfigProviderImpl::OnChangedParameterSet(const std::string& set_name,
                                                      OnChangedParameterSetCallback&& callback) noexcept
{
    logger_.LogDebug() << __func__ << " [" << set_name << "]";

    auto on_changed_parameter_set_callback = std::move(callback);
    if (on_changed_parameter_set_callback.empty())
    {
        logger_.LogError() << __func__ << " [" << set_name << "]: Empty callback provided.";
        return MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided, "Empty callback provided.");
    }
    std::lock_guard<std::mutex> lock{mutex_};
    return RegisterUpdateHandlerForParameterSetName(set_name, std::move(on_changed_parameter_set_callback));
}

ResultBlank ConfigProviderImpl::OnChangedParameterSetCbk(std::string_view set_name,
                                                         OnChangedParameterSetCallback&& callback) noexcept
{
    return OnChangedParameterSet(std::string{set_name}, std::move(callback));
}

ResultBlank ConfigProviderImpl::RegisterUpdateHandlerForParameterSetName(const score::cpp::string_view set_name,
                                                                         OnChangedParameterSetCallback&& callback)
{
    // NOTE: we assume here that `mutex_` got already acquired by the caller!
    logger_.LogDebug() << __func__ << " [" << set_name << "]";
    score::cpp::pmr::string set_name_obj{set_name.data(), set_name.size(), memory_resource_};

    auto on_changed_parameter_set_callback = std::move(callback);
    if (const auto found_handler = client_handlers_.find(set_name_obj);
        (found_handler == client_handlers_.end()) ||
        (found_handler->second.empty() && not on_changed_parameter_set_callback.empty()))
    {
        logger_.LogDebug() << __func__ << " [" << set_name << "]: set callback";
        score::cpp::ignore =
            client_handlers_.insert_or_assign(std::move(set_name_obj), std::move(on_changed_parameter_set_callback));
    }
    else if (not on_changed_parameter_set_callback.empty())
    {
        logger_.LogError() << __func__ << " [" << set_name << "]: callback is already set";
        return MakeUnexpected(ConfigProviderError::kCallbackAlreadySet);
    }

    return {};
}

ResultBlank ConfigProviderImpl::CheckParameterSetUpdates() noexcept
{
    logger_.LogDebug() << __func__;

    std::lock_guard<std::mutex> lock{mutex_};
    if (internal_config_provider_ == nullptr)
    {
        logger_.LogError() << __func__ << ": Proxy is not ready";
        return MakeUnexpected(ConfigProviderError::kProxyNotReady, "Proxy is not ready");
    }
    internal_config_provider_->CheckParameterSetUpdates();
    return {};
}

ParameterMap ConfigProviderImpl::FetchInitialParameterSetValuesFrom(
    const IInternalConfigProvider& internal_config_provider)
{
    score::cpp::pmr::vector<score::cpp::pmr::string> set_names{score::cpp::pmr::vector<score::cpp::pmr::string>::allocator_type{memory_resource_}};
    std::lock_guard<std::mutex> lock{mutex_};
    for (const auto& parameter_set : parameter_sets_)
    {
        set_names.push_back(parameter_set.first);
    }

    ParameterMap updated_parameter_sets{ParameterMap::allocator_type{memory_resource_}};
    for (const auto& set_name : set_names)  // LCOV_EXCL_BR_LINE tooling issue
    {
        const auto parameter_set =
            GetParameterSetFromInternalConfigProvider(set_name, internal_config_provider, kDefaultResponseTimeout);
        if (parameter_set.has_value())
        {
            logger_.LogDebug() << __func__ << " [" << set_name << "]: Updated parameter set with value: "
                               << GetParameterSetValue(logger_, *parameter_set.value());
            score::cpp::ignore = updated_parameter_sets.try_emplace(set_name, parameter_set.value());
        }
        else
        {
            logger_.LogError() << __func__ << " [" << set_name << "]: Failed to get parameter set";
        }
    }
    return updated_parameter_sets;
}

void ConfigProviderImpl::WriteInitialParameterSetValuesToPersistentCache(ParameterMap updated_parameter_sets)
{
    logger_.LogDebug() << __func__;

    std::lock_guard<std::mutex> lock{mutex_};
    const auto current_parameter_set_copy = parameter_sets_;
    for (const auto& [key, value] : updated_parameter_sets)
    {
        logger_.LogDebug() << __func__ << ": Cache parameter set " << key;
        persistency_->CacheParameterSet(current_parameter_set_copy, key, value, false);
    }

    persistency_->SyncToStorage();
    if (!updated_parameter_sets.empty())
    {
        parameter_sets_ = std::move(updated_parameter_sets);
        logger_.LogInfo() << __func__ << ": " << parameter_sets_.size() << " parameter sets were updated";
    }
}

void ConfigProviderImpl::RegisterCallbacksForPersistedParameterSetNames()
{
    std::lock_guard<std::mutex> lock{mutex_};
    for (const auto& parameter_set : parameter_sets_)
    {
        const auto& parameter_set_name = parameter_set.first;
        // Register update handler to keep this newly cached parameter set up-to-date.
        // We ignore returned value because we always pass empty callback here which
        // can't trigger error branch inside RegisterUpdateHandlerForParameterSet method
        score::cpp::ignore = RegisterUpdateHandlerForParameterSetName(parameter_set_name, {});
    }
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
