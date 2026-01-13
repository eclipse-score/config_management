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
#include "score/config_management/config_provider/code/proxies/details/mw_com/internal_config_provider_impl.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "score/concurrency/future/interruptible_promise.h"
#include "score/json/json_parser.h"

#include <sstream>

namespace score
{
namespace config_management
{
namespace config_provider
{

namespace
{
constexpr std::size_t kDefaultMaxSamplesLimit{500U};
constexpr std::chrono::seconds kDefaultPollingCycleInterval{5U};

/* KW_SUPPRESS_START:MISRA.LINKAGE.EXTERN: false positive */
InitialQualifierState Convert(const score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState value)
{
    // Suppress "AUTOSAR C++14 M6-4-5" and "AUTOSAR C++14 M6-4-3", The rule states: An unconditional throw or break
    // statement shall terminate every nonempty switch-clause." and "A switch statement shall be a well-formed
    // switch statement.", respectively.
    // Rationale: The `return` statements in this case clause unconditionally exits the switch case, making an
    // additional `break` statement redundant.
    // coverity[autosar_cpp14_m6_4_3_violation] See above
    switch (value)
    {
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kDefault:
            return InitialQualifierState::kDefault;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kInProgress:
            return InitialQualifierState::kInProgress;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kQualified:
            return InitialQualifierState::kQualified;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kQualifying:
            return InitialQualifierState::kQualifying;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kUnqualified:
            return InitialQualifierState::kUnqualified;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        case score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState::kUndefined:
            return InitialQualifierState::kUndefined;
        // coverity[autosar_cpp14_m6_4_5_violation] Return will terminate this switch clause
        default:
            return InitialQualifierState::kUndefined;
    }
}
/* KW_SUPPRESS_END:MISRA.LINKAGE.EXTERN */
}  // namespace

InternalConfigProvider::InternalConfigProvider(std::unique_ptr<InternalMwComProxy> proxy)
    : IInternalConfigProvider{},
      logger_{mw::log::CreateLogger(std::string_view{"CfgP"})},
      proxy_{std::move(proxy)},
      is_available_notification_callback_{},
      max_samples_limit_{kDefaultMaxSamplesLimit},
      polling_cycle_interval_{kDefaultPollingCycleInterval}
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__;
    /* KW_SUPPRESS_START:MISRA.USE.EXPANSION: Macro for assertion is tolerated by decision*/
    SCORE_LANGUAGE_FUTURECPP_ASSERT_PRD(proxy_ != nullptr);
    /* KW_SUPPRESS_END:MISRA.USE.EXPANSION */
    proxy_->initial_qualifier_state.Subscribe(1);
}

InternalConfigProvider::~InternalConfigProvider() noexcept
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__;
    polling_thread_.reset();
    if (proxy_ != nullptr)  // LCOV_EXCL_BR_LINE (impossible to reach the false case in unit test)
    {
        proxy_->last_updated_parameterset.Unsubscribe();
    }
}

Result<json::Any> InternalConfigProvider::GetParameterSet(const score::cpp::string_view set_name,
                                                          const std::chrono::milliseconds timeout) const
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__ << "[" << set_name << "]: timeout: " << timeout;
    (void)set_name;
    (void)timeout;
    return {};
}

bool InternalConfigProvider::TrySubscribeToLastUpdatedParameterSetEvent(const score::cpp::stop_token& stop_token,
                                                                        OnChangedParameterSetCallback&& callback)
{
    (void)stop_token;
    logger_.LogDebug() << "InternalConfigProvider::" << __func__;
    std::unique_lock<std::mutex> lock{mutex_};
    score::cpp::ignore = proxy_->last_updated_parameterset.Subscribe(2);
    on_changed_parameter_set_callback_ = std::move(callback);

    return true;
}

InitialQualifierState InternalConfigProvider::GetInitialQualifierState(const std::chrono::milliseconds timeout) const
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__ << "timeout: " << timeout;

    std::unique_lock<std::mutex> lock{mutex_};

    if (proxy_ != nullptr)
    {
        logger_.LogDebug() << "GetLatestReceivedInitialQualifierState";
        if ((proxy_->initial_qualifier_state.GetNumNewSamplesAvailable().has_value()) &&
            (proxy_->initial_qualifier_state.GetNumNewSamplesAvailable().value() > 0))
        {
            logger_.LogDebug() << " InternalConfigProviderProxy subscribed update";
            logger_.LogDebug() << proxy_->initial_qualifier_state.GetNumNewSamplesAvailable().value();
            score::cpp::ignore = proxy_->initial_qualifier_state.GetNewSamples(
                [&](const auto& sample) noexcept {
                    if (sample)
                    {
                        logger_.LogDebug() << " InternalConfigProviderProxy found value for LastUpdaterParameterSet";
                        initial_qualifier_state_ = *sample;
                    }
                },
                1U);
        }
    }

    lock.unlock();

    const auto value_converted = Convert(initial_qualifier_state_);
    logger_.LogInfo() << "InternalConfigProvider::" << __func__ << ": InitialQualifierState: "
                      << static_cast<std::underlying_type_t<InitialQualifierState>>(value_converted);
    return value_converted;
}

void InternalConfigProvider::StartParameterSetUpdatePollingRoutine(
    score::cpp::optional<std::size_t> max_samples_limit,
    score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval)
{
    const std::lock_guard<std::mutex> lock{mutex_};
    if (polling_thread_.has_value() && polling_thread_->joinable())
    {
        logger_.LogWarn() << "InternalConfigProvider::" << __func__ << ": Routine already in progress";
        return;
    }

    max_samples_limit_ = max_samples_limit.value_or(kDefaultMaxSamplesLimit);
    polling_cycle_interval_ = polling_cycle_interval.value_or(kDefaultPollingCycleInterval);

    logger_.LogDebug() << "InternalConfigProvider::" << __func__ << "max_samples_limit: " << max_samples_limit_
                       << ", polling_cycle_interval: " << polling_cycle_interval_;
    SCORE_LANGUAGE_FUTURECPP_ASSERT_PRD_MESSAGE(max_samples_limit_ > 0U,
                           "InternalConfigProvider::OnChangedParameterSet() max_samples_limit must not be zero");
    SCORE_LANGUAGE_FUTURECPP_ASSERT_PRD_MESSAGE(polling_cycle_interval_ > std::chrono::milliseconds{0},
                           "InternalConfigProvider::OnChangedParameterSet() polling_cycle_interval must not be zero");

    last_updated_parameter_set_names_.reserve(max_samples_limit_);

    polling_thread_ = score::cpp::jthread([this](const score::cpp::stop_token& stop_token) {
        std::unique_lock<std::mutex> polling_thread_lock{mutex_};
        while (not stop_token.stop_requested())
        {
            if (GetLastUpdatedParameterSetNewSamples())  // LCOV_EXCL_BR_LINE (the only 2 branches are covered in test)
            {
                decltype(last_updated_parameter_set_names_) parameter_set_names{};
                last_updated_parameter_set_names_.swap(parameter_set_names);
                polling_thread_lock.unlock();
                for (const auto& parameter_set_name : parameter_set_names)
                {
                    if (stop_token.stop_requested())
                    {
                        break;
                    }
                    on_changed_parameter_set_callback_(parameter_set_name);
                }
                polling_thread_lock.lock();
            }
            score::cpp::ignore = polling_routine_cv_.wait_for(
                polling_thread_lock, stop_token, polling_cycle_interval_, [this]() noexcept -> bool {
                    return not(last_updated_parameter_set_names_.empty());
                });
        }
    });
}

void InternalConfigProvider::StopParameterSetUpdatePollingRoutine() noexcept
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__;
    if (polling_thread_.has_value())
    {
        score::cpp::ignore = polling_thread_->request_stop();
        polling_thread_.reset();
    }
}

void InternalConfigProvider::CheckParameterSetUpdates() noexcept
{
    logger_.LogDebug() << "InternalConfigProvider::" << __func__;

    const std::unique_lock<std::mutex> lock{mutex_};
    if (GetLastUpdatedParameterSetNewSamples())
    {
        polling_routine_cv_.notify_one();
    }
}

bool InternalConfigProvider::GetLastUpdatedParameterSetNewSamples()
{
    /// @brief This method get from proxy last updated samples of parameter sets.
    /// @details Assumption of use.
    /// mutex_ should be locked before call.

    logger_.LogDebug() << "InternalConfigProvider::" << __func__;

    if (on_changed_parameter_set_callback_.empty())
    {
        logger_.LogWarn() << "InternalConfigProvider::" << __func__ << ": Callback empty";
        return false;
    }

    const auto callback{[this](auto sample_ptr) {
        // move used to clear cache in which it calls reset method to return memory_ptr_ to backend
        const auto value = std::move(sample_ptr);
        const std::string set_name{value->begin(), std::find(value->begin(), value->end(), 0)};
        score::cpp::ignore = last_updated_parameter_set_names_.insert(set_name);
    }};
    SCORE_LANGUAGE_FUTURECPP_PRECONDITION(max_samples_limit_ >= last_updated_parameter_set_names_.size());
    const std::size_t free_slots_in_samples_container = max_samples_limit_ - last_updated_parameter_set_names_.size();
    const auto get_new_samples_result =
        proxy_->last_updated_parameterset.GetNewSamples(callback, free_slots_in_samples_container);
    if (not get_new_samples_result.has_value())
    {
        logger_.LogError() << "InternalConfigProvider::" << __func__
                           << ": Failed to retrieve LastUpdatedParameterSet event samples: "
                           << get_new_samples_result.error().Message();
        return false;
    }
    if (!last_updated_parameter_set_names_.empty())
    {
        std::stringstream sstr;  // LCOV_EXCL_LINE tooling issue

        sstr << "[";
        for (const auto& f : last_updated_parameter_set_names_)
        {
            sstr << f << ", ";
        }
        score::cpp::ignore = sstr.seekp(-2, std::ios::cur);
        sstr << "]";
        logger_.LogInfo() << "InternalConfigProvider::" << __func__ << ": values: " << sstr.str();
    }
    return true;
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
