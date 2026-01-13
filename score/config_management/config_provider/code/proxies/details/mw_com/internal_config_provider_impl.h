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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_IMPL_H

#include "score/config_management/config_daemon/code/services/details/mw_com/generated_service/internal_config_provider_type.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"

#include "score/concurrency/condition_variable.h"

#include "score/json/i_json_parser.h"

#include "score/mw/log/logger.h"

#include <score/jthread.hpp>
#include <score/optional.hpp>
#include <score/unordered_set.hpp>

#include <chrono>
#include <mutex>

namespace score
{
namespace config_management
{
namespace config_provider
{

class InternalConfigProvider final : public IInternalConfigProvider
{
  public:
    using InternalMwComProxy = ::score::mw::com::AsProxy<score::config_management::config_daemon::InternalConfigProviderInterface>;

    explicit InternalConfigProvider(std::unique_ptr<InternalMwComProxy> proxy);

    InternalConfigProvider(const InternalConfigProvider&) = delete;
    InternalConfigProvider(InternalConfigProvider&&) = delete;
    InternalConfigProvider& operator=(const InternalConfigProvider&) & = delete;
    InternalConfigProvider& operator=(InternalConfigProvider&&) = delete;
    ~InternalConfigProvider() noexcept override;

    Result<json::Any> GetParameterSet(const score::cpp::string_view set_name,
                                      const std::chrono::milliseconds timeout) const override;
    bool TrySubscribeToLastUpdatedParameterSetEvent(const score::cpp::stop_token& stop_token,
                                                    OnChangedParameterSetCallback&& callback) override;

    InitialQualifierState GetInitialQualifierState(const std::chrono::milliseconds timeout) const override;

    void StartParameterSetUpdatePollingRoutine(
        score::cpp::optional<std::size_t> max_samples_limit,
        score::cpp::optional<std::chrono::milliseconds> polling_cycle_interval) override;
    void StopParameterSetUpdatePollingRoutine() noexcept override;

    void CheckParameterSetUpdates() noexcept override;

  private:
    /// @brief This method get from proxy last updated samples of parameter sets.
    /// @details Assumption of use.
    /// last_updated_parameter_set_names_mutex_ should be locked before call.
    bool GetLastUpdatedParameterSetNewSamples();

    mw::log::Logger& logger_;
    std::unique_ptr<InternalMwComProxy> proxy_;
    OnChangedParameterSetCallback on_changed_parameter_set_callback_;
    IsAvailableNotificationCallback is_available_notification_callback_;

    std::size_t max_samples_limit_;
    std::chrono::milliseconds polling_cycle_interval_;
    concurrency::InterruptibleConditionalVariable polling_routine_cv_;
    score::cpp::pmr::unordered_set<std::string> last_updated_parameter_set_names_;
    mutable std::mutex mutex_;
    // We intentionally put the jthread as last member since this ensures that upon destruction of our class
    // we first wait for the jthread to finish prior to destroying any other member which it might still access.
    score::cpp::optional<score::cpp::jthread> polling_thread_;
    mutable score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState initial_qualifier_state_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_IMPL_H
