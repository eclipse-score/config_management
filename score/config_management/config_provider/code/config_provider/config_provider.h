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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_H

#include "score/config_management/config_provider/code/config_provider/initial_qualifier_state_types.h"

#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"

#include "score/result/result.h"

#include <score/memory_resource.hpp>
#include <score/stop_token.hpp>
#include <score/unordered_map.hpp>
#include <optional>

namespace score
{
namespace config_management
{
namespace config_provider
{

using OnChangedParameterSetCallback = score::cpp::callback<void(std::shared_ptr<const ParameterSet>)>;
using ParameterSetMap = score::cpp::pmr::unordered_map<score::cpp::pmr::string, Result<std::shared_ptr<const ParameterSet>>>;

class ConfigProvider
{
  public:
    ConfigProvider() = default;

    ConfigProvider(const ConfigProvider&) = delete;
    ConfigProvider(ConfigProvider&&) = delete;

    ConfigProvider& operator=(const ConfigProvider&) & = delete;
    ConfigProvider& operator=(ConfigProvider&&) = delete;

    virtual ~ConfigProvider() noexcept = default;

    /**
     * Gets the parameter set by the set's name
     */
    [[deprecated(
        "SPP_DEPRECATION: This method should be called in "
        "conjunction with a timeout value instead.")]] virtual Result<std::shared_ptr<const ParameterSet>>
    GetParameterSet(const score::cpp::string_view set_name) = 0;
    virtual Result<std::shared_ptr<const ParameterSet>> GetParameterSet(
        const score::cpp::string_view set_name,
        const std::optional<std::chrono::milliseconds> timeout) = 0;

    virtual ParameterSetMap GetParameterSetsByNameList(const score::cpp::pmr::vector<score::cpp::string_view>& set_names,
                                                       const std::optional<std::chrono::milliseconds> timeout) = 0;

    virtual ResultBlank OnChangedInitialQualifierState(InitialQualifierStateNotifierCallbackType&& callback) noexcept = 0;

    virtual ResultBlank OnChangedParameterSet(const std::string& set_name,
                                              OnChangedParameterSetCallback&& callback) noexcept = 0;

    virtual ResultBlank OnChangedParameterSetCbk(std::string_view set_name,
                                                 OnChangedParameterSetCallback&& callback) noexcept = 0;

    [[deprecated(
        "SPP_DEPRECATION: This method should be called in conjunction with a timeout value instead.")]] virtual InitialQualifierState
    GetInitialQualifierState() noexcept = 0;
    [[deprecated(
        "SPP_DEPRECATION: This method should be called in conjunction with a timeout value instead.")]] virtual InitialQualifierState
    GetInitialQualifierState(const std::optional<std::chrono::milliseconds> timeout) noexcept = 0;

    virtual InitialQualifierState GetInitialQualifierState(
        const std::optional<std::chrono::milliseconds> timeout) noexcept = 0;

    virtual bool WaitUntilConnected(const std::chrono::milliseconds timeout,
                                    const score::cpp::stop_token& stop_token) noexcept = 0;
    [[nodiscard]] virtual ResultBlank CheckParameterSetUpdates() noexcept = 0;
    virtual std::size_t GetCachedParameterSetsCount() const noexcept = 0;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_H
