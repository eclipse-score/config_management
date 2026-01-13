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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_MOCK_H

#include "score/config_management/config_provider/code/config_provider/config_provider.h"

#include "score/result/result.h"

#include <score/memory.hpp>

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_provider
{

class ConfigProviderMock final : public ConfigProvider
{
  public:
    ConfigProviderMock();
    ~ConfigProviderMock() noexcept override = default;

    MOCK_METHOD(Result<std::shared_ptr<const ParameterSet>>,
                GetParameterSet,
                (const score::cpp::string_view set_name),
                (override));
    MOCK_METHOD(Result<std::shared_ptr<const ParameterSet>>,
                GetParameterSet,
                (const score::cpp::string_view set_name, const std::optional<std::chrono::milliseconds> timeout),
                (override));
    MOCK_METHOD(ParameterSetMap,
                GetParameterSetsByNameList,
                (const score::cpp::pmr::vector<score::cpp::string_view>& set_names,
                 const std::optional<std::chrono::milliseconds> timeout),
                (override));
    MOCK_METHOD(ResultBlank, OnChangedInitialQualifierState, (InitialQualifierStateNotifierCallbackType&&), (noexcept, override));
    MOCK_METHOD(ResultBlank,
                OnChangedParameterSet,
                (const std::string& set_name, OnChangedParameterSetCallback&& callback),
                (noexcept, override));
    MOCK_METHOD(ResultBlank,
                OnChangedParameterSetCbk,
                (std::string_view set_name, OnChangedParameterSetCallback&& callback),
                (noexcept, override));
    MOCK_METHOD(InitialQualifierState, GetInitialQualifierState, (), (noexcept, override));
    MOCK_METHOD(InitialQualifierState, GetInitialQualifierState, (const std::optional<std::chrono::milliseconds> timeout), (noexcept, override));
    MOCK_METHOD(InitialQualifierState,
                GetInitialQualifierState,
                (const std::optional<std::chrono::milliseconds> timeout),
                (noexcept, override));
    MOCK_METHOD(ResultBlank, CheckParameterSetUpdates, (), (noexcept, override));
    MOCK_METHOD(bool,
                WaitUntilConnected,
                (const std::chrono::milliseconds, const score::cpp::stop_token&),
                (noexcept, override));
    MOCK_METHOD(std::size_t, GetCachedParameterSetsCount, (), (const, noexcept, override));

  private:
    std::shared_ptr<const ParameterSet> parameter_set_;
    score::json::Any root_json_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_CONFIG_PROVIDER_MOCK_H
