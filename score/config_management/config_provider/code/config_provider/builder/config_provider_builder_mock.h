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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_MOCK_H

#include "score/config_management/config_provider/code/config_provider/builder/config_provider_builder.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
namespace score
{
namespace config_management
{
namespace config_provider
{
using ::testing::_;
using ::testing::ReturnRef;

class ConfigProviderBuilderMock final : public ConfigProviderBuilder
{
  public:
    ConfigProviderBuilderMock()
    {
        ON_CALL(*this, WithConnectionTimeout(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithRequiredParameterSets(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithMaxSamplesLimit(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithPollingCycleInterval(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithPersistency(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithMemoryResource(_)).WillByDefault(ReturnRef(*this));
        ON_CALL(*this, WithAvailabilityNotificationCallback(_)).WillByDefault(ReturnRef(*this));
    }
    ~ConfigProviderBuilderMock() noexcept override = default;

    MOCK_METHOD(ConfigProviderBuilder&, WithConnectionTimeout, (std::chrono::milliseconds timeout), (override));
    MOCK_METHOD(ConfigProviderBuilder&,
                WithRequiredParameterSets,
                (score::cpp::pmr::vector<std::string_view> initial_parameter_set_name_list),
                (override));
    MOCK_METHOD(ConfigProviderBuilder&, WithMaxSamplesLimit, (std::size_t max_samples_limit), (override));
    MOCK_METHOD(ConfigProviderBuilder&,
                WithPollingCycleInterval,
                (std::chrono::milliseconds polling_cycle_interval),
                (override));
    MOCK_METHOD(ConfigProviderBuilder&, WithPersistency, (score::cpp::pmr::unique_ptr<Persistency> persistency), (override));
    MOCK_METHOD(ConfigProviderBuilder&,
                WithMemoryResource,
                (score::cpp::pmr::memory_resource* const memory_resource),
                (override));
    MOCK_METHOD(ConfigProviderBuilder&,
                WithAvailabilityNotificationCallback,
                (AvailabilityNotificationCallback callback),
                (override));
    MOCK_METHOD(score::cpp::pmr::unique_ptr<ConfigProvider>, Build, (score::cpp::stop_token token), (override));
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_BUILDER_CONFIG_PROVIDER_BUILDER_MOCK_H
