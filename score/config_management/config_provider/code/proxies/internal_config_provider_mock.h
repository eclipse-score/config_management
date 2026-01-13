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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_MOCK_H

#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_provider
{

class InternalConfigProviderMock final : public IInternalConfigProvider
{
  public:
    ~InternalConfigProviderMock() noexcept override = default;

    MOCK_METHOD(Result<json::Any>,
                GetParameterSet,
                (const score::cpp::string_view, const std::chrono::milliseconds),
                (const, override));
    MOCK_METHOD(bool,
                TrySubscribeToLastUpdatedParameterSetEvent,
                (const score::cpp::stop_token&, OnChangedParameterSetCallback&& callback),
                (override));

    MOCK_METHOD(InitialQualifierState, GetInitialQualifierState, (const std::chrono::milliseconds), (const, override));
    MOCK_METHOD(void,
                StartParameterSetUpdatePollingRoutine,
                (score::cpp::optional<std::size_t>, score::cpp::optional<std::chrono::milliseconds>),
                (noexcept, override));
    MOCK_METHOD(void, StopParameterSetUpdatePollingRoutine, (), (noexcept, override));
    MOCK_METHOD(void, CheckParameterSetUpdates, (), (noexcept, override));
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PROXIES_INTERNAL_CONFIG_PROVIDER_MOCK_H
