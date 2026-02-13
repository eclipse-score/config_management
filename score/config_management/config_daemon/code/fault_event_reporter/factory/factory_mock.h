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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_MOCK_H

#include "score/config_management/config_daemon/code/fault_event_reporter/factory/factory.h"
#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{
class FactoryMock : public IFactory
{
  public:
    ~FactoryMock() override = default;

    MOCK_METHOD(mw::service::ProxyFuture<std::unique_ptr<IFaultEventProxy>>, CreateFaultEventProxy, (), (override));
};
}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_MOCK_H
