// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_SCORE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_SCORE_H

#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"

#include <memory>
#include <utility>

namespace score
{
namespace config_management
{
namespace mw
{
namespace service
{

// Stub ProxyFuture for SCORE/OSS environments
template <typename T>
class ProxyFuture
{
  public:
    ProxyFuture() = default;
    explicit ProxyFuture(T value) : value_(std::move(value)) {}

    T get()
    {
        return std::move(value_);
    }

  private:
    T value_;
};

}  // namespace service
}  // namespace mw

namespace config_daemon
{
namespace fault_event_reporter
{

// In SCORE/OSS environments, IFaultEventProxy is an alias to IFaultEventReporter
// since there's no middleware proxy layer
using IFaultEventProxy = IFaultEventReporter;

class IFactory
{
  public:
    IFactory() = default;
    virtual ~IFactory() = default;
    IFactory(IFactory&&) = delete;
    IFactory(const IFactory&) = delete;

    IFactory& operator=(IFactory&&) & = delete;
    IFactory& operator=(const IFactory&) & = delete;

    // Stub: Returns empty ProxyFuture with nullptr in OSS environments
    virtual mw::service::ProxyFuture<std::unique_ptr<IFaultEventProxy>> CreateFaultEventProxy() = 0;
};

}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_FACTORY_SCORE_H
