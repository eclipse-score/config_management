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

#include "score/config_management/config_daemon/code/fault_event_reporter/factory/details/factory_score_impl.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/details/fault_event_reporter_score_impl.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

mw::service::ProxyFuture<std::unique_ptr<IFaultEventProxy>> Factory::CreateFaultEventProxy()
{
    // Stub implementation for OSS/SCORE: Return ProxyFuture with FaultEventReporter stub
    // In open-source environments, the fault event service is not available via middleware,
    // so we return a local stub implementation that does minimal/no-op reporting
    return mw::service::ProxyFuture<std::unique_ptr<IFaultEventProxy>>(std::make_unique<FaultEventReporter>());
}

}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
