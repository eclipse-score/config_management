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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_DETAILS_FACTORY_SCORE_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_DETAILS_FACTORY_SCORE_IMPL_H

#include "score/config_management/config_daemon/code/fault_event_reporter/factory/factory_score.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

/**
 * @brief SCORE/OSS stub implementation of Factory
 *
 * This is a minimal stub implementation for open-source environments
 * where SCORE middleware services are not available.
 */
class Factory final : public IFactory
{
  public:
    Factory() = default;
    ~Factory() override = default;
    Factory(Factory&&) = delete;
    Factory(const Factory&) = delete;

    Factory& operator=(Factory&&) & = delete;
    Factory& operator=(const Factory&) & = delete;

    /**
     * @brief Create a stub FaultEventProxy
     *
     * @return Empty ProxyFuture with nullptr (no fault event service available in SCORE/OSS)
     */
    mw::service::ProxyFuture<std::unique_ptr<IFaultEventProxy>> CreateFaultEventProxy() override;
};

}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FACTORY_DETAILS_FACTORY_SCORE_IMPL_H
