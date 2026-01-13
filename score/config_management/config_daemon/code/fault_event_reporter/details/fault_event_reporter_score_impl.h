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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H

#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

class FaultEventReporter : public IFaultEventReporter
{
  public:
    FaultEventReporter() = default;
    FaultEventReporter(const FaultEventReporter&) = delete;
    FaultEventReporter(FaultEventReporter&&) = delete;
    FaultEventReporter& operator=(const FaultEventReporter&) = delete;
    FaultEventReporter& operator=(FaultEventReporter&&) = delete;
    ~FaultEventReporter() override = default;
    void Initialize() override;
    bool Report(const std::uint8_t fault_event_id, [[maybe_unused]] const bool is_fault_present) override;

  private:
};
}  // namespace fault_event_reporter

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H
