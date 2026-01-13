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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

enum class FaultEventId : std::uint8_t
{
    kUnkownError,
};

}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H
