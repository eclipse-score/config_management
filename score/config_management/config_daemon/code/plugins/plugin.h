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

#ifndef CODE_PLUGINS_PLUGIN_H
#define CODE_PLUGINS_PLUGIN_H

#include "score/result/result.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include <score/stop_token.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class IPlugin
{
  public:
    explicit IPlugin() = default;
    IPlugin(IPlugin&&) = delete;
    IPlugin(const IPlugin&) = delete;
    IPlugin& operator=(IPlugin&&) = delete;
    IPlugin& operator=(const IPlugin&) = delete;
    virtual ~IPlugin() = default;

    virtual ResultBlank Initialize() = 0;
    virtual void Deinitialize() noexcept = 0;

    virtual std::int32_t Run(std::shared_ptr<data_model::IParameterSetCollection> parameterset_collection,
                             LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set,
                             InitialQualifierStateSender cbk_update_initial_qualifier_state,
                             score::cpp::stop_token stop_token,
                             std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter) = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_PLUGINS_PLUGIN_H
