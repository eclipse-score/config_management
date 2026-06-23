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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_PLUGIN_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_PLUGIN_MOCK_H

#include "score/config_management/config_daemon/code/plugins/plugin.h"

#include <gmock/gmock.h>
#include <cstdint>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class PluginMock final : public IPlugin
{
  public:
    ~PluginMock() = default;

    MOCK_METHOD(Result<void>, Initialize, (), (override));
    MOCK_METHOD(void, Deinitialize, (), (noexcept, override));

    MOCK_METHOD(std::int32_t,
                Run,
                (std::shared_ptr<data_model::IParameterSetCollectionManager> parameterset_collection_manager,
                 LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set,
                 InitialQualifierStateSender cbk_update_initial_qualifier_state,
                 score::cpp::stop_token stop_token,
                 std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter),
                (override));
    MOCK_METHOD(Result<void>, ParameterSetCollectionUpdateStart, (data_model::IParameterSetCollection&), (override));
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_PLUGIN_MOCK_H
