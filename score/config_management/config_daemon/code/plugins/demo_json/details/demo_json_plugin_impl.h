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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_DETAILS_DEMO_JSON_PLUGIN_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_DETAILS_DEMO_JSON_PLUGIN_IMPL_H

#include "score/json/i_json_parser.h"
#include "score/json/json_parser.h"
#include "score/mw/log/logger.h"
#include "score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/demo_parameter_loader.h"
#include "score/config_management/config_daemon/code/plugins/plugin.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{

class DemoJsonPluginImpl final : public IPlugin
{
  public:
    explicit DemoJsonPluginImpl(
        std::unique_ptr<score::json::IJsonParser> json_parser = std::make_unique<score::json::JsonParser>()) noexcept;

    DemoJsonPluginImpl(DemoJsonPluginImpl&&) = delete;
    DemoJsonPluginImpl(const DemoJsonPluginImpl&) = delete;

    DemoJsonPluginImpl& operator=(DemoJsonPluginImpl&&) = delete;
    DemoJsonPluginImpl& operator=(const DemoJsonPluginImpl&) = delete;

    ~DemoJsonPluginImpl() noexcept override = default;

    ResultBlank Initialize() override;
    void Deinitialize() noexcept override;

    std::int32_t Run(std::shared_ptr<data_model::IParameterSetCollectionManager> parameterset_collection_manager,
                     LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set,
                     InitialQualifierStateSender cbk_update_initial_qualifier_state,
                     score::cpp::stop_token stop_token,
                     std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter) override;

    ResultBlank ParameterSetCollectionUpdateStart(
        data_model::IParameterSetCollection& parameter_set_collection) override;

  private:
    std::unique_ptr<score::json::IJsonParser> json_parser_;
    mw::log::Logger& logger_;
};

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_DETAILS_DEMO_JSON_PLUGIN_IMPL_H
