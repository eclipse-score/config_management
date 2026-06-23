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
#include "score/config_management/config_daemon/code/plugins/demo_json/details/demo_json_plugin_impl.h"

#include "score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/details/demo_parameter_loader_impl.h"

#include "score/json/json_parser.h"
#include "score/mw/log/logging.h"

#include <cstdlib>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{
namespace
{
constexpr std::string_view kDemoParametersPath = "etc/demo_parameters.json";
}

DemoJsonPluginImpl::DemoJsonPluginImpl(std::unique_ptr<score::json::IJsonParser> json_parser) noexcept
    : IPlugin{}, json_parser_{std::move(json_parser)}, logger_{mw::log::CreateLogger(std::string_view{"DemJ"})}
{
    logger_.LogInfo() << "DemoJson::" << __func__ << "- Created";
}

Result<void> DemoJsonPluginImpl::Initialize()
{
    return {};
}

void DemoJsonPluginImpl::Deinitialize() noexcept {}

std::int32_t DemoJsonPluginImpl::Run(
    std::shared_ptr<data_model::IParameterSetCollectionManager> parameterset_collection_manager,
    [[maybe_unused]] LastUpdatedParameterSetSender,
    [[maybe_unused]] InitialQualifierStateSender,
    [[maybe_unused]] score::cpp::stop_token,
    [[maybe_unused]] std::shared_ptr<fault_event_reporter::IFaultEventReporter>)
{
    logger_.LogInfo() << "DemoJson::" << __func__ << "Start loading JSON file: " << kDemoParametersPath;
    if (json_parser_ == nullptr)
    {
        json_parser_ = std::make_unique<score::json::JsonParser>();
    }

    DemoParameterLoaderImpl parameter_loader{json_parser_->FromFile(kDemoParametersPath)};
    logger_.LogInfo() << "DemoJson::" << __func__ << "Finished loading JSON file: " << kDemoParametersPath;

    if (!parameter_loader.LoadParameterData(parameterset_collection_manager->GetParameterSetCollection()))
    {
        logger_.LogError() << "DemoJson::" << __func__ << "- Failed to load demo parameters";
        return EXIT_FAILURE;
    }

    logger_.LogInfo() << "DemoJson::" << __func__ << "- Demo parameters loaded";
    return EXIT_SUCCESS;
}

Result<void> DemoJsonPluginImpl::ParameterSetCollectionUpdateStart(
    data_model::IParameterSetCollection& parameter_set_collection)
{
    score::cpp::ignore = parameter_set_collection;
    return {};
}

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
