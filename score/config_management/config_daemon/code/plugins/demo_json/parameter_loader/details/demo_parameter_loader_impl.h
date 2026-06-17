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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DETAILS_DEMO_PARAMETER_LOADER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DETAILS_DEMO_PARAMETER_LOADER_IMPL_H

#include "score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/demo_parameter_loader.h"
#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include "score/json/internal/model/any.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{

class DemoParameterLoaderImpl final : public DemoParameterLoader
{
  public:
    explicit DemoParameterLoaderImpl(score::Result<json::Any>&& demo_parameters_data);

    DemoParameterLoaderImpl(DemoParameterLoaderImpl&&) = delete;
    DemoParameterLoaderImpl(const DemoParameterLoaderImpl&) = delete;

    DemoParameterLoaderImpl& operator=(DemoParameterLoaderImpl&&) = delete;
    DemoParameterLoaderImpl& operator=(const DemoParameterLoaderImpl&) = delete;

    ~DemoParameterLoaderImpl() override = default;

    bool LoadParameterData(
        const std::shared_ptr<data_model::IParameterSetCollection> parameter_set_collection) override;

  private:
    score::Result<json::Any> demo_parameters_data_;
    mw::log::Logger& logger_;
};

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DETAILS_DEMO_PARAMETER_LOADER_IMPL_H
