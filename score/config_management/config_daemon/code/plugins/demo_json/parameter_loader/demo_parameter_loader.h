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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DEMO_PARAMETER_LOADER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DEMO_PARAMETER_LOADER_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{

class DemoParameterLoader
{
  public:
    DemoParameterLoader() noexcept = default;
    DemoParameterLoader(DemoParameterLoader&&) noexcept = delete;
    DemoParameterLoader(const DemoParameterLoader&) noexcept = delete;
    DemoParameterLoader& operator=(DemoParameterLoader&&) noexcept = delete;
    DemoParameterLoader& operator=(const DemoParameterLoader&) noexcept = delete;
    virtual ~DemoParameterLoader() noexcept = default;

    virtual bool LoadParameterData(
        const std::shared_ptr<data_model::IParameterSetCollection> parameter_set_collection) = 0;
};

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_DEMO_JSON_PARAMETER_LOADER_DEMO_PARAMETER_LOADER_H
