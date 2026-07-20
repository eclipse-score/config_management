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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "platform/aas/mw/diag/dtc/dtc.h"
#include <score/string.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ParameterLoader
{
  public:
    ParameterLoader() noexcept = default;
    ParameterLoader(ParameterLoader&&) noexcept = delete;
    ParameterLoader(const ParameterLoader&) noexcept = delete;
    ParameterLoader& operator=(ParameterLoader&&) noexcept = delete;
    ParameterLoader& operator=(const ParameterLoader&) noexcept = delete;
    virtual ~ParameterLoader() noexcept = default;
    virtual bool LoadParameterData(const std::shared_ptr<data_model::IParameterSetCollection> parameter_data) = 0;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_H
