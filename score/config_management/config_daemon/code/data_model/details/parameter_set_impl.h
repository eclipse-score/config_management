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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_SET_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_SET_IMPL_H

#include "score/config_management/config_daemon/code/data_model/details/parameter_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"

#include "score/json/i_json_writer.h"
#include "score/json/internal/model/any.h"
#include "score/mw/log/logger.h"

#include <score/optional.hpp>
#include <score/string.hpp>

#include <mutex>
#include <unordered_map>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

class ParameterSet final
{
  public:
    explicit ParameterSet(std::unique_ptr<json::IJsonWriter> json_writer);

    ~ParameterSet() = default;
    ParameterSet(ParameterSet&&) = delete;
    ParameterSet(const ParameterSet&) = delete;

    ParameterSet& operator=(ParameterSet&&) = delete;
    ParameterSet& operator=(const ParameterSet&) = delete;

    Result<score::cpp::pmr::string> GetParameterSetAsString() const;
    ResultBlank Add(const score::cpp::string_view parameter_name, json::Any&& parameter_value);
    ResultBlank Update(json::Object&& parameters);
    void SetCalibratable(const bool is_calibratable);
    void SetQualifier(const score::config_management::config_daemon::ParameterSetQualifier qualifier);
    score::config_management::config_daemon::ParameterSetQualifier GetQualifier() const;
    Result<json::Any> GetParameter(const score::cpp::string_view parameter_name);

  private:
    json::Object GetParameterSetAsJson() const;

    mw::log::Logger& logger_;
    std::unordered_map<score::cpp::pmr::string, Parameter> data_;
    std::unique_ptr<json::IJsonWriter> json_writer_;
    score::config_management::config_daemon::ParameterSetQualifier qualifier_;
    bool is_calibratable_;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_SET_IMPL_H
