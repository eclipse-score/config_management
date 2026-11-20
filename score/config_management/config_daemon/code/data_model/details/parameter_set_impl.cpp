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

#include "score/config_management/config_daemon/code/data_model/details/parameter_set_impl.h"
#include "score/config_management/config_daemon/code/data_model/details/common.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/config_management/lib/parameter_set_json_serializer/details/parameter_set_json_serializer_impl.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

ParameterSet::ParameterSet()
    : logger_{mw::log::CreateLogger(std::string_view("DtMd"))},
      data_{},
      json_serializer_{std::make_unique<score::config_management::ParameterSetJsonSerializerImpl>()},
      qualifier_{},
      is_calibratable_{false}
{
}

score::Result<void> ParameterSet::Add(const score::cpp::string_view parameter_name, score::json::Any&& parameter_value)
{
    Parameter parameter;
    parameter.SetValue(std::move(parameter_value));

    const bool inserted = data_.try_emplace(AsString(parameter_name), std::move(parameter)).second;
    if (inserted)
    {
        logger_.LogDebug() << __func__ << "parameter with name:" << parameter_name << "added";
    }
    else
    {
        logger_.LogError() << "ParameterSet::" << __func__ << "parameter with name: " << parameter_name
                           << "already exists in parameter set";
        return score::MakeUnexpected(DataModelError::kParameterAlreadyExists,
                                     "Parameter already exist in parameter set");
    }
    return score::Result<void>{};
}

bool ParameterSet::InsertOrAssign(const score::cpp::string_view parameter_name, score::json::Any&& parameter_value)
{
    Parameter parameter;
    parameter.SetValue(std::move(parameter_value));

    const bool inserted = data_.insert_or_assign(AsString(parameter_name), std::move(parameter)).second;
    logger_.LogDebug() << "ParameterSet::" << __func__ << "parameter with name:" << parameter_name
                       << (inserted ? "inserted" : "assigned");
    return inserted;
}

std::size_t ParameterSet::GetParameterCount() const noexcept
{
    return data_.size();
}

score::Result<void> ParameterSet::Update(score::json::Object&& parameters)
{
    // check if the parameter set is calibratable
    if (is_calibratable_)
    {
        // check if any input parameters is not found
        // and if so, the whole update request will be reject
        auto all_parameters_exist = true;
        for (const auto& param : parameters)
        {
            const auto parameter_name = AsString(param.first.GetAsStringView());
            if (data_.find(parameter_name) == data_.end())
            {
                all_parameters_exist = false;
                logger_.LogError() << "ParameterSet::" << __func__ << "parameter with name:" << parameter_name
                                   << "doesn't exist";
                break;
            }
        }

        if (all_parameters_exist)
        {
            for (auto& param : parameters)
            {
                const auto parameter_name = AsString(param.first.GetAsStringView());
                data_[parameter_name].SetValue(std::move(param.second));
                logger_.LogInfo() << __func__ << "parameter with name:" << parameter_name << "updated";
            }
            return score::Result<void>{};
        }
        else
        {
            return score::MakeUnexpected(DataModelError::kParametersNotFound, "Some parameters are not found");
        }
    }
    else
    {
        return score::MakeUnexpected(DataModelError::kParameterSetNotCalibratable, "ParameterSet is not calibratable");
    }
}

score::Result<score::cpp::pmr::string> ParameterSet::GetParameterSetAsString() const
{
    return json_serializer_->SerializeParameterSet(GetParametersAsJson(), score::cpp::to_underlying(qualifier_));
}

score::Result<score::json::Any> ParameterSet::GetParameter(const score::cpp::string_view parameter_name)
{
    auto iter = data_.find(AsString(parameter_name));
    if (iter == data_.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << "parameter with name: " << parameter_name
                           << "does not exist";
        return score::MakeUnexpected<score::json::Any>(DataModelError::kParameterMissedError);
    }
    else
    {
        return iter->second.GetValue().CloneByValue();
    }
}

score::json::Object ParameterSet::GetParametersAsJson() const
{
    score::json::Object parameters;
    for (const auto& parameter : data_)
    {
        parameters[parameter.first.c_str()] = parameter.second.GetValue().CloneByValue();
    }
    return parameters;
}

score::json::Object ParameterSet::GetParameterSetAsJson() const
{
    score::json::Object parameter_set;
    parameter_set["parameters"] = GetParametersAsJson();
    score::json::Any qualifier{score::cpp::to_underlying(qualifier_)};
    parameter_set["qualifier"] = std::move(qualifier);

    return parameter_set;
}

void ParameterSet::SetCalibratable(const bool is_calibratable)
{
    is_calibratable_ = is_calibratable;
}

void ParameterSet::SetQualifier(const ParameterSetQualifier qualifier)
{
    qualifier_ = qualifier;
}

ParameterSetQualifier ParameterSet::GetQualifier() const
{
    return qualifier_;
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
