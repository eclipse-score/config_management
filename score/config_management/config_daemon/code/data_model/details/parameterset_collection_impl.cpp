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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/details/common.h"
#include "score/config_management/config_daemon/code/data_model/details/parameter_set_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"

#include "score/json/internal/model/any.h"
#include "score/json/json_parser.h"
#include "score/json/json_writer.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

ParameterSetCollection::ParameterSetCollection()
    : IParameterSetCollection{}, logger_{mw::log::CreateLogger(std::string_view{"DtMd"})}, mutex_{}, parameter_sets_{}
{
}

ResultBlank ParameterSetCollection::Insert(const score::cpp::string_view set_name,
                                           const score::cpp::string_view parameter_name,
                                           json::Any&& parameter_value) noexcept
{
    logger_.LogDebug() << "ParameterSetCollection::" << __func__ << "set_name:" << set_name
                       << "parameter_name:" << parameter_name;

    const std::lock_guard<std::mutex> lock{mutex_};

    std::shared_ptr<ParameterSet> parameter_set;
    auto result = parameter_sets_.find(AsString(set_name));

    if (result != parameter_sets_.end())
    {
        parameter_set = result->second;
    }
    else
    {
        parameter_set = std::make_shared<ParameterSet>(std::make_unique<json::JsonWriter>());
        score::cpp::ignore = parameter_sets_.emplace(AsString(set_name), parameter_set);
    }

    return parameter_set->Add(parameter_name, std::move(parameter_value));
}

Result<score::cpp::pmr::string> ParameterSetCollection::GetParameterSet(const std::string set_name) const
{
    const std::lock_guard<std::mutex> lock{mutex_};

    const auto parameter_set = Find(set_name);
    if (parameter_set.has_value() == true)
    {
        return parameter_set.value()->GetParameterSetAsString();
    }
    return MakeUnexpected<score::cpp::pmr::string>(parameter_set.error());
}

Result<json::Any> ParameterSetCollection::GetParameterFromSet(const score::cpp::string_view set_name,
                                                              const score::cpp::string_view parameter_name) const
{
    const std::lock_guard<std::mutex> lock{mutex_};

    const auto parameter_set = Find(set_name);
    if (parameter_set.has_value() == true)
    {
        return parameter_set.value()->GetParameter(parameter_name);
    }
    return MakeUnexpected<json::Any>(parameter_set.error());
}

Result<std::shared_ptr<ParameterSet>> ParameterSetCollection::Find(const score::cpp::string_view set_name) const noexcept
{
    logger_.LogDebug() << "ParameterSetCollection::" << __func__;

    auto result = parameter_sets_.find(AsString(set_name));
    if (result == parameter_sets_.end())
    {
        logger_.LogWarn() << "ParameterSetCollection::" << __func__ << "ParameterSet with name:" << set_name
                          << "doesn't exist";
        return MakeUnexpected(DataModelError::kParameterSetNotFound);
    }

    return result->second;
}

ResultBlank ParameterSetCollection::UpdateParameterSet(const score::cpp::string_view set_name, const score::cpp::string_view set)
{
    const std::lock_guard<std::mutex> lock{mutex_};

    const json::JsonParser json_parser{};
    const std::string buffer{set.begin(), set.end()};
    auto parsing_result = json_parser.FromBuffer(buffer);
    if (!parsing_result.has_value())
    {
        logger_.LogError() << "ParameterSetCollection::" << __func__
                           << "Can't parse input set data as json format with error: "
                           << parsing_result.error().Message();
        return MakeUnexpected(DataModelError::kParsingError, "Can't parse input set data as json format");
    }

    auto set_object_result = parsing_result.value().As<json::Object>();
    if (!set_object_result.has_value())
    {
        logger_.LogError() << "ParameterSetCollection::" << __func__ << "set data:" << set_name
                           << ", expected to be object json formatted";
        return MakeUnexpected(DataModelError::kParsingError, "Set data expected to be object json formatted");
    }

    const auto set_data = Find(set_name);
    if (set_data.has_value() == false)
    {
        logger_.LogError() << "ParameterSetCollection::" << __func__ << "ParameterSet with name:" << set_name
                           << "doesn't exist";
        return MakeUnexpected(DataModelError::kParameterSetNotFound, "Parameter set is not found");
    }

    return (*set_data)->Update(std::move(set_object_result.value().get()));
}

bool ParameterSetCollection::SetCalibratable(const score::cpp::string_view set_name, const bool is_calibratable) const noexcept
{
    const std::lock_guard<std::mutex> lock{mutex_};

    bool result = false;

    const auto found_parameter_set = Find(set_name);

    if (found_parameter_set.has_value() == true)
    {
        (*found_parameter_set)->SetCalibratable(is_calibratable);
        result = true;
    }

    return result;
}

score::Result<score::config_management::config_daemon::ParameterSetQualifier> ParameterSetCollection::GetParameterSetQualifier(
    const score::cpp::string_view set_name) const
{
    const std::lock_guard<std::mutex> lock{mutex_};
    const auto parameter_set = Find(set_name);
    if (parameter_set.has_value() == true)
    {
        return parameter_set.value()->GetQualifier();
    }
    logger_.LogError() << "ParameterSetCollection::" << __func__ << "ParameterSet with name:" << set_name
                       << "doesn't exist";
    return MakeUnexpected(DataModelError::kParameterSetNotFound, "Parameter set not found");
}

ResultBlank ParameterSetCollection::SetParameterSetQualifier(
    const score::cpp::string_view set_name,
    const score::config_management::config_daemon::ParameterSetQualifier qualifier)
{
    const std::lock_guard<std::mutex> lock{mutex_};
    const auto parameter_set = Find(set_name);
    if (parameter_set.has_value() == true)
    {
        parameter_set.value()->SetQualifier(qualifier);
        return {};
    }
    logger_.LogError() << "ParameterSetCollection::" << __func__ << "ParameterSet with name:" << set_name
                       << "doesn't exist";
    return MakeUnexpected(DataModelError::kParameterSetNotFound, "Parameter set not found");
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
