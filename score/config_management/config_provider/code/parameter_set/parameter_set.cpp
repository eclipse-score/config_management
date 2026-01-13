// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
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
#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"

#include "score/json/json_writer.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

ParameterSet::ParameterSet(score::json::Any set_json, score::cpp::pmr::memory_resource* const memory_resource)
    : logger_{mw::log::CreateLogger(std::string_view("CfgP"))},
      set_json_(std::move(set_json)),
      memory_resource_{memory_resource}
{
}

Result<std::reference_wrapper<const score::json::Any>> ParameterSet::GetParameters() const
{
    const auto& set_result = set_json_.As<score::json::Object>();
    if (!set_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to cast JSON set to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& set_obj = set_result.value().get();  // Got Set Object!

    // Find Parameters Json
    const auto parameters_it = set_obj.find("parameters");
    if (parameters_it == set_obj.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to find parameters";
        return MakeUnexpected(ConfigProviderError::kParsingFailed);
    }
    return std::cref(parameters_it->second);  // Got Parameters Json!
}

bool ParameterSet::ContainsSameContent(const ParameterSet& target_parameter_set) const
{
    const auto local_parameters = GetParameters();
    const auto target_parameters = target_parameter_set.GetParameters();
    if (local_parameters.has_value() && target_parameters.has_value())
    {
        if (local_parameters.value().get() == target_parameters.value().get())
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to find parameters from two parameter sets";
        return false;
    }
}

Result<std::reference_wrapper<const score::json::Any>> ParameterSet::GetParameterAsJsonAny(
    const score::cpp::string_view& parameter_name) const
{
    // Acquiring set Object
    const auto& set_result = set_json_.As<score::json::Object>();
    if (!set_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name << "]: "
                           << "Failed to cast JSON set to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& set_obj = set_result.value().get();  // Got Set Object!

    // Find Parameters Json
    const auto parameters_it = set_obj.find("parameters");
    if (parameters_it == set_obj.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name << "]: "
                           << "Failed to find parameters";
        return MakeUnexpected(ConfigProviderError::kParsingFailed);
    }
    const auto& parameters_json = parameters_it->second;  // Got Parameters Json!

    // Acquiring Parameters Object
    const auto& parameters_result = parameters_json.As<json::Object>();
    if (!parameters_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name << "]: "
                           << "Failed to cast JSON parameters to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& parameters_obj = parameters_result.value().get();  // Got Parameters Object!

    // Find Parameter Json
    const auto set_it = parameters_obj.find(parameter_name);
    if (set_it == parameters_obj.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name << "]: "
                           << "Failed to find parameter in set";
        return MakeUnexpected(ConfigProviderError::kParameterNotFound);
    }
    return std::cref(set_it->second);
}

score::Result<std::string> ParameterSet::FormatAsKeyValuePairs() const
{
    return GetParametersAsString();
}

score::Result<std::string> ParameterSet::GetParametersAsString() const
{
    // Acquiring set Object
    const auto& set_result = set_json_.As<score::json::Object>();
    if (!set_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to cast JSON set to object instance";

        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& set_obj = set_result.value().get();  // Got Set Object!

    // Find Parameters Json
    const auto parameters_it = set_obj.find("parameters");
    if (parameters_it == set_obj.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to find parameters";
        return MakeUnexpected(ConfigProviderError::kParsingFailed);
    }
    const auto& parameters_json = parameters_it->second;  // Got Parameters Json!

    return ConvertJsonToString(parameters_json);
}

score::Result<std::string> ParameterSet::ConvertJsonToString(const score::json::Any& json) const
{
    // Acquiring json object
    const auto& json_object_result = json.As<score::json::Object>();
    if (!json_object_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to cast JSON to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& object_data = json_object_result.value().get();  // Got object data!

    score::json::JsonWriter json_writer{};
    auto write_result = json_writer.ToBuffer(object_data);
    // LCOV_EXCL_START (impossible to reach due to JsonWriter internal implementation)
    if (!write_result.has_value())  // LCOV_EXCL_BR_LINE (see comment below)
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to cast JSON to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    // LCOV_EXCL_STOP

    return write_result.value();
}

score::Result<score::config_management::config_daemon::ParameterSetQualifier> ParameterSet::GetQualifier() const
{
    // Acquiring set Object
    const auto& set_result = set_json_.As<score::json::Object>();
    if (!set_result.has_value())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to cast JSON set to object instance";
        return MakeUnexpected(ConfigProviderError::kObjectCastingError);
    }
    const auto& set_obj = set_result.value().get();

    // Find qualifier Json
    const auto qualifier_it = set_obj.find("qualifier");
    if (qualifier_it == set_obj.end())
    {
        logger_.LogError() << "ParameterSet::" << __func__ << ": Failed to find qualifier";
        return MakeUnexpected(ConfigProviderError::kParsingFailed);
    }
    const auto value_result = qualifier_it->second.As<std::uint8_t>();
    if (value_result.has_value() == true)
    {
        const std::uint8_t qualifier = value_result.value();
        if (qualifier <= score::cpp::to_underlying(score::config_management::config_daemon::ParameterSetQualifier::kModified))
        {
            return static_cast<score::config_management::config_daemon::ParameterSetQualifier>(qualifier);
        }
    }
    return MakeUnexpected(ConfigProviderError::kValueCastingError);
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
