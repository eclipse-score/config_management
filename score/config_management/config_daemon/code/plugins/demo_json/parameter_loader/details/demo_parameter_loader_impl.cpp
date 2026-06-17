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
#include "score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/details/demo_parameter_loader_impl.h"

#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"
#include "score/json/internal/model/any.h"

#include <score/string_view.hpp>

#include <string>
#include <utility>

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
constexpr auto kParameterSetsKey = "parameterSets";
constexpr auto kParametersKey = "parameters";
constexpr auto kInitValueKey = "initValue";
}  // namespace

DemoParameterLoaderImpl::DemoParameterLoaderImpl(score::Result<json::Any>&& demo_parameters_data)
    : demo_parameters_data_{std::move(demo_parameters_data)}, logger_{mw::log::CreateLogger(std::string_view{"DemP"})}
{
}

bool DemoParameterLoaderImpl::LoadParameterData(
    const std::shared_ptr<data_model::IParameterSetCollection> parameter_set_collection)
{
    if (parameter_set_collection == nullptr)
    {
        logger_.LogError() << "DemoParameterLoader::" << __func__ << "- parameter_set_collection is null";
        return false;
    }

    if (!demo_parameters_data_.has_value())
    {
        logger_.LogError() << "DemoParameterLoader::" << __func__
                           << "- Failed to parse demo JSON: " << demo_parameters_data_.error().UserMessage();
        return false;
    }

    auto json_root_result = demo_parameters_data_.value().As<score::json::Object>();
    if (!json_root_result.has_value())
    {
        logger_.LogError() << "DemoParameterLoader::" << __func__ << "- Root element is not an object";
        return false;
    }

    auto& json_root = json_root_result.value().get();
    const auto& param_sets_iter = json_root.find(kParameterSetsKey);
    if (param_sets_iter == json_root.end())
    {
        logger_.LogError() << "DemoParameterLoader::" << __func__ << "- Failed to find 'parameterSets' key";
        return false;
    }

    auto param_sets_result = param_sets_iter->second.As<score::json::Object>();
    if (!param_sets_result.has_value())
    {
        logger_.LogError() << "DemoParameterLoader::" << __func__ << "- Value of 'parameterSets' is not an object";
        return false;
    }

    auto& param_sets = param_sets_result.value().get();
    for (auto& param_set : param_sets)
    {
        const auto param_set_sv = param_set.first.GetAsStringView();
        const std::string param_set_name{param_set_sv.data(), param_set_sv.size()};
        auto param_set_obj_result = param_set.second.As<score::json::Object>();
        if (!param_set_obj_result.has_value())
        {
            logger_.LogError() << "DemoParameterLoader::" << __func__
                               << "- Parameter set value is not an object for set: " << param_set_name;
            return false;
        }

        auto& param_set_obj = param_set_obj_result.value().get();
        const auto& parameters_iter = param_set_obj.find(kParametersKey);
        if (parameters_iter == param_set_obj.end())
        {
            logger_.LogError() << "DemoParameterLoader::" << __func__
                               << "- Failed to find 'parameters' key in set: " << param_set_name;
            return false;
        }

        auto parameters_obj_result = parameters_iter->second.As<score::json::Object>();
        if (!parameters_obj_result.has_value())
        {
            logger_.LogError() << "DemoParameterLoader::" << __func__
                               << "- Value of 'parameters' is not an object for set: " << param_set_name;
            return false;
        }

        auto& parameters_obj = parameters_obj_result.value().get();
        for (auto& param : parameters_obj)
        {
            const auto param_sv = param.first.GetAsStringView();
            const std::string param_name{param_sv.data(), param_sv.size()};
            auto param_obj_result = param.second.As<score::json::Object>();
            if (!param_obj_result.has_value())
            {
                logger_.LogError() << "DemoParameterLoader::" << __func__
                                   << "- Parameter value is not an object for set: " << param_set_name
                                   << ", parameter: " << param_name;
                return false;
            }

            auto& param_obj = param_obj_result.value().get();
            const auto init_value_iter = param_obj.find(kInitValueKey);
            if (init_value_iter == param_obj.end())
            {
                logger_.LogError() << "DemoParameterLoader::" << __func__
                                   << "- Failed to find 'initValue' for set: " << param_set_name
                                   << ", parameter: " << param_name;
                return false;
            }

            logger_.LogDebug() << "DemoParameterLoader::" << __func__ << "inserting " << param_set_name
                               << ", parameter: " << param_name;
            const auto insert_res = parameter_set_collection->Insert(
                score::cpp::string_view{param_set_name}, score::cpp::string_view{param_name}, std::move(init_value_iter->second));
            if (!insert_res.has_value())
            {
                logger_.LogError() << "DemoParameterLoader::" << __func__
                                   << "- Insert failed for set: " << param_set_name << ", parameter: " << param_name
                                   << ", error: " << insert_res.error().UserMessage();
                return false;
            }
        }

        const auto qualifier_res = parameter_set_collection->SetParameterSetQualifier(
            score::cpp::string_view{param_set_name}, ParameterSetQualifier::kQualified);
        if (!qualifier_res.has_value())
        {
            logger_.LogError() << "DemoParameterLoader::" << __func__
                               << "- Set qualifier failed for set: " << param_set_name
                               << ", error: " << qualifier_res.error().UserMessage();
            return false;
        }

        const bool calibratable_ok = parameter_set_collection->SetCalibratable(score::cpp::string_view{param_set_name}, true);
        if (!calibratable_ok)
        {
            logger_.LogError() << "DemoParameterLoader::" << __func__
                               << "- SetCalibratable failed for set: " << param_set_name;
            return false;
        }
    }

    return true;
}

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
