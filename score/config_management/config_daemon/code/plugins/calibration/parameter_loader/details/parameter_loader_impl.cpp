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
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details/parameter_loader_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_score_types.h"
#include "score/config_management/config_daemon/code/json_helper/json_helper.h"
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/error/error.h"
#include "score/json/internal/model/any.h"
#include "score/json/json_writer.h"
#include "score/mw/log/logging.h"
#include <memory>
#include <sstream>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{
using FaultEventId = score::config_management::config_daemon::fault_event_reporter::FaultEventId;

namespace
{
constexpr auto kParameterSetsKey = "parameterSets";
constexpr auto kCodingDependencyKey = "codingDependency";
constexpr auto kInitValueKey = "initValue";
constexpr auto kCodingParamValuesKey = "codingParamValues";
constexpr auto kCodingParamNameKey = "codingParamName";
constexpr auto kContainsDefaultValue = "containsDefaultValue";
constexpr auto kParametersKey = "parameters";

}  // namespace

ParameterLoaderImpl::ParameterLoaderImpl(
    std::unique_ptr<score::Result<json::Any>> calibration_data,
    const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter,
    std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error,
    std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use)
    : ParameterLoader(),
      calibration_data_(std::move(calibration_data)),
      parameter_set_mapping_(parameter_set_mapping),
      fault_event_reporter_(std::move(fault_event_reporter)),
      dtc_integrity_error_{std::move(dtc_integrity_error)},
      dtc_default_values_in_use_{std::move(dtc_default_values_in_use)},
      parameter_sets_default_in_use_error_{false},
      parameter_sets_integrity_error_{false},
      logger_{mw::log::CreateLogger(std::string_view{"PaLo"})}
{
    logger_.LogInfo() << "ParameterLoader::ParameterLoader - Created";
}

bool ParameterLoaderImpl::LoadParameterData(const std::shared_ptr<data_model::IParameterSetCollection> parameter_data)
{
    parameter_data_ = parameter_data;

    logger_.LogInfo() << "ParameterLoader::" << __func__ << " - Start loading data JSON object";
    if (calibration_data_ == nullptr)
    {
        SetIntegrityErrorDtcsToFailed();
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Calibration data is nullptr ";
        return false;
    }
    if (!calibration_data_->has_value())
    {
        SetIntegrityErrorDtcsToFailed();
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - JSON object is invalid: " << calibration_data_->error();
        return false;
    }
    auto json_root_result = calibration_data_->value().As<score::json::Object>();
    if (!json_root_result.has_value())
    {
        SetIntegrityErrorDtcsToFailed();
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Root element is not an object.";
        return false;
    }

    auto& json_root = json_root_result.value().get();
    const auto& param_sets_obj_iter = json_root.find(kParameterSetsKey);
    if (param_sets_obj_iter == json_root.end())
    {
        SetIntegrityErrorDtcsToFailed();
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Failed to find 'parameterSets' key.";
        return false;
    }
    auto param_sets_result = param_sets_obj_iter->second.As<json::Object>();
    if (!param_sets_result.has_value())
    {
        SetIntegrityErrorDtcsToFailed();
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Value of 'parameterSets' is not an object.";
        return false;
    }

    LoadParameterSets(param_sets_result.value().get());

    SetDtcs();
    logger_.LogInfo() << "ParameterLoader::" << __func__ << " - Finished loading data JSON object";
    return true;
}

void ParameterLoaderImpl::SetIntegrityErrorDtcsToFailed() noexcept
{
    if (fault_event_reporter_ != nullptr &&
        !fault_event_reporter_->Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), true))
    {
        logger_.LogError() << "Failed to report kCalibrationPluginSwError";
    }
    if (dtc_integrity_error_ != nullptr)
    {
        logger_.LogInfo() << "ParameterLoader::" << __func__ << " - Setting integrity error DTC to Failed";
        dtc_integrity_error_->Failed();
    }
}

void ParameterLoaderImpl::LoadParameterSets(json::Object& param_sets)
{
    for (auto& param_set : param_sets)
    {
        // LCOV_EXCL_START, already covered in unit test
        std::string param_set_name;
        score::json::Object param_set_obj{};
        // LCOV_EXCL_STOP
        if (GetObjectElement(param_set, param_set_name, param_set_obj))
        {
            ParameterSetQualifier set_qualifier = ParameterSetQualifier::kQualified;

            if (!HandleContainsDefaultValues(param_set_obj, param_set_name))
            {
                continue;
            }

            const auto& parameter_set_parameters_iter = param_set_obj.find(kParametersKey);
            if (parameter_set_parameters_iter == param_set_obj.end())
            {
                parameter_sets_integrity_error_ = true;
                logger_.LogError() << "ParameterLoader::" << __func__
                                   << " - Failed to find 'parameters' key in set: " << param_set_name;
                continue;
            }
            auto parameter_set_parameters_object_result = parameter_set_parameters_iter->second.As<json::Object>();
            if (!parameter_set_parameters_object_result.has_value())
            {
                parameter_sets_integrity_error_ = true;
                logger_.LogError() << "ParameterLoader::" << __func__
                                   << " -  Failed to convert value of "
                                      "'parameters' into json object for set: "
                                   << param_set_name
                                   << "with error: " << parameter_set_parameters_object_result.error().UserMessage();
                continue;
            }

            auto& parameter_set_parameters_object = parameter_set_parameters_object_result.value().get();
            LoadParameterSetParameters(parameter_set_parameters_object, param_set_name, set_qualifier);
            auto set_parameter_set_qualifier_res =
                parameter_data_->SetParameterSetQualifier(param_set_name, set_qualifier);
            if (!set_parameter_set_qualifier_res.has_value())
            {
                logger_.LogError() << "ParameterLoader::" << __func__
                                   << " - Failed to set parameter set qualifier with error: "
                                   << set_parameter_set_qualifier_res.error().UserMessage();
                continue;
            }
            /* KW_SUPPRESS_START:MISRA.CAST.CONST: There is no way to cast without loosing "* const" qualifier */
            if (!parameter_data_->SetCalibratable(score::cpp::string_view{param_set_name}, true))
            {
                logger_.LogError() << "ParameterLoader::" << __func__
                                   << " - Failed to set the calibration flag for parameter_set: " << param_set_name;
            }
        }
        else
        {
            parameter_sets_integrity_error_ = true;
            logger_.LogError() << "ParameterLoader::" << __func__ << " - Failed to load parameter set";
        }
    }
}

bool ParameterLoaderImpl::GetObjectElement(std::pair<const score::memory::StringComparisonAdaptor, score::json::Any>& obj,
                                           std::string& obj_name,
                                           score::json::Object& obj_value) const
{
    obj_name = obj.first.GetAsStringView().data();
    auto obj_result = obj.second.As<score::json::Object>();
    if (!obj_result.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - " << obj_name << " value is not an object.";
        return false;
    }

    obj_value = std::move(obj_result.value().get());
    return true;
}

bool ParameterLoaderImpl::HandleContainsDefaultValues(const json::Object& param_set_obj,
                                                      const std::string& param_set_name)
{
    const auto& set_contains_default_value_obj = param_set_obj.find(kContainsDefaultValue);
    if (set_contains_default_value_obj == param_set_obj.end())
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Failed to find 'containsDefaultValue' key in set: " << param_set_name;
        parameter_sets_integrity_error_ = true;
        return false;
    }
    auto set_contains_default_value_res = set_contains_default_value_obj->second.As<bool>();
    if (!set_contains_default_value_res.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " -  Failed to convert value of "
                              "'containsDefaultValue' into boolean for set: "
                           << param_set_name;
        parameter_sets_integrity_error_ = true;
        return false;
    }
    if (set_contains_default_value_res.value() == true)
    {
        logger_.LogInfo() << "ParameterLoader::" << __func__ << "- Setting Default Value in use DTC";
        parameter_sets_default_in_use_error_ = true;
    }

    return true;
}

void ParameterLoaderImpl::LoadParameterSetParameters(json::Object& parameter_set_parameters_object,
                                                     const std::string& param_set_name,
                                                     ParameterSetQualifier& set_qualifier)
{
    for (auto& param : parameter_set_parameters_object)
    {
        std::string param_name;
        score::json::Object param_obj{};
        if (GetObjectElement(param, param_name, param_obj))
        {
            LoadParameter(param_obj, param_name, param_set_name, set_qualifier);
        }
        else
        {
            logger_.LogError() << "ParameterLoader::" << __func__
                               << " - Failed to load parameter object for parameter name" << param_name
                               << "and parameter_set name" << param_set_name << "- Setting qualifier to UNQUALIFIED.";
            set_qualifier = ParameterSetQualifier::kUnqualified;
            parameter_sets_integrity_error_ = true;
        }
    }
}

void ParameterLoaderImpl::LoadParameter(json::Object& param_obj,
                                        const std::string& param_name,
                                        const std::string& param_set_name,
                                        ParameterSetQualifier& set_qualifier)
{
    const auto& coding_dependency_object = param_obj.find(kCodingDependencyKey);
    if (coding_dependency_object != param_obj.end())
    {
        auto coding_dependency_object_res = coding_dependency_object->second.As<json::Object>();
        if (!coding_dependency_object_res.has_value())
        {
            logger_.LogError() << "ParameterLoader::" << __func__
                               << " - Value of 'codingDependency' is not an object for parameter: " << param_name
                               << "- Setting qualifier to UNQUALIFIED.";
            set_qualifier = ParameterSetQualifier::kUnqualified;
            parameter_sets_integrity_error_ = true;
        }
        else
        {
            auto json_loaded = LoadCodingDependentParameterFromJson(
                param_set_name, param_name, coding_dependency_object_res.value(), set_qualifier);
            if (!json_loaded.has_value())
            {
                logger_.LogError() << "ParameterLoader::" << __func__
                                   << " - Failed to load coding-dependent parameter: " << param_name;
                // Coding dependent parameters are qualified if the provided coding value isn't found in
                // "codingParamValues"
                if (json_loaded.error() != ParameterLoaderError::kCodingValueNotAvailable)
                {
                    logger_.LogError() << "ParameterLoader::" << __func__ << "- Setting qualifier to UNQUALIFIED.";
                    set_qualifier = ParameterSetQualifier::kUnqualified;
                }
                parameter_sets_integrity_error_ = true;

                if (!LoadParameterFromJson(param_set_name, param_name, param_obj))
                {
                    logger_.LogError() << "ParameterLoader::" << __func__
                                       << " - Failed to load default parameter: " << param_name;
                }
                else
                {
                    parameter_sets_default_in_use_error_ = true;
                }
            }
        }
    }
    else
    {
        if (!LoadParameterFromJson(param_set_name, param_name, param_obj))
        {
            logger_.LogError() << "ParameterLoader::" << __func__ << " - Failed to load parameter: " << param_name
                               << "- Setting qualifier to UNQUALIFIED.";
            set_qualifier = ParameterSetQualifier::kUnqualified;
            parameter_sets_integrity_error_ = true;
        }
    }
}

Result<void> ParameterLoaderImpl::LoadCodingDependentParameterFromJson(
    const std::string& param_set_name,
    const std::string& param_name,
    std::map<score::memory::StringComparisonAdaptor, score::json::Any>& param_coding_dependency,
    ParameterSetQualifier& set_qualifier)
{
    const auto& coding_param = param_coding_dependency.find(kCodingParamNameKey);
    if (coding_param == param_coding_dependency.end())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Failed to find key " << kCodingParamNameKey
                           << " in parameter: " << param_name;
        return MakeUnexpected(ParameterLoaderError::kFailedToFindCodingParamNameKey);
    }
    const auto coding_param_name_str = coding_param->second.As<std::string>();
    if (!coding_param_name_str.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - " << kCodingParamNameKey
                           << " value is not string: ";
        return MakeUnexpected(ParameterLoaderError::kInvalidCodingParamNameKeyValue);
    }
    const score::cpp::pmr::string coding_param_name{coding_param_name_str.value().get()};
    if (parameter_set_mapping_ == nullptr)
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - ParameterSetMapping is nullptr";
        return MakeUnexpected(ParameterLoaderError::kParameterSetMappingIsNullptr);
    }

    const auto coding_param_set_name = parameter_set_mapping_->GetParameterSetForParameter(coding_param_name);
    if (coding_param_set_name.size() > static_cast<std::size_t>(0))
    {
        const std::string coding_param_set_name_str{std::begin(coding_param_set_name), std::end(coding_param_set_name)};

        auto coding_set_qualifier_res = parameter_data_->GetParameterSetQualifier(coding_param_set_name_str);
        if (coding_set_qualifier_res.has_value() == true)
        {
            if ((coding_set_qualifier_res.value() != ParameterSetQualifier::kQualified) &&
                (set_qualifier != ParameterSetQualifier::kUnqualified))
            {
                logger_.LogInfo() << "ParameterLoader::" << __func__ << "- Setting qualifier for" << param_set_name
                                  << "to UNQUALIFIED because it depends on a coding parameter which isn't qualified.";
                set_qualifier = ParameterSetQualifier::kUnqualified;
            }
        }
        else
        {
            logger_.LogInfo()
                << "ParameterLoader::" << __func__ << "- Setting qualifier for" << param_set_name
                << "to UNQUALIFIED due to a failure in reading the qualifier of the dependent coding parameter.";
            set_qualifier = ParameterSetQualifier::kUnqualified;
        }

        std::string coding_param_value;
        if (GetCodingParamValue(coding_param_set_name_str, coding_param_name_str.value().get(), coding_param_value))
        {
            return LoadCodingDependentParameterValue(
                param_set_name, param_name, param_coding_dependency, coding_param_value);
        }
        else
        {
            logger_.LogError() << "ParameterLoader::" << __func__
                               << " - Failed to get coding parameter value for "
                                  "coding parameter: "
                               << coding_param_name.c_str();
            return MakeUnexpected(ParameterLoaderError::kFailedToGetCodingParameterValue);
        }
    }
    else
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Failed to get parameter_set for parameter: " << coding_param_name.c_str();
        return MakeUnexpected(ParameterLoaderError::kFailedToGetParameterSetForParameter);
    }
}

bool ParameterLoaderImpl::GetCodingParamValue(const std::string& coding_param_set_name,
                                              const std::string& coding_param_name,
                                              std::string& coding_param_value) const
{
    const auto parameter_value = parameter_data_->GetParameterFromSet(coding_param_set_name, coding_param_name);

    if (!parameter_value.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Coding parameter " << coding_param_name
                           << " is not found";
        return false;
    }

    // Coding parameter value is assumed to be of type uint8
    // Used uint16_t because using uint8 doesn't work with stringstream, resulting empty string
    const auto value_integer = parameter_value.value().As<std::uint16_t>();
    if (!value_integer.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Coding parameter value is not of type uint16";
        return false;
    }

    std::stringstream value_string;  // LCOV_EXCL_LINE, already covered in unit test
    value_string << value_integer.value();
    coding_param_value = value_string.str();
    return true;
}

Result<void> ParameterLoaderImpl::LoadCodingDependentParameterValue(
    const std::string& param_set_name,
    const std::string& param_name,
    std::map<score::memory::StringComparisonAdaptor, score::json::Any>& param_coding_dependency,
    const std::string& coding_param_name)
{
    const auto& coding_param = param_coding_dependency.find(kCodingParamValuesKey);
    if (coding_param == param_coding_dependency.end())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Failed to find key " << kCodingParamValuesKey
                           << " in parameter: " << param_name;
        return MakeUnexpected(ParameterLoaderError::kFailedToFindCodingParamValuesKey);
    }

    auto coding_param_values_result = coding_param->second.As<json::Object>();
    if (!coding_param_values_result.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Invalid " << kCodingParamValuesKey
                           << " value for parameter " << param_name << " in set " << param_set_name;
        return MakeUnexpected(ParameterLoaderError::kInvalidCodingParamValuesKey);
    }

    auto& coding_param_values = coding_param_values_result.value().get();

    auto coding_param_values_iter = coding_param_values.find(coding_param_name);
    if (coding_param_values_iter == coding_param_values.end())
    {
        logger_.LogError() << "ParameterLoader::" << __func__ << " - Coding parameter value " << coding_param_name
                           << " is not available for parameter " << param_name << " in set " << param_set_name;
        return MakeUnexpected(ParameterLoaderError::kCodingValueNotAvailable);
    }

    const auto existing_value = parameter_data_->GetParameterFromSet(param_set_name, param_name);
    if (existing_value.has_value())
    {
        if (existing_value.value() == coding_param_values_iter->second)
        {
            logger_.LogInfo() << "ParameterLoader::" << __func__
                              << " - Parameter already exists with same value: " << param_name
                              << " in set: " << param_set_name << " (already loaded by daemon)";
            return {};
        }
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Parameter already exists with different value: " << param_name
                           << " in set: " << param_set_name;
        return MakeUnexpected(ParameterLoaderError::kFailedToInsertValue);
    }

    auto insert_res = parameter_data_->Insert(param_set_name, param_name, std::move(coding_param_values_iter->second));
    if (!insert_res.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Failed to insert parameter data with error: " << insert_res.error().UserMessage();
        return MakeUnexpected(ParameterLoaderError::kFailedToInsertValue);
    }

    return {};
}

bool ParameterLoaderImpl::LoadParameterFromJson(
    const std::string& param_set_name,
    const std::string& param_name,
    std::map<memory::StringComparisonAdaptor, json::Any>& parameter_obj) noexcept
{
    auto init_value_iter = parameter_obj.find(kInitValueKey);
    if (init_value_iter == parameter_obj.end())
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Failed to load value for parameter: " << param_name;
        return false;
    }

    const auto existing_value = parameter_data_->GetParameterFromSet(param_set_name, param_name);
    if (existing_value.has_value())
    {
        if (existing_value.value() == init_value_iter->second)
        {
            logger_.LogInfo() << "ParameterLoader::" << __func__
                              << " - Parameter already exists with same value: " << param_name
                              << " in set: " << param_set_name << " (already loaded by daemon)";
            return true;
        }
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Parameter already exists with different value: " << param_name
                           << " in set: " << param_set_name;
        return false;
    }

    auto insert_res = parameter_data_->Insert(param_set_name, param_name, std::move(init_value_iter->second));
    if (!insert_res.has_value())
    {
        logger_.LogError() << "ParameterLoader::" << __func__
                           << " - Failed to insert parameter data with error: " << insert_res.error().UserMessage();
        return false;
    }

    return true;
}

void ParameterLoaderImpl::SetDtcs() noexcept
{
    if (parameter_sets_integrity_error_ == true)
    {
        SetIntegrityErrorDtcsToFailed();
    }
    else
    {
        if (fault_event_reporter_ != nullptr &&
            !fault_event_reporter_->Report(static_cast<std::uint8_t>(FaultEventId::kCalibrationPluginSwError), false))
        {
            logger_.LogError() << "Failed to report kCalibrationPluginSwError";
        }
        if (dtc_integrity_error_ != nullptr)
        {
            dtc_integrity_error_->Succeeded();
        }
    }

    if (parameter_sets_default_in_use_error_ == true)
    {
        if (dtc_default_values_in_use_ != nullptr)
        {
            dtc_default_values_in_use_->Failed();
        }
    }
    else
    {
        if (dtc_default_values_in_use_ != nullptr)
        {
            dtc_default_values_in_use_->Succeeded();
        }
    }
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
