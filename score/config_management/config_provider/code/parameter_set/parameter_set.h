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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PARAMETER_SET_PARAMETER_SET_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PARAMETER_SET_PARAMETER_SET_H

#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "score/json/internal/model/any.h"
#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include <score/memory_resource.hpp>
#include <score/vector.hpp>
#include <score/zip_iterator.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{

class ParameterSet final
{
  public:
    template <typename PrimitiveType>
    using Array = score::cpp::pmr::vector<PrimitiveType>;
    template <typename PrimitiveType>
    using TwoDimensionalArray = Array<Array<PrimitiveType>>;

    template <typename>
    struct IsArray : std::false_type
    {
    };

    template <typename T>
    struct IsArray<Array<T>> : std::true_type
    {
    };

    explicit ParameterSet(score::json::Any set_json,
                          score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource());

    ParameterSet() = delete;
    ~ParameterSet() = default;

    ParameterSet(ParameterSet&&) noexcept = delete;
    ParameterSet(const ParameterSet&) noexcept = delete;

    ParameterSet& operator=(ParameterSet&&) & noexcept = delete;
    ParameterSet& operator=(const ParameterSet&) & noexcept = delete;

    bool ContainsSameContent(const ParameterSet& target_parameter_set) const;
    score::Result<score::config_management::config_daemon::ParameterSetQualifier> GetQualifier() const;
    /**
     * Gets the parameter from the set by the parameter's name
     */
    template <typename T, typename = std::enable_if_t<!IsArray<T>::value, bool>>
    score::Result<T> GetParameterAs(const score::cpp::string_view& parameter_name) const
    {
        const auto value_json = GetParameterAsJsonAny(parameter_name);
        if (value_json.has_value() == true)
        {
            return ConvertJsonAnyToType<T>(value_json.value().get());
        }
        return MakeUnexpected<T>(value_json.error());
    }

    template <typename T,
              typename = std::enable_if_t<(IsArray<T>::value) && (!IsArray<typename T::value_type>::value), bool>>
    score::Result<Array<typename T::value_type>> GetParameterAs(const score::cpp::string_view& parameter_name) const
    {
        return GetParameterAsArray<typename T::value_type>(parameter_name);
    }

    template <typename T,
              typename = std::enable_if_t<(IsArray<T>::value) && (IsArray<typename T::value_type>::value), bool>>
    score::Result<TwoDimensionalArray<typename T::value_type::value_type>> GetParameterAs(
        const score::cpp::string_view& parameter_name) const
    {
        return GetParameterAsTwoDimensionalArray<typename T::value_type::value_type>(parameter_name);
    }
    score::Result<std::string> FormatAsKeyValuePairs() const;
    score::Result<std::string> GetParametersAsString() const;
    Result<std::reference_wrapper<const json::Any>> GetParameterAsJsonAny(const score::cpp::string_view& parameter_name) const;

  private:
    Result<std::reference_wrapper<const score::json::Any>> GetParameters() const;

    template <typename PrimitiveType>
    score::Result<Array<PrimitiveType>> ConvertJsonListToAmpVector(const score::json::List& list_result,
                                                                 const score::cpp::string_view& parameter_name) const
    {
        const auto& list = list_result;
        Array<PrimitiveType> result(list.size(), memory_resource_);
        for (auto zipped : score::cpp::make_zip_range(list, result))  // LCOV_EXCL_BR_LINE tooling issue
        {
            const score::json::Any& list_element = std::get<0>(zipped);
            const auto conversion_result = ConvertJsonAnyToType<PrimitiveType>(list_element);
            if (conversion_result.has_value())
            {
                std::get<1>(zipped) = conversion_result.value();
            }
            else
            {
                logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name
                                   << "]: Failed to cast object instance to given C++ type";
                return MakeUnexpected(ConfigProviderError::kValueCastingError);
            }
        }
        return result;
    }

    template <typename PrimitiveType>
    score::Result<Array<PrimitiveType>> GetParameterAsArray(const score::cpp::string_view& parameter_name) const
    {
        const auto value_json = GetParameterAsJsonAny(parameter_name);
        if (value_json.has_value() == true)
        {
            const auto list_result = value_json.value().get().As<json::List>();
            if (list_result.has_value() == true)
            {
                return ConvertJsonListToAmpVector<PrimitiveType>(list_result.value().get(), parameter_name);
            }
            logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name
                               << "]: Failed to cast object instance to JSON list";
            return MakeUnexpected(ConfigProviderError::kValueCastingError);
        }
        const auto error_code = static_cast<ConfigProviderError>(*value_json.error());
        return MakeUnexpected(error_code);
    }

    template <typename PrimitiveType>
    score::Result<TwoDimensionalArray<PrimitiveType>> GetParameterAsTwoDimensionalArray(
        const score::cpp::string_view& parameter_name) const
    {
        const auto value_json = GetParameterAsJsonAny(parameter_name);

        if (value_json.has_value() == true)
        {
            const auto list_outer_result = value_json.value().get().As<json::List>();
            if (list_outer_result.has_value() == true)
            {
                const auto& list_outer = list_outer_result.value().get();
                TwoDimensionalArray<PrimitiveType> result_outer(list_outer.size(), memory_resource_);
                // LCOV_EXCL_BR_START, already covered in unit test
                for (const auto zipped : score::cpp::make_zip_range(list_outer, result_outer))
                // LCOV_EXCL_BR_STOP
                {
                    const json::Any& list_element_outer = std::get<0>(zipped);
                    const auto& list_inner_result = list_element_outer.As<json::List>();
                    if (list_inner_result.has_value() == true)
                    {
                        // LCOV_EXCL_START, already covered in unit test
                        const auto& result_array =
                            ConvertJsonListToAmpVector<PrimitiveType>(list_inner_result.value().get(), parameter_name);
                        // LCOV_EXCL_STOP
                        if (result_array.has_value() == true)
                        {
                            std::get<1>(zipped) = result_array.value();
                        }
                        else
                        {
                            return MakeUnexpected(ConfigProviderError::kValueCastingError);
                        }
                    }
                    else
                    {
                        logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name
                                           << "]: Failed to cast object instance to JSON list";
                        return MakeUnexpected(ConfigProviderError::kValueCastingError);
                    }
                }
                return result_outer;
            }
            logger_.LogError() << "ParameterSet::" << __func__ << " [" << parameter_name
                               << "]: Failed to cast object instance to JSON list";
            return MakeUnexpected(ConfigProviderError::kValueCastingError);
        }
        const auto error_code = static_cast<ConfigProviderError>(*value_json.error());
        return MakeUnexpected(error_code);
    }

    template <typename T, typename std::enable_if_t<std::is_floating_point<T>::value, bool> = true>
    score::Result<T> ConvertJsonAnyToType(const score::json::Any& value) const
    {
        const auto value_result = value.As<T>();
        if (value_result.has_value() == true)
        {
            return value_result.value();
        }
        else
        {
            // In the CRETA dcm export, some floating point values are formatted like integers. E.g. 1000000 instead of
            // 1000000.0 This results in the ".As<float/double>()" not working since it tries to convert an int to
            // a floating point value without precision loss. Therefore, this workaround is used.
            const auto int_result = value.As<int64_t>();
            if (int_result.has_value() == true)
            {
                return static_cast<T>(int_result.value());
            }
        }
        return MakeUnexpected(ConfigProviderError::kValueCastingError);
    }

    template <typename T, typename std::enable_if_t<!std::is_floating_point<T>::value, bool> = true>
    // Suppress "AUTOSAR C++14 A0-1-3" rule finding. This rule states: "Every function defined in an anonymous
    // namespace, or static function with internal linkage, or private member function shall be used.".
    // Rationale: function used in the same file.
    // coverity[autosar_cpp14_a0_1_3_violation] false-positive
    score::Result<T> ConvertJsonAnyToType(const score::json::Any& value) const
    {
        const auto value_result = value.As<T>();
        if (value_result.has_value() == true)  // LCOV_EXCL_BR_LINE tooling issue, details in Ticket-141380
        {
            return value_result.value();
        }
        else
        {
            logger_.LogError() << "ParameterSet::" << __func__ << ": Conversion to type "
                               << std::string_view(typeid(T).name()) << " failed";
        }
        return MakeUnexpected(ConfigProviderError::kValueCastingError);
    }

    score::Result<std::string> ConvertJsonToString(const score::json::Any& json) const;

    mw::log::Logger& logger_;
    score::json::Any set_json_;
    score::cpp::pmr::memory_resource* const memory_resource_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PARAMETER_SET_PARAMETER_SET_H
