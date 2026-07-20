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
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/error/error.h"

#include "score/result/error_domain.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

namespace
{
class ParameterLoaderErrorDomain final : public score::result::ErrorDomain
{
  public:
    // This method contains a large switch statement to map error enumeration values to corresponding error messages.
    // It is not possible to split the functionality in a meaningful way. This strategy has been
    // reviewed and adopted as a project-wide convention for error mapping. Hence, suppressing the warning.
    // SCORE_CCM_NO_LINT
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    {
        if ((code < score::cpp::to_underlying(ParameterLoaderError::kFailedToFindCodingParamValuesKey)) ||
            (code > score::cpp::to_underlying(ParameterLoaderError::kFailedToGetParameterSetForParameter)))
        {
            return std::string_view{"Unknown Error!"};
        }

        std::string_view message;
        switch (static_cast<ParameterLoaderError>(code))
        {
            case ParameterLoaderError::kFailedToFindCodingParamValuesKey:
                message = std::string_view{"Failed to find 'codingParamValues' key"};
                break;
            case ParameterLoaderError::kInvalidCodingParamValuesKey:
                message = std::string_view{"Invalid 'codingParamValues' value"};
                break;
            case ParameterLoaderError::kCodingValueNotAvailable:
                message = std::string_view{"Coding value is not available for parameter"};
                break;
            case ParameterLoaderError::kFailedToInsertValue:
                message = std::string_view{"Failed to insert parameter data"};
                break;
            case ParameterLoaderError::kFailedToFindCodingParamNameKey:
                message = std::string_view{"Failed to find 'codingParamName' key"};
                break;
            case ParameterLoaderError::kInvalidCodingParamNameKeyValue:
                message = std::string_view{"Invalid 'codingParamName' value"};
                break;
            case ParameterLoaderError::kParameterSetMappingIsNullptr:
                message = std::string_view{"ParameterSetMapping is nullptr"};
                break;
            case ParameterLoaderError::kFailedToGetCodingParameterValue:
                message = std::string_view{"Failed to get coding parameter value"};
                break;
            case ParameterLoaderError::kFailedToGetParameterSetForParameter:
                message = std::string_view{"Failed to get parameter set for parameter"};
                break;
            // LCOV_EXCL_START (Reaching this default case is not possible as range is checked above.)
            default:
                message = std::string_view{"Unknown Error!"};
                break;
                // LCOV_EXCL_STOP
        }
        return message;
    }
};

constexpr ParameterLoaderErrorDomain kParameterLoaderErrorDomain;
}  // namespace

score::result::Error MakeError(const ParameterLoaderError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kParameterLoaderErrorDomain, user_message};
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
