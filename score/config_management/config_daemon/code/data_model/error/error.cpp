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

#include "score/config_management/config_daemon/code/data_model/error/error.h"

#include "score/result/error_domain.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

namespace
{
class DataModelErrorDomain final : public score::result::ErrorDomain
{
  public:
    // SCORE_CCM_NO_LINT Since it has switch case, it is not possible to split the functionality in a meaningful way.
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    {
        if ((code < score::cpp::to_underlying(DataModelError::kParameterMissedError)) ||
            (code > score::cpp::to_underlying(DataModelError::kParameterAlreadyExists)))
        {
            return std::string_view{"Unknown Error!"};
        }

        std::string_view message;
        switch (static_cast<DataModelError>(code))
        {
            case DataModelError::kParameterMissedError:
                message = std::string_view{"Parameter Missed error"};
                break;
            case DataModelError::kConvertingError:
                message = std::string_view{"Converting error"};
                break;
            case DataModelError::kParsingError:
                message = std::string_view{"Parsing error"};
                break;
            case DataModelError::kParameterSetNotFound:
                message = std::string_view{"Parameter set not found"};
                break;
            case DataModelError::kParametersNotFound:
                message = std::string_view{"Parameters not found"};
                break;
            case DataModelError::kParentParameterDataNotfound:
                message = std::string_view{"Parent ParameterData not found"};
                break;
            case DataModelError::kParameterSetNotCalibratable:
                message = std::string_view{"Parameter Set is not calibratable"};
                break;
            case DataModelError::kParameterAlreadyExists:
                message = std::string_view{"Parameter with input name already exists"};
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

constexpr DataModelErrorDomain kOpenFileTransferErrorDomain;
}  // namespace

score::result::Error MakeError(const DataModelError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kOpenFileTransferErrorDomain, user_message};
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
