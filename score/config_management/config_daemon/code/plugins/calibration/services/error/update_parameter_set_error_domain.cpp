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
#include "score/config_management/config_daemon/code/plugins/calibration/services/error/update_parameter_set_error_domain.h"

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
class UpdateParameterSetErrorDomain final : public score::result::ErrorDomain
{
  public:
    /* KW_SUPPRESS_START:MISRA.VIRTUAL.NOVIRTUAL,AUTOSAR.MEMB.VIRTUAL.FINAL: valid use */
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    {
        if ((code < score::cpp::to_underlying(UpdateParameterSetError::kParsingError)) ||
            (code > score::cpp::to_underlying(UpdateParameterSetError::kUnknownError)))
        {
            return std::string_view{"Unknown Error!"};
        }

        std::string_view message;
        switch (static_cast<UpdateParameterSetError>(code))
        {
            case UpdateParameterSetError::kParsingError:
                message = std::string_view{"Parsing error"};
                break;
            case UpdateParameterSetError::kParameterSetNotFound:
                message = std::string_view{"Parameter set not found"};
                break;
            case UpdateParameterSetError::kParametersNotFound:
                message = std::string_view{"Parameters not found"};
                break;
            case UpdateParameterSetError::kSendLastUpdatedParameterSetFailed:
                message = std::string_view{"SendLastUpdatedParameterSet failed"};
                break;
            case UpdateParameterSetError::kParameterSetNotCalibratable:
                message = std::string_view{"Parameter Set is not calibratable"};
                break;
            case UpdateParameterSetError::kUnknownError:
                message = std::string_view{"Unknown Error!"};
                break;
            // LCOV_EXCL_START (Reaching this default case is not possible as range is checked above.)
            default:
                message = std::string_view{"Unknown Error!"};
                break;
                // LCOV_EXCL_STOP
        }
        return message;
    }
    /* KW_SUPPRESS_END:MISRA.VIRTUAL.NOVIRTUAL,AUTOSAR.MEMB.VIRTUAL.FINAL */
};

constexpr UpdateParameterSetErrorDomain kOpenFileTransferErrorDomain;
}  // namespace

score::result::Error MakeError(const UpdateParameterSetError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kOpenFileTransferErrorDomain, user_message};
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
