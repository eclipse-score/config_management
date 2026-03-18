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

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/error/parameter_set_storage_error.h"

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
class ParameterSetStorageErrorDomain final : public score::result::ErrorDomain
{
  public:
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    {
        if ((code < score::cpp::to_underlying(ParameterSetStorageError::kDataNotFound)) ||
            (code > score::cpp::to_underlying(ParameterSetStorageError::kUnableToSaveToPersistency)))
        {
            return std::string_view{"Unknown Error!"};
        }

        std::string_view message;
        switch (static_cast<ParameterSetStorageError>(code))
        {
            case ParameterSetStorageError::kDataNotFound:
            {
                message = std::string_view{"Data not found"};
            }
            break;

            case ParameterSetStorageError::kUnableToSaveToPersistency:
            {
                message = std::string_view{"Unable to save data to persistency"};
            }
            break;

            // LCOV_EXCL_START (Reaching this default case is not possible as range is checked above.)
            default:
            {
                message = std::string_view{"Unknown Error!"};
            }
            break;
                // LCOV_EXCL_STOP
        }

        return message;
    }
};

constexpr ParameterSetStorageErrorDomain kParameterSetStorageErrorDomain{};
}  // namespace

score::result::Error MakeError(const ParameterSetStorageError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kParameterSetStorageErrorDomain, user_message};
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
