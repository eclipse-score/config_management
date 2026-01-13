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
#include "score/config_management/config_provider/code/persistency/error/persistency_error.h"

#include "score/result/error_domain.h"

#include <score/assert.hpp>
#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace
{
class PersistencyErrorDomain final : public score::result::ErrorDomain
{
  public:
    /* KW_SUPPRESS_START:AUTOSAR.MEMB.VIRTUAL.FINAL: Klocwork error, the function is an override */
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    /* KW_SUPPRESS_END:AUTOSAR.MEMB.VIRTUAL.FINAL */
    {
        const bool enum_in_range = (code >= score::cpp::to_underlying(PersistencyError::kDataNotFound)) &&
                                   (code <= score::cpp::to_underlying(PersistencyError::kUnableToSaveToPersistency));
        SCORE_LANGUAGE_FUTURECPP_ASSERT_PRD_MESSAGE(enum_in_range, "value of score::result::ErrorCode is out of range of PersistencyError");

        // Suppress "AUTOSAR C++14 M6-4-3" rule finding. This rule declares: "A switch statement shall be
        // a well-formed switch statement".
        // Rationale: False positive, this switch statement is well-formed.
        // coverity[autosar_cpp14_m6_4_3_violation]
        switch (static_cast<PersistencyError>(code))
        {
            // Suppress "AUTOSAR C++14 M6-4-5" rule finding. This rule declares: "An unconditional throw
            // or break statement shall terminate every non-empty switch-clause".
            // Rationale: The return statements are used in each case and do not need break statements.
            // coverity[autosar_cpp14_m6_4_5_violation]
            case PersistencyError::kDataNotFound:
                return "Data not found";
            // coverity[autosar_cpp14_m6_4_5_violation]
            case PersistencyError::kUnableToSaveToPersistency:
                return "Unable to save data to persistency";
            // LCOV_EXCL_START (Reaching this default case is not possible as range is checked above.)
            // coverity[autosar_cpp14_m6_4_5_violation]
            default:
                return "Unknown Error!";
                // LCOV_EXCL_STOP
        }
    }
};

constexpr PersistencyErrorDomain kDataStorageErrorDomain{};

}  // namespace

score::result::Error MakeError(const PersistencyError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kDataStorageErrorDomain, user_message};
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
