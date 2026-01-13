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
#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "score/result/error_domain.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{

namespace
{
class ConfigProviderErrorDomain final : public score::result::ErrorDomain
{
  public:
    // The following method is composed entirely of a well-structured switch block to
    // handle various error codes for CfgP and does not require further simplification.
    // SCORE_CCM_NO_LINT
    /* KW_SUPPRESS_START:AUTOSAR.MEMB.VIRTUAL.FINAL: valid use */
    /*Code is compiled with -Werror=suggest-override, meaning that compilation
    fails unless method has override qualifier. But using override instead of
    final triggers the klocwork warning. Warning can not be fixed while
    -Werror=suggest-override is used as a compiler option.*/
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override
    /* KW_SUPPRESS_END:AUTOSAR.MEMB.VIRTUAL.FINAL */
    {
        using std::string_view_literals::operator""sv;
        // Suppress "AUTOSAR C++14 M6-4-3" rule finding. This rule declares: "A switch statement shall be
        // a well-formed switch statement".
        // Rationale: False positive, this switch statement is well-formed.
        // coverity[autosar_cpp14_m6_4_3_violation]
        switch (code)
        {
            // Suppress "AUTOSAR C++14 M6-4-5" rule finding. This rule declares: "An unconditional throw
            // or break statement shall terminate every non-empty switch-clause".
            // Rationale: The return statements are used in each case and do not need break statements.
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kParsingFailed):
                return "JSON parsing failed"sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kObjectCastingError):
                return "Failed to cast JSON to object instance."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kParameterNotFound):
                return "Parameter name was not found in JSON"sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kValueCastingError):
                return "Failed to cast object instance to given C++ type"sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kValueNotFound):
                return "Failed to find parameter value in JSON."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kProxyNotReady):
                return "Proxy is not ready."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kProxyAccessTimeout):
                return "Proxy access did not finish in time."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kProxyReturnedNoResult):
                return "Proxy request did not return any result."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kEmptyCallbackProvided):
                return "Empty callback provided."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kCallbackAlreadySet):
                return "A callback is already set."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kMethodNotSupported):
                return "Method is not supported."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kFailedToSubscribe):
                return "Failed to subscribe to event."sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            case score::cpp::to_underlying(ConfigProviderError::kParameterSetNotFound):
                return "Parameter set was not found"sv;
            // coverity[autosar_cpp14_m6_4_5_violation]
            default:
                return "Unknown Error!"sv;
        }
    }
};

constexpr ConfigProviderErrorDomain kConfigProviderErrorDomain{};
}  // namespace

score::result::Error MakeError(const ConfigProviderError code, const std::string_view user_message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kConfigProviderErrorDomain, user_message};
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
