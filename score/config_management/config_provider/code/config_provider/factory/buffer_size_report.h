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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_BUFFER_SIZE_REPORT_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_BUFFER_SIZE_REPORT_H

#include "score/json/i_json_parser.h"
#include "score/result/result.h"

#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/vector.hpp>

#include <cstddef>
#include <memory>
#include <string_view>

namespace score
{
namespace config_management
{
namespace config_provider
{

/// @brief Per-argument shared-memory sizing needed by ConfigProvider's semi-dynamic `get_parameter_set` method, so
/// that a proxy implementation knows how to split its pool between the requested parameter set name (arg1) and the
/// returned payload (arg2).
struct AdditionalShmSizing
{
    std::size_t max_payload_size;
    std::size_t max_name_length;
};

/// Deployed alongside the other ConfigDaemon config files (see
/// //ecu/xpad/xpad-shared/config/ipnext/isoc/config_management/config_daemon:buffer_size_report), produced by
/// //platform/aas/config_management/tools/buffer_size_calculator.
constexpr std::string_view kDefaultBufferSizeReportPath{"/platform/opt/ConfigDaemon/etc/buffer_size_report.json"};

/// @brief Loads and parses buffer_size_report.json (from kDefaultBufferSizeReportPath), returning the theoretical
/// worst-case buffer size (in bytes) and the longest parameter set name (in bytes, excluding a null terminator)
/// among `initial_parameter_set_name_list`, as calculated by the buffer_size_calculator tool - or (if
/// `initial_parameter_set_name_list` has no value, i.e. the caller did not provide an explicit list of parameter
/// set names - see the deprecated ConfigProviderFactory::Create() overloads) among every parameter set present in
/// the report. The returned buffer size is never smaller than
/// score::config_management::config_daemon::mw_com_icp_types::kMinParameterSetContentBufferSize, so it's always big enough
/// to hold whichever sentinel content the skeleton may write instead of a real payload.
class BufferSizeReport
{
  public:
    /// @return An error if `json_parser` is nullptr (kJsonParserNotProvided), or if the file is missing,
    /// unreadable, or does not conform to buffer_size_report.schema.json (kBufferSizeReportNotFound,
    /// kBufferSizeReportParsingFailed). Any of `initial_parameter_set_name_list` that has no corresponding entry
    /// in the report is logged as an error and ignored (not treated as a failure) - a caller-side typo or stale
    /// name shouldn't disable the whole ConfigProvider, since GetParameterSet() for it will fail on its own anyway.
    ///
    /// @param json_parser Callers must provide a JsonParser instance; passing nullptr returns
    /// kJsonParserNotProvided. Unit tests may inject an IJsonParserMock here to avoid touching the real filesystem.
    /// @param buffer_size_report_path Defaults to the production path (kDefaultBufferSizeReportPath). Callers that
    /// run outside of production deployment (e.g. in-process SCT test bindings that aren't relocated into sctf's
    /// sandboxed mount namespace) may override this to point at their own, differently-located copy of the file.
    static score::Result<AdditionalShmSizing> GetMaxBufferSizeInfo(
        const score::cpp::optional<score::cpp::pmr::vector<std::string_view>>& initial_parameter_set_name_list,
        score::cpp::pmr::memory_resource* const memory_resource = score::cpp::pmr::get_default_resource(),
        std::shared_ptr<score::json::IJsonParser> json_parser = nullptr,
        std::string_view buffer_size_report_path = kDefaultBufferSizeReportPath);
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_CONFIG_PROVIDER_FACTORY_BUFFER_SIZE_REPORT_H
