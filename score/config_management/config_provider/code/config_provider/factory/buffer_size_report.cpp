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
#include "score/config_management/config_provider/code/config_provider/factory/buffer_size_report.h"

#include "score/config_management/config_provider/code/config_provider/error/error.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <unordered_set>

namespace score
{
namespace config_management
{
namespace config_provider
{

namespace
{
constexpr std::string_view kBufferSizeMappingKey{"buffer_size_mapping"};
}  // namespace

score::Result<AdditionalShmSizing> BufferSizeReport::GetMaxBufferSizeInfo(
    const score::cpp::optional<score::cpp::pmr::vector<std::string_view>>& initial_parameter_set_name_list,
    score::cpp::pmr::memory_resource* const memory_resource,
    std::shared_ptr<score::json::IJsonParser> json_parser,
    std::string_view buffer_size_report_path)
{
    if (json_parser == nullptr)
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ": No JSON parser was provided";
        return score::MakeUnexpected(ConfigProviderError::kJsonParserNotProvided);
    }

    // An empty list means "every parameter set in the report", matching the deprecated Create() overloads that
    // don't provide an explicit list of parameter set names.
    const score::cpp::pmr::vector<std::string_view> empty_set_names{
        score::cpp::pmr::vector<std::string_view>::allocator_type{memory_resource}};
    const auto& set_names =
        initial_parameter_set_name_list.has_value() ? initial_parameter_set_name_list.value() : empty_set_names;

    // FromFile API is used for a file stored under /opt/ConfigDaemon/, which is protected by qtsafefs, guaranteeing
    // the integrity of the file's contents. Hence FromFile API is safe to use in this scenario.
    // NOLINTNEXTLINE(score-banned-function): justification is given above
    auto report_result = json_parser->FromFile(buffer_size_report_path);
    if (!report_result.has_value())
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ": Failed to load" << buffer_size_report_path << ":"
                            << report_result.error().UserMessage();
        return score::MakeUnexpected(ConfigProviderError::kBufferSizeReportNotFound, buffer_size_report_path);
    }

    const auto root_object_result = report_result.value().As<score::json::Object>();
    if (!root_object_result.has_value())
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ": Expected" << buffer_size_report_path
                            << "to contain a JSON object";
        return score::MakeUnexpected(ConfigProviderError::kBufferSizeReportParsingFailed, buffer_size_report_path);
    }

    const auto& root_object = root_object_result.value().get();
    const auto mapping_it = root_object.find(kBufferSizeMappingKey);
    if (mapping_it == root_object.end())
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ":" << buffer_size_report_path << "is missing the"
                            << kBufferSizeMappingKey << "key";
        return score::MakeUnexpected(ConfigProviderError::kBufferSizeReportParsingFailed, buffer_size_report_path);
    }

    const auto mapping_object_result = mapping_it->second.As<score::json::Object>();
    if (!mapping_object_result.has_value())
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ":" << kBufferSizeMappingKey << "in"
                            << buffer_size_report_path << "is not a JSON object";
        return score::MakeUnexpected(ConfigProviderError::kBufferSizeReportParsingFailed, buffer_size_report_path);
    }

    // Tracks max sizes in a single pass over the report, without building a map of every parameter set in
    // buffer_size_report.json (which can cover the whole vehicle) when the caller only asked about a handful:
    // `pending` starts as the requested names and each is erased once matched, so whatever remains afterwards had
    // no entry in the report. Unused when set_names is empty ("use every parameter set in the report").
    std::unordered_set<std::string_view> pending{set_names.begin(), set_names.end()};

    std::size_t max_payload_size{score::config_management::config_daemon::mw_com_icp_types::kMinParameterSetContentBufferSize};
    std::size_t max_name_length{0U};
    for (const auto& entry : mapping_object_result.value().get())
    {
        const auto size_result = entry.second.As<std::uint64_t>();
        if (!size_result.has_value())
        {
            mw::log::LogError() << "BufferSizeReport::" << __func__ << ": Buffer size for parameter set"
                                << entry.first.GetAsStringView() << "in" << buffer_size_report_path
                                << "is not an unsigned integer";
            return score::MakeUnexpected(ConfigProviderError::kBufferSizeReportParsingFailed, buffer_size_report_path);
        }
        const auto entry_name = entry.first.GetAsStringView();
        const auto buffer_size = static_cast<std::size_t>(size_result.value());

        if (set_names.empty() || (pending.erase(entry_name) > 0U))
        {
            max_payload_size = std::max(max_payload_size, buffer_size);
            max_name_length = std::max(max_name_length, entry_name.size());
        }
    }

    // A name not in the report is a caller-side configuration mistake (typo, stale name), not a reason to disable
    // the whole ConfigProvider: GetParameterSet() for it will fail on its own at call time anyway.
    for (const auto& not_found : pending)
    {
        mw::log::LogError() << "BufferSizeReport::" << __func__ << ": Parameter set" << not_found << "was not found in"
                            << buffer_size_report_path << "- ignoring it";
    }
    return AdditionalShmSizing{max_payload_size, max_name_length};
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
