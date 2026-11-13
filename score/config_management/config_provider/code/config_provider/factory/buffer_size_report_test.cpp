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

#include "score/json/i_json_parser_mock.h"

#include <score/memory_resource.hpp>
#include <score/optional.hpp>
#include <score/vector.hpp>

#include <gtest/gtest.h>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace
{

score::json::Any MakeReport(const std::initializer_list<std::pair<const char*, std::uint64_t>> buffer_size_mapping)
{
    score::json::Object mapping{};
    for (const auto& entry : buffer_size_mapping)
    {
        mapping[entry.first] = score::json::Any{entry.second};
    }
    score::json::Object root{};
    root["buffer_size_mapping"] = score::json::Any{std::move(mapping)};
    return score::json::Any{std::move(root)};
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoFailsWhenJsonParserIsNull)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() returns kJsonParserNotProvided when no JSON parser is "
                   "given.");

    const auto result = BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::nullopt, score::cpp::pmr::get_default_resource(), nullptr);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), MakeError(ConfigProviderError::kJsonParserNotProvided));
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoFailsWhenFileCannotBeRead)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() returns kBufferSizeReportNotFound when "
                   "buffer_size_report.json is missing or unreadable.");

    auto json_parser_mock = std::make_shared<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser_mock, FromFile(std::string_view{kDefaultBufferSizeReportPath}))
        .WillOnce([](std::string_view) -> score::Result<score::json::Any> {
            return score::MakeUnexpected<score::json::Any>(ConfigProviderError::kBufferSizeReportNotFound);
        });

    const auto result =
        BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::nullopt, score::cpp::pmr::get_default_resource(), json_parser_mock);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), MakeError(ConfigProviderError::kBufferSizeReportNotFound));
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoFailsForMalformedReport)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() returns kBufferSizeReportParsingFailed when "
                   "buffer_size_report.json does not conform to buffer_size_report.schema.json.");

    auto json_parser_mock = std::make_shared<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser_mock, FromFile(std::string_view{kDefaultBufferSizeReportPath}))
        .WillOnce([](std::string_view) -> score::Result<score::json::Any> {
            score::json::Object root{};
            root["unexpected_key"] = score::json::Any{std::int64_t{1}};
            return score::json::Any{std::move(root)};
        });

    const auto result =
        BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::nullopt, score::cpp::pmr::get_default_resource(), json_parser_mock);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), MakeError(ConfigProviderError::kBufferSizeReportParsingFailed));
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoReturnsLargestOfRequestedSets)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() returns the largest buffer size and longest parameter set "
                   "name length among the requested parameter sets, ignoring sets that were not requested.");

    auto json_parser_mock = std::make_shared<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser_mock, FromFile(std::string_view{kDefaultBufferSizeReportPath}))
        .WillOnce([](std::string_view) -> score::Result<score::json::Any> {
            return MakeReport({{"SmallSet", 100U}, {"MediumSet", 500U}, {"LargeSet", 16425U}});
        });

    const score::cpp::pmr::vector<std::string_view> set_names{{"SmallSet", "MediumSet"}};
    const auto result =
        BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::optional<score::cpp::pmr::vector<std::string_view>>{set_names},
                                               score::cpp::pmr::get_default_resource(),
                                               json_parser_mock);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().max_payload_size, 500U);
    EXPECT_EQ(result.value().max_name_length, std::string_view{"MediumSet"}.size());
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoIgnoresUnknownParameterSet)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() logs an error and ignores a requested parameter set that "
                   "has no entry in buffer_size_report.json, rather than failing outright - a caller-side typo or "
                   "stale name should not disable the whole ConfigProvider; GetParameterSet() for it will fail on "
                   "its own at call time anyway.");

    auto json_parser_mock = std::make_shared<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser_mock, FromFile(std::string_view{kDefaultBufferSizeReportPath}))
        .WillOnce([](std::string_view) -> score::Result<score::json::Any> {
            return MakeReport({{"SmallSet", 100U}, {"MediumSet", 500U}, {"LargeSet", 16425U}});
        });

    const score::cpp::pmr::vector<std::string_view> set_names{{"SmallSet", "UnknownSet"}};
    const auto result =
        BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::optional<score::cpp::pmr::vector<std::string_view>>{set_names},
                                               score::cpp::pmr::get_default_resource(),
                                               json_parser_mock);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().max_payload_size, 100U);
    EXPECT_EQ(result.value().max_name_length, std::string_view{"SmallSet"}.size());
}

TEST(BufferSizeReportTest, GetMaxBufferSizeInfoForEmptyListReturnsOverallMaximum)
{
    RecordProperty("Priority", "2");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::BufferSizeReport::GetMaxBufferSizeInfo()");
    RecordProperty("Description",
                   "Verifies that GetMaxBufferSizeInfo() returns the largest buffer size and longest parameter set "
                   "name length across every parameter set in buffer_size_report.json when given an empty list, "
                   "for the deprecated Create() overloads that do not provide an explicit list of parameter set "
                   "names.");

    auto json_parser_mock = std::make_shared<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser_mock, FromFile(std::string_view{kDefaultBufferSizeReportPath}))
        .WillOnce([](std::string_view) -> score::Result<score::json::Any> {
            return MakeReport({{"SmallSet", 100U}, {"MediumSet", 500U}, {"LargeSet", 16425U}});
        });

    const auto result =
        BufferSizeReport::GetMaxBufferSizeInfo(score::cpp::nullopt, score::cpp::pmr::get_default_resource(), json_parser_mock);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().max_payload_size, 16425U);
    EXPECT_EQ(result.value().max_name_length, std::string_view{"MediumSet"}.size());
}

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
