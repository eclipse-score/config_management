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
#include "score/config_management/config_daemon/code/plugins/demo_json/details/demo_json_plugin_impl.h"

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_manager_mock.h"

#include "score/json/i_json_parser_mock.h"
#include "score/json/json_parser.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#include <score/stop_token.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{
namespace test
{

using score::json::operator""_json;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;

TEST(DemoJsonPluginImplTest, RunWithoutInitializeReturnsFailure)
{
    DemoJsonPluginImpl plugin{};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();
    auto parameter_set_collection_manager = std::make_shared<data_model::ParameterSetCollectionManagerMock>();
    ON_CALL(*parameter_set_collection_manager, GetParameterSetCollection()).WillByDefault(Return(collection));

    const std::int32_t run_result = plugin.Run(parameter_set_collection_manager,
                                               LastUpdatedParameterSetSender{},
                                               InitialQualifierStateSender{},
                                               score::cpp::stop_token{},
                                               nullptr);
    EXPECT_EQ(run_result, EXIT_FAILURE);
}

TEST(DemoJsonPluginImplTest, InitializeThenRunLoadsParameters)
{
    auto json_parser = std::make_unique<score::json::IJsonParserMock>();
    EXPECT_CALL(*json_parser, FromFile(_)).WillOnce(Return(ByMove(score::Result<score::json::Any>{R"({
    "parameterSets": {
        "DemoSet": {
            "parameters": {
                "ParamA": { "initValue": 123 }
            }
        }
    }
})"_json})));

    DemoJsonPluginImpl plugin{std::move(json_parser)};
    ASSERT_TRUE(plugin.Initialize().has_value());

    auto collection = std::make_shared<data_model::ParameterSetCollection>();
    auto parameter_set_collection_manager = std::make_shared<data_model::ParameterSetCollectionManagerMock>();
    ON_CALL(*parameter_set_collection_manager, GetParameterSetCollection()).WillByDefault(Return(collection));
    const std::int32_t run_result = plugin.Run(parameter_set_collection_manager,
                                               LastUpdatedParameterSetSender{},
                                               InitialQualifierStateSender{},
                                               score::cpp::stop_token{},
                                               nullptr);

    EXPECT_EQ(run_result, EXIT_SUCCESS);

    const auto param_a = collection->GetParameterFromSet("DemoSet", "ParamA");
    ASSERT_TRUE(param_a.has_value());
    ASSERT_TRUE(param_a.value().As<std::int64_t>().has_value());
    EXPECT_EQ(param_a.value().As<std::int64_t>().value(), 123);

    plugin.Deinitialize();
}

TEST(DemoJsonPluginImplTest, InitializeThenRunFailsOnInvalidJsonFile)
{
    auto json_parser = std::make_unique<score::json::IJsonParserMock>();
    auto parse_res = score::json::JsonParser().FromBuffer("not-json");
    EXPECT_CALL(*json_parser, FromFile(_)).WillOnce(Return(ByMove(std::move(parse_res))));

    DemoJsonPluginImpl plugin{std::move(json_parser)};
    ASSERT_TRUE(plugin.Initialize().has_value());

    auto collection = std::make_shared<data_model::ParameterSetCollection>();
    auto parameter_set_collection_manager = std::make_shared<data_model::ParameterSetCollectionManagerMock>();
    ON_CALL(*parameter_set_collection_manager, GetParameterSetCollection()).WillByDefault(Return(collection));
    const std::int32_t run_result = plugin.Run(parameter_set_collection_manager,
                                               LastUpdatedParameterSetSender{},
                                               InitialQualifierStateSender{},
                                               score::cpp::stop_token{},
                                               nullptr);

    EXPECT_EQ(run_result, EXIT_FAILURE);

    plugin.Deinitialize();
}

}  // namespace test
}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
