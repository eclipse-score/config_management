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
#include "score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/details/demo_parameter_loader_impl.h"

#include "score/json/json_parser.h"
#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

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

score::ResultBlank Ok()
{
    return score::ResultBlank{score::Blank{}};
}

score::ResultBlank Err()
{
    return score::ResultBlank{score::unexpect,
                            score::config_management::config_daemon::data_model::MakeError(
                                score::config_management::config_daemon::data_model::DataModelError::kParsingError, "unit-test")};
}

TEST(DemoParameterLoaderImplTest, LoadsParametersIntoDataModel)
{
    auto json_any = R"({
		"parameterSets": {
			"DemoSet": {
				"parameters": {
					"ParamA": { "initValue": 123 },
					"ParamB": { "initValue": 123.444 }
				}
			}
		}
	})"_json;

    auto loader = std::make_unique<DemoParameterLoaderImpl>(std::move(json_any));

    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    ASSERT_TRUE(loader->LoadParameterData(collection));

    const auto param_a = collection->GetParameterFromSet("DemoSet", "ParamA");
    ASSERT_TRUE(param_a.has_value());
    ASSERT_TRUE(param_a.value().As<std::int64_t>().has_value());
    EXPECT_EQ(param_a.value().As<std::int64_t>().value(), 123);

    const auto param_b = collection->GetParameterFromSet("DemoSet", "ParamB");
    ASSERT_TRUE(param_b.has_value());
    ASSERT_TRUE(param_b.value().As<double>().has_value());
    EXPECT_DOUBLE_EQ(param_b.value().As<double>().value(), 123.444);
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsOnNullCollection)
{
    auto json_any = R"({"parameterSets": {}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};

    EXPECT_FALSE(loader.LoadParameterData(nullptr));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsOnNullJsonResult)
{
    score::Result<json::Any> demo_data{};
    DemoParameterLoaderImpl loader{std::move(demo_data)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsOnJsonParseError)
{
    DemoParameterLoaderImpl loader{score::json::JsonParser().FromFile("not-json")};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenRootIsNotObject)
{
    auto json_any = R"([])"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParameterSetsMissing)
{
    auto json_any = R"({})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParameterSetsIsNotObject)
{
    auto json_any = R"({"parameterSets": []})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParameterSetValueIsNotObject)
{
    auto json_any = R"({"parameterSets": {"DemoSet": 5}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParametersMissing)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParametersIsNotObject)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": []}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenParameterValueIsNotObject)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": {"ParamA": 123}}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenInitValueMissing)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": {"ParamA": {}}}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};
    auto collection = std::make_shared<data_model::ParameterSetCollection>();

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenInsertFails)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": {"ParamA": {"initValue": 1}}}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};

    auto collection = std::make_shared<data_model::ParameterSetCollectionMock>();
    EXPECT_CALL(*collection, Insert(_, _, _)).WillOnce(::testing::Return(Err()));

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenSetQualifierFails)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": {"ParamA": {"initValue": 1}}}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};

    auto collection = std::make_shared<data_model::ParameterSetCollectionMock>();
    EXPECT_CALL(*collection, Insert(_, _, _)).WillOnce(::testing::Return(Ok()));
    EXPECT_CALL(*collection, SetParameterSetQualifier(_, _)).WillOnce(::testing::Return(Err()));

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

TEST(DemoParameterLoaderImplTest, LoadParameterDataFailsWhenSetCalibratableFails)
{
    auto json_any = R"({"parameterSets": {"DemoSet": {"parameters": {"ParamA": {"initValue": 1}}}}})"_json;
    DemoParameterLoaderImpl loader{std::move(json_any)};

    auto collection = std::make_shared<data_model::ParameterSetCollectionMock>();
    EXPECT_CALL(*collection, Insert(_, _, _)).WillOnce(::testing::Return(Ok()));
    EXPECT_CALL(*collection, SetParameterSetQualifier(_, _)).WillOnce(::testing::Return(Ok()));
    EXPECT_CALL(*collection, SetCalibratable(_, true)).WillOnce(::testing::Return(false));

    EXPECT_FALSE(loader.LoadParameterData(collection));
}

}  // namespace test
}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
