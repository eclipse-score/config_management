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
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/services/details/internal_config_provider_service_reactor_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

using testing::Return;

class InternalConfigProviderReactorTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        parameterset_collection_mock_ = std::make_shared<data_model::ParameterSetCollectionMock>();
    }

    void TearDown() override
    {
        parameterset_collection_mock_.reset();
    }

    std::shared_ptr<data_model::ParameterSetCollectionMock> parameterset_collection_mock_;
};

TEST_F(InternalConfigProviderReactorTest, GetParameterSetSucceeds)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::InternalConfigProviderServiceReactorImpl::GetParameterSet()");
    RecordProperty("Description",
                   "This test ensures that GetParameterSet() returns ParameterSet, when ConfigProvider client lib "
                   "calls it with correct ParameterSet name");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");

    const std::string param_set_name = "parameter_set_1";

    EXPECT_CALL(*parameterset_collection_mock_, GetParameterSet(param_set_name))
        .WillOnce(Return(score::Result<score::cpp::pmr::string>(R"({"param_name_a": 42, "param_name_b": "test"})")));

    InternalConfigProviderServiceReactorImpl reactor{parameterset_collection_mock_};
    auto result = reactor.GetParameterSet(param_set_name);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), R"({"param_name_a": 42, "param_name_b": "test"})");
}

TEST_F(InternalConfigProviderReactorTest, GetParameterSetFailsWithKeyNotFound)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::InternalConfigProviderServiceReactorImpl::GetParameterSet()");
    RecordProperty("Description",
                   "This test ensures that GetParameterSet() returns ParameterSet, when ConfigProvider client lib "
                   "calls it with wrong ParameterSet name");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");

    const std::string param_set_name = "non_existent_parameter_set";

    EXPECT_CALL(*parameterset_collection_mock_, GetParameterSet(param_set_name))
        .WillOnce(Return(MakeUnexpected(data_model::DataModelError::kParameterSetNotFound)));

    InternalConfigProviderServiceReactorImpl reactor{parameterset_collection_mock_};
    auto result = reactor.GetParameterSet(param_set_name);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), data_model::DataModelError::kParameterSetNotFound);
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
