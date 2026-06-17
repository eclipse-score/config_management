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
#include "score/config_management/config_provider/code/persistency/details/persistency_impl.h"
#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace
{

class PersistencyImplTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        sut_ = std::make_unique<PersistencyImpl>();
    }

    std::unique_ptr<PersistencyImpl> sut_;
};

TEST_F(PersistencyImplTest, ReadParameterSetsByNameListFromFile_DoesNothing)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_provider::PersistencyImpl::ReadParameterSetsByNameListFromFile()");
    RecordProperty("Description",
                   "This test verifies that ReadParameterSetsByNameListFromFile on PersistencyImpl leaves the "
                   "parameter set cache unchanged.");

    ParameterMap cached_parameter_sets;
    score::cpp::pmr::vector<std::string_view> set_names{"SomeName"};

    sut_->ReadParameterSetsByNameListFromFile(cached_parameter_sets, set_names, score::cpp::pmr::get_default_resource());

    EXPECT_TRUE(cached_parameter_sets.empty());
}

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
