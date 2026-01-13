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
#include "score/config_management/config_provider/code/persistency/details/persistency_empty.h"
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

TEST_F(PersistencyImplTest, Test_ReadCachedParameterSets)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::PersistencyImpl::ReadCachedParameterSets()");
    RecordProperty("Description", "This test verifies that ReadCachedParameterSets is called without exceptions.");

    // Given there is no cached values
    ParameterMap cached_parameter_set;
    score::filesystem::Filesystem filesystem = score::filesystem::FilesystemFactory{}.CreateInstance();
    sut_->ReadCachedParameterSets(cached_parameter_set, score::cpp::pmr::get_default_resource(), filesystem);
}

TEST_F(PersistencyImplTest, Test_CacheParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::PersistencyImpl::CacheParameterSet()");
    RecordProperty("Description", "This test verifies that CacheParameterSet is called without exceptions.");

    // Given there is no content to be cached
    ParameterMap cached_parameter_set;
    // Then CacheParameterSet would execute without exceptions
    EXPECT_NO_THROW(sut_->CacheParameterSet(cached_parameter_set, "", nullptr, false));
}

TEST_F(PersistencyImplTest, Test_SyncToStorage)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::PersistencyImpl::SyncToStorage()");
    RecordProperty("Description", "This test verifies that SyncToStorage is called without exceptions.");

    // Given an existing persistency
    // Then SyncToStorage would execute without exceptions
    EXPECT_NO_THROW(sut_->SyncToStorage());
}

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
