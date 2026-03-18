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

#include "kvs_mock.hpp"

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/details/parameter_set_storage_score_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/error/parameter_set_storage_error.h"
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
namespace data_model
{
namespace
{

using ::testing::Return;

constexpr std::string_view kParameterSetHashKvsKey{"ActualParameterHashKey"};

class ParameterSetStorageScoreImplTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto kvs = std::make_unique<score::mw::per::kvs::MockKvs>();
        kvs_mock_ = kvs.get();
        sut_ = std::make_unique<ParameterSetStorageScoreImpl>(std::move(kvs));
    }

    score::mw::per::kvs::MockKvs* kvs_mock_{nullptr};
    std::unique_ptr<ParameterSetStorageScoreImpl> sut_;
};

TEST_F(ParameterSetStorageScoreImplTest, StoreParameterSetCollection_EmptyCollection_Pass)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence class and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that StoreParameterSetCollection with an empty collection serializes, "
                   "hashes, and stores successfully via score KVS.");

    data_model::ParameterSetCollectionMock collection_mock{};
    EXPECT_CALL(collection_mock, GetParameterSetCollectionAsJson()).WillOnce([]() -> score::Result<json::Object> {
        return json::Object{};
    });

    EXPECT_CALL(*kvs_mock_, set_value(kParameterSetHashKvsKey, ::testing::_)).WillOnce(Return(score::ResultBlank{}));
    EXPECT_CALL(*kvs_mock_, flush()).WillOnce(Return(score::ResultBlank{}));

    EXPECT_TRUE(sut_->StoreParameterSetCollection(collection_mock).has_value());
}

TEST_F(ParameterSetStorageScoreImplTest, StoreParameterSetCollection_KvsSetValueFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence class and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that StoreParameterSetCollection returns kUnableToSaveToPersistency "
                   "when score KVS set_value fails.");

    data_model::ParameterSetCollectionMock collection_mock{};
    EXPECT_CALL(collection_mock, GetParameterSetCollectionAsJson()).WillOnce([]() -> score::Result<json::Object> {
        return json::Object{};
    });

    EXPECT_CALL(*kvs_mock_, set_value(kParameterSetHashKvsKey, ::testing::_))
        .WillOnce(Return(score::MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency)));
    EXPECT_CALL(*kvs_mock_, flush()).Times(0);

    EXPECT_FALSE(sut_->StoreParameterSetCollection(collection_mock).has_value());
}

TEST_F(ParameterSetStorageScoreImplTest, StoreParameterSetCollection_KvsFlushFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence class and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that StoreParameterSetCollection returns kUnableToSaveToPersistency "
                   "when score KVS flush fails.");

    data_model::ParameterSetCollectionMock collection_mock{};
    EXPECT_CALL(collection_mock, GetParameterSetCollectionAsJson()).WillOnce([]() -> score::Result<json::Object> {
        return json::Object{};
    });

    EXPECT_CALL(*kvs_mock_, set_value(kParameterSetHashKvsKey, ::testing::_)).WillOnce(Return(score::ResultBlank{}));
    EXPECT_CALL(*kvs_mock_, flush())
        .WillOnce(Return(score::MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency)));

    EXPECT_FALSE(sut_->StoreParameterSetCollection(collection_mock).has_value());
}

}  // namespace
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
