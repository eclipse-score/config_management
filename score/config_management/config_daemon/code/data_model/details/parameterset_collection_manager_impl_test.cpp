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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_manager_impl.h"

#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/parameter_set_storage_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

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

using ::testing::_;

class ParameterSetCollectionManagerImplTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        primary_collection_ = std::make_shared<ParameterSetCollection>();

        auto plugin = std::make_shared<PluginMock>();
        plugin_mock_ = plugin.get();
        plugins_.push_back(std::move(plugin));

        auto storage = std::make_unique<ParameterSetStorageMock>();
        storage_mock_ = storage.get();

        sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, plugins_, std::move(storage));
    }

    std::shared_ptr<ParameterSetCollection> primary_collection_;
    std::vector<std::shared_ptr<IPlugin>> plugins_;
    PluginMock* plugin_mock_{nullptr};
    ParameterSetStorageMock* storage_mock_{nullptr};
    std::unique_ptr<ParameterSetCollectionManager> sut_;
};

TEST_F(ParameterSetCollectionManagerImplTest,
       ParameterSetCollectionUpdateRequest_StorageReceivesCollectionAsPopulatedByPlugin)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Analysis of equivalence class and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest passes the temporary collection "
                   "to storage exactly as populated by the plugin, without the manager modifying "
                   "the qualifiers. The storage impl is responsible for overriding qualifiers to "
                   "kQualifying when writing to disk.");

    // The plugin inserts two parameter sets with different qualifiers.
    EXPECT_CALL(*plugin_mock_, ParameterSetCollectionUpdateStart(_))
        .WillOnce([](data_model::IParameterSetCollection& collection) -> ResultBlank {
            score::cpp::ignore = collection.Insert("set_a", "param1", json::Any{42});
            score::cpp::ignore = collection.SetParameterSetQualifier("set_a", ParameterSetQualifier::kQualified);

            score::cpp::ignore = collection.Insert("set_b", "param2", json::Any{99});
            score::cpp::ignore = collection.SetParameterSetQualifier("set_b", ParameterSetQualifier::kModified);

            return {};
        });
    EXPECT_CALL(*storage_mock_, StoreParameterSetCollection(_))
        .WillOnce([](data_model::IParameterSetCollection& collection) -> ResultBlank {
            const auto qualifier_a = collection.GetParameterSetQualifier("set_a");
            EXPECT_TRUE(qualifier_a.has_value());
            EXPECT_EQ(ParameterSetQualifier::kQualified, qualifier_a.value());

            const auto qualifier_b = collection.GetParameterSetQualifier("set_b");
            EXPECT_TRUE(qualifier_b.has_value());
            EXPECT_EQ(ParameterSetQualifier::kModified, qualifier_b.value());

            return {};
        });

    EXPECT_TRUE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

}  // namespace
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
