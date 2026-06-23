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
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_mock.h"
#include "score/config_management/config_daemon/code/types/initial_qualifier_state/initial_qualifier_state.h"

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
using ::testing::Return;

class ParameterSetCollectionManagerImplTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        primary_collection_ = std::make_shared<ParameterSetCollection>();

        auto plugin = std::make_shared<PluginMock>();
        plugin_mock_ = plugin.get();
        plugins_.push_back(std::move(plugin));

        CreateSutWithLoadResult(Result<bool>{false});
    }

    void CreateSutWithLoadResult(Result<bool> load_result)
    {
        auto storage = std::make_unique<ParameterSetStorageMock>();
        storage_mock_ = storage.get();
        ON_CALL(*storage_mock_, LoadParameterSetCollection(_)).WillByDefault(Return(load_result));
        sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, plugins_, std::move(storage));
        score::cpp::ignore = sut_->LoadParameterSetCollectionFromStorage();
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
        .WillOnce([](data_model::IParameterSetCollection& collection) -> Result<void> {
            score::cpp::ignore = collection.Insert("set_a", "param1", json::Any{42});
            score::cpp::ignore = collection.SetParameterSetQualifier("set_a", ParameterSetQualifier::kQualified);

            score::cpp::ignore = collection.Insert("set_b", "param2", json::Any{99});
            score::cpp::ignore = collection.SetParameterSetQualifier("set_b", ParameterSetQualifier::kModified);

            return {};
        });
    EXPECT_CALL(*storage_mock_, StoreParameterSetCollection(_))
        .WillOnce([](data_model::IParameterSetCollection& collection) -> Result<void> {
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

TEST_F(ParameterSetCollectionManagerImplTest,
       LoadParameterSetCollectionFromStorage_SetsKQualifyingForAllSetsWhenActualDataLoaded)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "75483749");
    RecordProperty("Description",
                   "Verifies that all ParameterSet qualifiers are set to kQualifying when "
                   "storage_->LoadParameterSetCollection() returns Result<bool>{true} (actual data loaded).");

    // Given: storage returns actual data and populates the collection with two sets
    auto storage = std::make_unique<ParameterSetStorageMock>();
    storage_mock_ = storage.get();
    ON_CALL(*storage_mock_, LoadParameterSetCollection(_))
        .WillByDefault([](data_model::IParameterSetCollection& collection) -> Result<bool> {
            score::cpp::ignore = collection.Insert("set_a", "param1", json::Any{42});
            score::cpp::ignore = collection.Insert("set_b", "param2", json::Any{99});
            return Result<bool>{true};
        });
    sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, plugins_, std::move(storage));
    const auto result = sut_->LoadParameterSetCollectionFromStorage();

    // Then: all sets have kQualifying qualifier
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(InitialQualifierState::kQualifying, result.value());

    const auto qualifier_a = primary_collection_->GetParameterSetQualifier("set_a");
    ASSERT_TRUE(qualifier_a.has_value());
    EXPECT_EQ(ParameterSetQualifier::kQualifying, qualifier_a.value());

    const auto qualifier_b = primary_collection_->GetParameterSetQualifier("set_b");
    ASSERT_TRUE(qualifier_b.has_value());
    EXPECT_EQ(ParameterSetQualifier::kQualifying, qualifier_b.value());
}

TEST_F(ParameterSetCollectionManagerImplTest,
       LoadParameterSetCollectionFromStorage_SetsKDefaultForAllSetsWhenDefaultDataLoaded)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "75483427, 75570264");
    RecordProperty("Description",
                   "Verifies that all ParameterSet qualifiers are set to kDefault when "
                   "storage_->LoadParameterSetCollection() returns Result<bool>{false} (default data loaded).");

    // Given: storage returns default data and populates the collection with one set
    auto storage = std::make_unique<ParameterSetStorageMock>();
    storage_mock_ = storage.get();
    ON_CALL(*storage_mock_, LoadParameterSetCollection(_))
        .WillByDefault([](data_model::IParameterSetCollection& collection) -> Result<bool> {
            score::cpp::ignore = collection.Insert("set_a", "param1", json::Any{42});
            return Result<bool>{false};
        });
    sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, plugins_, std::move(storage));
    const auto result = sut_->LoadParameterSetCollectionFromStorage();

    // Then: all sets have kDefault qualifier
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(InitialQualifierState::kDefault, result.value());

    const auto qualifier_a = primary_collection_->GetParameterSetQualifier("set_a");
    ASSERT_TRUE(qualifier_a.has_value());
    EXPECT_EQ(ParameterSetQualifier::kDefault, qualifier_a.value());
}

TEST_F(ParameterSetCollectionManagerImplTest, GetParameterSetCollection_ReturnsPrimaryCollection)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Description",
                   "Verifies that GetParameterSetCollection() returns the same collection that was "
                   "passed to the constructor.");

    EXPECT_EQ(sut_->GetParameterSetCollection(), primary_collection_);
}

TEST_F(ParameterSetCollectionManagerImplTest,
       LoadParameterSetCollectionFromStorage_LogsErrorWhenSetParameterSetQualifierFails)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that construction completes without crashing when "
                   "SetParameterSetQualifier returns an error while applying initial qualifiers.");

    auto mock_collection = std::make_shared<ParameterSetCollectionMock>();
    auto storage = std::make_unique<ParameterSetStorageMock>();
    storage_mock_ = storage.get();
    ON_CALL(*storage_mock_, LoadParameterSetCollection(_))
        .WillByDefault([](data_model::IParameterSetCollection& collection) -> Result<bool> {
            score::cpp::ignore = collection.Insert("set_a", "param1", json::Any{42});
            return Result<bool>{true};
        });

    ON_CALL(*mock_collection, GetParameterSetCollectionAsJson()).WillByDefault([]() -> Result<json::Object> {
        json::Object one_entry{};
        one_entry["set_a"] = json::Any{std::int64_t{42}};
        return one_entry;
    });
    ON_CALL(*mock_collection, SetParameterSetQualifier(_, _))
        .WillByDefault(Return(MakeUnexpected(score::json::Error::kParsingError, "qualifier error")));

    sut_ = std::make_unique<ParameterSetCollectionManager>(mock_collection, plugins_, std::move(storage));
    // LoadParameterSetCollectionFromStorage must not crash; qualifier-set failures are only logged
    const auto result = sut_->LoadParameterSetCollectionFromStorage();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(InitialQualifierState::kQualifying, result.value());
}

TEST_F(ParameterSetCollectionManagerImplTest, ParameterSetCollectionUpdateRequest_FailsWhenNoPlugins)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest returns an error when "
                   "the plugin list is empty.");

    std::vector<std::shared_ptr<IPlugin>> no_plugins{};
    auto storage = std::make_unique<ParameterSetStorageMock>();
    storage_mock_ = storage.get();
    sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, no_plugins, std::move(storage));

    EXPECT_FALSE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

TEST_F(ParameterSetCollectionManagerImplTest, ParameterSetCollectionUpdateRequest_FailsWhenPluginHasExpired)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest returns an error when "
                   "a plugin weak_ptr has expired before the update runs.");

    // Build a sut with one plugin, then let the plugin expire
    auto expiring_plugin = std::make_shared<PluginMock>();
    std::vector<std::shared_ptr<IPlugin>> expiring_plugins{expiring_plugin};
    auto storage = std::make_unique<ParameterSetStorageMock>();
    storage_mock_ = storage.get();
    sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, expiring_plugins, std::move(storage));

    // Let the plugin expire after construction — must release ALL shared_ptr owners
    expiring_plugin.reset();
    expiring_plugins.clear();

    EXPECT_FALSE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

TEST_F(ParameterSetCollectionManagerImplTest, ParameterSetCollectionUpdateRequest_FailsWhenPluginUpdateFails)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest returns an error when "
                   "a plugin's ParameterSetCollectionUpdateStart returns an error.");

    EXPECT_CALL(*plugin_mock_, ParameterSetCollectionUpdateStart(_))
        .WillOnce(Return(MakeUnexpected(score::json::Error::kParsingError, "plugin update error")));

    EXPECT_FALSE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

TEST_F(ParameterSetCollectionManagerImplTest, ParameterSetCollectionUpdateRequest_FailsWhenStoreFails)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest returns an error when "
                   "storage_->StoreParameterSetCollection fails.");

    EXPECT_CALL(*plugin_mock_, ParameterSetCollectionUpdateStart(_)).WillOnce(Return(Result<void>{}));
    EXPECT_CALL(*storage_mock_, StoreParameterSetCollection(_))
        .WillOnce(Return(MakeUnexpected(score::json::Error::kParsingError, "store error")));

    EXPECT_FALSE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

TEST_F(ParameterSetCollectionManagerImplTest, ParameterSetCollectionUpdateRequest_SucceedsWhenStorageIsNull)
{
    RecordProperty("Priority", "1");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Description",
                   "Verifies that ParameterSetCollectionUpdateRequest succeeds (without persisting) "
                   "when storage is nullptr.");

    sut_ = std::make_unique<ParameterSetCollectionManager>(primary_collection_, plugins_, nullptr);

    EXPECT_CALL(*plugin_mock_, ParameterSetCollectionUpdateStart(_)).WillOnce(Return(Result<void>{}));

    EXPECT_TRUE(sut_->ParameterSetCollectionUpdateRequest().has_value());
}

}  // namespace
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
