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
#include "score/config_management/config_daemon/code/initial_qualifier_container/details/initial_qualifier_container_impl.h"

#include <gtest/gtest.h>

#include <future>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace
{

TEST(InitialQualifierContainerTest, StoresQualifierStateLocally)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "6950593");
    RecordProperty("ASIL", "B");
    RecordProperty("Description",
                   "This test verifies that the qualifier container starts undefined and stores the latest state.");

    InitialQualifierContainerImpl unit;

    EXPECT_EQ(InitialQualifierState::kUndefined, unit.GetInitialQualifierState());

    unit.SetInitialQualifierState(InitialQualifierState::kInProgress);
    unit.SetInitialQualifierState(InitialQualifierState::kQualified);
    EXPECT_EQ(InitialQualifierState::kQualified, unit.GetInitialQualifierState());
}

TEST(InitialQualifierContainerTest, ConcurrentWritersKeepOneOfTheirStates)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "15580321, 6950608");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "This test exercises concurrent access to the shared qualifier container.");

    InitialQualifierContainerImpl unit;

    std::promise<void> go, first_writer_ready, second_writer_ready;
    std::shared_future<void> ready{go.get_future()};

    auto first_writer = std::async(std::launch::async, [&]() {
        first_writer_ready.set_value();
        ready.wait();
        unit.SetInitialQualifierState(InitialQualifierState::kInProgress);
        return unit.GetInitialQualifierState();
    });
    auto second_writer = std::async(std::launch::async, [&]() {
        second_writer_ready.set_value();
        ready.wait();
        unit.SetInitialQualifierState(InitialQualifierState::kQualified);
        return unit.GetInitialQualifierState();
    });

    first_writer_ready.get_future().wait();
    second_writer_ready.get_future().wait();

    go.set_value();

    const auto first_state = first_writer.get();
    const auto second_state = second_writer.get();
    EXPECT_TRUE(first_state == InitialQualifierState::kInProgress || first_state == InitialQualifierState::kQualified);
    EXPECT_TRUE(second_state == InitialQualifierState::kInProgress ||
                second_state == InitialQualifierState::kQualified);
    const auto final_state = unit.GetInitialQualifierState();
    EXPECT_TRUE(final_state == InitialQualifierState::kInProgress || final_state == InitialQualifierState::kQualified);
}

}  // namespace
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
