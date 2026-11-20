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
#include "score/config_management/lib/mw_com_types/runtime_sized_array.h"

#include <gtest/gtest.h>

#include <memory>

namespace score::config_management::mw_com_types
{
namespace
{

using IntArray = RuntimeSizedArray<int>;

TEST(RuntimeSizedArrayTest, StartsEmpty)
{
    IntArray array{std::allocator<int>{}};

    EXPECT_EQ(array.size(), 0U);
    EXPECT_EQ(array.Capacity(), 0U);
    EXPECT_EQ(array.Data(), nullptr);
}

TEST(RuntimeSizedArrayTest, ReservesAndEmplacesElements)
{
    IntArray array{std::allocator<int>{}};
    array.ReserveOnce(3U);

    EXPECT_EQ(array.size(), 0U);
    EXPECT_EQ(array.Capacity(), 3U);

    EXPECT_EQ(array.emplace_back(10), 10);
    EXPECT_EQ(array.emplace_back(20), 20);
    EXPECT_EQ(array.emplace_back(30), 30);
    EXPECT_EQ(array.size(), 3U);
    EXPECT_EQ(array.at(0U), 10);
    EXPECT_EQ(array.at(1U), 20);
    EXPECT_EQ(array.at(2U), 30);
}

TEST(RuntimeSizedArrayTest, ClearResetsSizeAndAllowsReuse)
{
    IntArray array{std::allocator<int>{}};
    array.ReserveOnce(2U);
    array.emplace_back(10);
    array.emplace_back(20);

    array.Clear();

    EXPECT_EQ(array.size(), 0U);
    EXPECT_EQ(array.Capacity(), 2U);
    EXPECT_EQ(array.emplace_back(30), 30);
    EXPECT_EQ(array.at(0U), 30);
}

TEST(RuntimeSizedArrayTest, ConstAccessReadsElements)
{
    IntArray array{std::allocator<int>{}};
    array.ReserveOnce(1U);
    array.emplace_back(42);
    const auto& const_array = array;

    EXPECT_EQ(const_array.at(0U), 42);
    EXPECT_EQ(const_array.Data()[0], 42);
}

}  // namespace
}  // namespace score::config_management::mw_com_types
