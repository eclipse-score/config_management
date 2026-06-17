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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PARAMETER_SET_STORAGE_DETAILS_SCORE_KVS_STUB_KVS_MOCK_HPP
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PARAMETER_SET_STORAGE_DETAILS_SCORE_KVS_STUB_KVS_MOCK_HPP

#include "kvs.hpp"

#include <gmock/gmock.h>

namespace score::mw::per::kvs
{

class MockKvs final : public Kvs
{
  public:
    // NOLINTBEGIN(readability-identifier-naming)
    MOCK_METHOD(score::Result<KvsValue>, get_value, (std::string_view key), (noexcept, override));
    MOCK_METHOD(score::Result<void>, set_value, (std::string_view key, const KvsValue& value), (noexcept, override));
    MOCK_METHOD(score::Result<void>, flush, (), (noexcept, override));
    // NOLINTEND(readability-identifier-naming)
};

}  // namespace score::mw::per::kvs

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PARAMETER_SET_STORAGE_DETAILS_SCORE_KVS_STUB_KVS_MOCK_HPP
