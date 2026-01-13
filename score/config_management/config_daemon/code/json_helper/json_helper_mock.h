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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_JSON_HELPER_JSON_HELPER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_JSON_HELPER_JSON_HELPER_MOCK_H

#include "score/config_management/config_daemon/code/json_helper/json_helper.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace common
{

class JsonHelperMock final : public IJsonHelper
{
  public:
    MOCK_METHOD(std::shared_ptr<json::IJsonParser>, GetJsonParser, (), (const, noexcept, override));
    MOCK_METHOD(std::shared_ptr<json::IJsonWriter>, GetJsonWriter, (), (const, noexcept, override));
    MOCK_METHOD(std::shared_ptr<filesystem::IStandardFilesystem>,
                GetStandardFilesystem,
                (),
                (const, noexcept, override));
    MOCK_METHOD(std::shared_ptr<filesystem::IFileFactory>, GetFileFactory, (), (const, noexcept, override));
};

}  // namespace common
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_JSON_HELPER_JSON_HELPER_MOCK_H
