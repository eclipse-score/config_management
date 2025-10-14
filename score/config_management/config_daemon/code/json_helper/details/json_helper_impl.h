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

#ifndef CODE_JSON_HELPER_DETAILS_JSON_HELPER_IMPL_H
#define CODE_JSON_HELPER_DETAILS_JSON_HELPER_IMPL_H

#include "score/config_management/config_daemon/code/json_helper/json_helper.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace common
{

class JsonHelper final : public IJsonHelper
{
  public:
    JsonHelper();
    ~JsonHelper() override = default;
    JsonHelper(JsonHelper&&) = delete;
    JsonHelper(const JsonHelper&) = delete;

    JsonHelper& operator=(JsonHelper&&) = delete;
    JsonHelper& operator=(const JsonHelper&) = delete;

    std::shared_ptr<json::IJsonParser> GetJsonParser() const noexcept override;
    std::shared_ptr<json::IJsonWriter> GetJsonWriter() const noexcept override;
    std::shared_ptr<filesystem::IStandardFilesystem> GetStandardFilesystem() const noexcept override;
    std::shared_ptr<filesystem::IFileFactory> GetFileFactory() const noexcept override;

  private:
    std::shared_ptr<json::IJsonParser> json_parser_;
    std::shared_ptr<json::IJsonWriter> json_writer_;
    std::shared_ptr<filesystem::IStandardFilesystem> standart_filesystem_;
    std::shared_ptr<filesystem::IFileFactory> file_factory_;
};

}  // namespace common
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_JSON_HELPER_DETAILS_JSON_HELPER_IMPL_H
