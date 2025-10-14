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

#include "score/config_management/config_daemon/code/json_helper/details/json_helper_impl.h"

#include "score/filesystem/details/standard_filesystem.h"
#include "score/json/json_parser.h"
#include "score/json/json_writer.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace common
{

JsonHelper::JsonHelper()
    : IJsonHelper{},
      json_parser_{std::make_shared<json::JsonParser>()},
      json_writer_{std::make_shared<json::JsonWriter>()},
      standart_filesystem_{std::make_shared<filesystem::StandardFilesystem>()},
      file_factory_{std::make_shared<filesystem::FileFactory>()}
{
}

std::shared_ptr<json::IJsonParser> JsonHelper::GetJsonParser() const noexcept
{
    return json_parser_;
}
std::shared_ptr<json::IJsonWriter> JsonHelper::GetJsonWriter() const noexcept
{
    return json_writer_;
}
std::shared_ptr<filesystem::IStandardFilesystem> JsonHelper::GetStandardFilesystem() const noexcept
{
    return standart_filesystem_;
}
std::shared_ptr<filesystem::IFileFactory> JsonHelper::GetFileFactory() const noexcept
{
    return file_factory_;
}

}  // namespace common
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
