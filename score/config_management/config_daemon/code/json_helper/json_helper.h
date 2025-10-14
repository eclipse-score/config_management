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

#ifndef CODE_JSON_HELPER_JSON_HELPER_H
#define CODE_JSON_HELPER_JSON_HELPER_H

#include "score/filesystem/filestream/i_file_factory.h"
#include "score/filesystem/i_standard_filesystem.h"
#include "score/json/i_json_parser.h"
#include "score/json/i_json_writer.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace common
{

///
/// \brief This is interface of JsonHelper class
/// The JsonHelper class should encapsulate all the business logic for working with json files.
/// Further implementation of JsonHelper will be added in Ticket-96496
///

class IJsonHelper
{
  public:
    IJsonHelper() = default;
    virtual ~IJsonHelper() = default;
    IJsonHelper(IJsonHelper&&) = delete;
    IJsonHelper(const IJsonHelper&) = delete;

    IJsonHelper& operator=(IJsonHelper&&) = delete;
    IJsonHelper& operator=(const IJsonHelper&) = delete;

    virtual std::shared_ptr<json::IJsonParser> GetJsonParser() const noexcept = 0;
    virtual std::shared_ptr<json::IJsonWriter> GetJsonWriter() const noexcept = 0;
    virtual std::shared_ptr<filesystem::IStandardFilesystem> GetStandardFilesystem() const noexcept = 0;
    virtual std::shared_ptr<filesystem::IFileFactory> GetFileFactory() const noexcept = 0;
};

}  // namespace common
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_JSON_HELPER_JSON_HELPER_H
