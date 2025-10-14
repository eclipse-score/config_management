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

#ifndef CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_MOCK_H
#define CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_MOCK_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces/read_only_parameterset_collection.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

class ReadOnlyParameterSetCollectionMock final : public IReadOnlyParameterSetCollection
{
  public:
    ReadOnlyParameterSetCollectionMock();
    ReadOnlyParameterSetCollectionMock(ReadOnlyParameterSetCollectionMock&&) noexcept = delete;
    ReadOnlyParameterSetCollectionMock(const ReadOnlyParameterSetCollectionMock&) noexcept = delete;
    ReadOnlyParameterSetCollectionMock& operator=(ReadOnlyParameterSetCollectionMock&&) noexcept = delete;
    ReadOnlyParameterSetCollectionMock& operator=(const ReadOnlyParameterSetCollectionMock&) noexcept = delete;
    virtual ~ReadOnlyParameterSetCollectionMock() noexcept;

    MOCK_METHOD(Result<score::cpp::pmr::string>, GetParameterSet, (const std::string set_name), (const, noexcept, override));
    MOCK_METHOD(Result<json::Any>,
                GetParameterFromSet,
                (const score::cpp::string_view set_name, const score::cpp::string_view parameter_name),
                (const, noexcept, override));
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
#endif  // CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_MOCK_H
