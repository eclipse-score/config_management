// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
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
#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_provider
{

void TestMessage(ConfigProviderError error, const char* message)
{
    EXPECT_EQ(MakeError(error).Message(), message);
}

TEST(ConfigProviderErrorTest, CanConvertToString)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::MakeError()");
    RecordProperty(
        "Description",
        "This test verifies that all possible error types are covered with a corresponding error text message.");
    // Given all possible PersistencyError values
    // When MakeError is called
    // Then the correct message is returned
    TestMessage(ConfigProviderError::kParsingFailed, "JSON parsing failed");
    TestMessage(ConfigProviderError::kObjectCastingError, "Failed to cast JSON to object instance.");
    TestMessage(ConfigProviderError::kParameterNotFound, "Parameter name was not found in JSON");
    TestMessage(ConfigProviderError::kValueCastingError, "Failed to cast object instance to given C++ type");
    TestMessage(ConfigProviderError::kValueNotFound, "Failed to find parameter value in JSON.");
    TestMessage(ConfigProviderError::kProxyNotReady, "Proxy is not ready.");
    TestMessage(ConfigProviderError::kProxyAccessTimeout, "Proxy access did not finish in time.");
    TestMessage(ConfigProviderError::kProxyReturnedNoResult, "Proxy request did not return any result.");
    TestMessage(ConfigProviderError::kEmptyCallbackProvided, "Empty callback provided.");
    TestMessage(ConfigProviderError::kCallbackAlreadySet, "A callback is already set.");
    TestMessage(ConfigProviderError::kMethodNotSupported, "Method is not supported.");
    TestMessage(ConfigProviderError::kFailedToSubscribe, "Failed to subscribe to event.");
    TestMessage(static_cast<ConfigProviderError>(0xff), "Unknown Error!");
    TestMessage(static_cast<ConfigProviderError>(-1), "Unknown Error!");
    TestMessage(ConfigProviderError::kParameterSetNotFound, "Parameter set was not found");
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
