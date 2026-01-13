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
#include "score/config_management/config_provider/code/config_provider/factory/factory_mw_com.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

ConfigProviderFactory::ConfigProviderFactory() : logger_{mw::log::CreateLogger(std::string_view("CfgP"))} {}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
