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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_SERVICE_CONTAINER_SELECTOR_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_SERVICE_CONTAINER_SELECTOR_H

#ifdef SCORE_BUILD
#include "score/config_management/config_daemon/code/factory/stub_service_container.h"
#else
#include "platform/aas/mw/service/provided_service_container.h"
#endif

namespace score
{
namespace config_management
{
namespace config_daemon
{

#ifdef SCORE_BUILD
using ProvidedServiceContainer = score::config_management::config_daemon::StubServiceContainer;
#else
using ProvidedServiceContainer = score::mw::service::ProvidedServiceContainer;
#endif

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_SERVICE_CONTAINER_SELECTOR_H
