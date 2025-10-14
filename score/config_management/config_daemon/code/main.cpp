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

#include "score/config_management/config_daemon/code/app/details/config_daemon_impl.h"
#include "score/config_management/config_daemon/code/factory/details/factory_impl.h"

#include "platform/aas/mw/lifecycle/runapplication.h"

#include <score/utility.hpp>

// Suppress AUTOSAR C++14 A15-3-3: Main function and a task main function shall catch at least: base class exceptions
// from all third-party libraries used, std::exception and all otherwise unhandled exceptions.
// Rationale: The project doesn't require exception capturing
// Suppress AUTOSAR C++14 A15-5-3:The std::terminate() function shall not be called implicitly.
// Rationale: Calling std::terminate() if any exceptions are thrown is expected as per safety requirements
// coverity[autosar_cpp14_a15_3_3_violation] see above
// coverity[autosar_cpp14_a15_5_3_violation] see above
int main(const int argc, const char* argv[])
{
    return score::mw::lifecycle::run_application<score::config_management::config_daemon::ConfigDaemon>(
        argc, argv, std::make_unique<score::config_management::config_daemon::Factory>());
}
