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

#include "score/config_management/config_daemon/code/app/config_daemon.h"

#include "score/mwcoreinitwrapper/mocklib/mwcoreinitializer_mock.hpp"
#include "platform/aas/mw/lifecycle/test/ut/mocks/applicationcontextmock.h"
#include "platform/aas/mw/lifecycle/test/ut/mocks/mwlifecyclemanagermock.h"
#include "platform/aas/mw/lifecycle/test/ut/mocks/lifecyclemanagermock.h"

#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace test
{

class TestMainFunction
{
  public:
    TestMainFunction()
    {
        mw_core_initializer_mock_ = std::make_unique<score::mwcoreinitwrapper::MwCoreInitializerMock>();
        mw_lifecycle_manager_mock_ = std::make_unique<score::mw::lifecycle::MwLifeCycleManagerMock>();
        application_context_mock_ = std::make_unique<score::mw::lifecycle::ApplicationContextMock>();
        lifecycle_manager_mock_ = std::make_unique<score::mw::lifecycle::LifeCycleManagerMock>();

        lifecycle_manager_mock_->SetCallbackForRunMethod([this](auto& application_instance,
                                                                const auto& /*application_context*/) -> std::int32_t {
            ++lifecycle_manager_run_method_invocation_counter_;
            auto* config_daemon_app = dynamic_cast<score::config_management::config_daemon::IConfigDaemon*>(&application_instance);
            if (config_daemon_app == nullptr)
            {
                std::cerr << "\nTestMainFunction FAILED: application_instance being run by LifeCycleManager is "
                             "not of type ConfigDaemonApp!"
                          << std::endl;
                std::exit(EXIT_FAILURE);
            }
            return EXIT_SUCCESS;
        });
    }

    ~TestMainFunction()
    {
        lifecycle_manager_mock_->ResetCallbackForRunMethod();
        if (lifecycle_manager_run_method_invocation_counter_ != 1)
        {
            std::cerr << "\nTestMainFunction failed: score::mw::lifecycle::mw::LifeCycleManager::run() "
                         "did not get invoked exactly once but "
                      << lifecycle_manager_run_method_invocation_counter_ << " times!\n"
                      << std::endl;
            std::exit(EXIT_FAILURE);
        }

        lifecycle_manager_mock_.reset();
        application_context_mock_.reset();
        mw_lifecycle_manager_mock_.reset();
        mw_core_initializer_mock_.reset();
    }

  private:
    std::unique_ptr<score::mwcoreinitwrapper::MwCoreInitializerMock> mw_core_initializer_mock_{};
    std::unique_ptr<score::mw::lifecycle::MwLifeCycleManagerMock> mw_lifecycle_manager_mock_{};
    std::unique_ptr<score::mw::lifecycle::ApplicationContextMock> application_context_mock_{};
    std::unique_ptr<score::mw::lifecycle::LifeCycleManagerMock> lifecycle_manager_mock_{};

    std::uint64_t lifecycle_manager_run_method_invocation_counter_{0};
};

// We create the object as static one so that it gets constructed prior to function main()
// being invoked and so that it gets destroyed after the function main() finished.
// That way we can check the expectation(s) verified in the destructor above.
TestMainFunction gTestMainFunction{};

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
