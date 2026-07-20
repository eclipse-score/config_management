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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/details/service_toggler_impl.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{
namespace test
{

class ProvidedServicesMock final : public score::mw::service::ProvidedServicesBase
{
  public:
    MOCK_METHOD(std::size_t, Count, (), (const, noexcept, override));
    MOCK_METHOD(void, StartAll, (), (noexcept, override));
    MOCK_METHOD(void, StopAll, (), (noexcept, override));
};

class ServiceTogglerImplTest : public ::testing::Test
{
};

TEST_F(ServiceTogglerImplTest, StartStopService)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540927, 20540962");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies success of starting/stopping ConfigCalibration service");

    auto provided_services = std::make_unique<ProvidedServicesMock>();
    EXPECT_CALL(*provided_services, StartAll()).Times(1);
    EXPECT_CALL(*provided_services, StopAll()).Times(1);
    ServiceTogglerImpl unit{std::move(provided_services)};

    // Start service
    unit.ToggleInterface(true);
    // Check for service stop
    unit.ToggleInterface(false);
}

TEST_F(ServiceTogglerImplTest, ServiceIsNotAvailable)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Fault injection test");
    RecordProperty("Verifies", "score::config_management::config_daemon::calibration::ServiceToggler::ToggleInterface()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test covers a code when ConfigCalibration service in not available");

    auto provided_services = std::make_unique<ProvidedServicesMock>();
    ServiceTogglerImpl unit{nullptr};

    unit.ToggleInterface(true);
}

TEST_F(ServiceTogglerImplTest, ServiceIsAreadyEnabled)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "20540927, 20540962");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Description", "This test verifies service is not enabled twice");

    auto provided_services = std::make_unique<ProvidedServicesMock>();
    EXPECT_CALL(*provided_services, StartAll()).Times(1);
    ServiceTogglerImpl unit{std::move(provided_services)};

    // Start service
    unit.ToggleInterface(true);
    // Start service again
    unit.ToggleInterface(true);
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
