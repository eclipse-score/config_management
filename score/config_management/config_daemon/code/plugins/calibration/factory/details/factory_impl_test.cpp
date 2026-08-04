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
#include <gtest/gtest.h>

#include "score/config_management/config_daemon/code/plugins/calibration/factory/details/factory_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service.h"
#include "score/mw/service/provided_service_container.h"

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/details/param_set_mapping_impl.hpp"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping_mock.h"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer_mock.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/secure_debug.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"
#include "score/mw/service/get_proxy.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

using testing::_;
using testing::Exactly;
using testing::Invoke;
using testing::Return;

class ProvidedServicesMock final : public score::mw::service::ProvidedServicesBase
{
  public:
    MOCK_METHOD(std::size_t, Count, (), (const, noexcept, override));
    MOCK_METHOD(void, StartAll, (), (noexcept, override));
    MOCK_METHOD(void, StopAll, (), (noexcept, override));
};

template <typename P>
void SetupTestEnvironmentForProxy(mw::core::InstanceSpecifier instance_specifier)
{
    P::CreateFindProxy();
    EXPECT_CALL(*(P::GetFindProxyInstance()), StartFindService(_, instance_specifier))
        .Times(Exactly(1))
        .WillOnce(Invoke([&](auto&& callback, auto&& /*instance_specifier*/) {
            typename P::HandleType proxy_handle{mw::com::InstanceIdentifier{{}}};
            callback({{proxy_handle}});
            return mw::com::FindServiceHandle{};
        }));
}

template <typename P>
void TearOffTestEnvironmentForProxy()
{
    P::DestroyFindProxy();
}

TEST(Factory, CanCreate)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::Factory()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description", "This test ensures that Factory can be created succesfully");
    EXPECT_NO_THROW(FactoryImpl unit);
}

TEST(Factory, CreateParameterLoaderTest)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateParameterLoader()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test ensures that CreateParameterLoader() returns a valid "
                   "InternalConfigProviderService object");
    auto calibration_data = std::make_unique<score::Result<json::Any>>();
    auto param_set_mapping_mock = std::make_shared<score::config_management::config_daemon::coding::ParamSetMappingMock>();
    auto parameter_data_handler_mock = std::make_shared<data_model::ParameterSetCollectionMock>();

    FactoryImpl unit;
    auto parameter_loader = unit.CreateParameterLoader(
        std::move(calibration_data), std::move(param_set_mapping_mock), nullptr, nullptr, nullptr);
    ASSERT_NE(nullptr, parameter_loader.get()) << "Factory did not return a valid ParameterLoader object";
    const bool is_param_data_loaded = parameter_loader->LoadParameterData(parameter_data_handler_mock);
    EXPECT_FALSE(is_param_data_loaded);  // calibraiton_data is empty
}

TEST(Factory, CreateCalibrationService)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateCalibrationService()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test ensures that CreateCalibrationService() returns a valid "
                   "InternalConfigProviderService object");
    auto parameterset_collection_mock = std::make_unique<data_model::ParameterSetCollectionMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };
    auto calibration_update_observer_mock = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();

    FactoryImpl unit;
    auto provided_service = unit.CreateCalibrationService(std::move(parameterset_collection_mock),
                                                          std::move(last_updated_parameter_set_sender),
                                                          calibration_update_observer_mock);
    EXPECT_EQ(provided_service->Count(), 1);
}

TEST(Factory, CreateCalibrationServiceFailDueToInvalidConfigCalibrationServiceId)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateCalibrationService()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test ensures that CreateCalibrationService() returns nullptr "
                   "in case of invalid config calibration service id");
    ConfigCalibrationSkeleton::CreateConstructionMockInstance();
    auto parameterset_collection_mock = std::make_unique<data_model::ParameterSetCollectionMock>();
    auto last_updated_parameter_set_sender = [](const std::string_view) noexcept {
        return true;
    };
    auto calibration_update_observer_mock = std::make_shared<runtime_calibration::CalibrationUpdateObserverMock>();
    // Expect ConfigCalibrationSkeleton::Preconstruct return construction token
    EXPECT_CALL(*ConfigCalibrationSkeleton::GetConstructionMockInstance(),
                Preconstruct(::testing::An<mw::core::InstanceSpecifier>(), testing::_))
        .Times(1)
        .WillOnce(Return(
            ConfigCalibrationSkeleton::ConstructionResult::FromError(mw::core::ErrorCode{mw::core::future_errc{}})));

    FactoryImpl unit;
    auto provided_service = unit.CreateCalibrationService(
        std::move(parameterset_collection_mock), last_updated_parameter_set_sender, calibration_update_observer_mock);
    EXPECT_EQ(provided_service, nullptr);
    ConfigCalibrationSkeleton::DestroyConstructionMockInstance();
}

TEST(Factory, CreateServiceToggler)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateServiceToggler()");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Description",
                   "This test ensures that CreateServiceToggler() returns a valid ServiceToggler object");
    auto provided_services = std::make_unique<ProvidedServicesMock>();
    EXPECT_CALL(*provided_services, StartAll()).Times(1);

    FactoryImpl unit;
    auto res = unit.CreateServiceToggler(std::move(provided_services));
    res->ToggleInterface(true);

    EXPECT_TRUE(res != nullptr);
}

TEST(Factory, CreateCalibrationProxies)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateCalibrationProxies()");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("Description",
                   "This test ensures that CreateCalibrationProxies() returns a valid CalibrationProxies object");

    // Given SecureDebug setup
    SetupTestEnvironmentForProxy<SecureDebug::AdaptiveProxy>(
        mw::core::InstanceSpecifier{mw::core::StringView{"ConfigDaemon/ConfigDaemon_RootSwc/SecureDebugRPort"}});

    // When Calling CreateCalibrationProxies()
    FactoryImpl unit;
    auto proxy = unit.CreateCalibrationProxies();
    const score::cpp::stop_token empty_token;

    // Then a valid SecureDebugProxy is created
    const auto proxy_container = proxy.InitiateServiceDiscovery(empty_token);
    TearOffTestEnvironmentForProxy<SecureDebug::AdaptiveProxy>();
}

TEST(Factory, CreateSecureDebugFuture)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateSecureDebugFuture()");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("Description", "This test ensures that CreateSecureDebugFuture() returns a valid SecureDebugFuture");

    // Given SecureDebug setup
    SetupTestEnvironmentForProxy<SecureDebug::AdaptiveProxy>(
        mw::core::InstanceSpecifier{mw::core::StringView{"ConfigDaemon/ConfigDaemon_RootSwc/SecureDebugRPort"}});

    // When Calling CreateSecureDebugFuture()
    FactoryImpl unit;
    const score::cpp::stop_token empty_token;
    auto proxy = unit.CreateCalibrationProxies();
    auto proxy_container = proxy.WaitForMandatoryProxies(empty_token);

    auto secure_debug_proxy_data = unit.CreateSecureDebugFuture(proxy_container);
    auto secure_debug_proxy = mw::service::GetProxyFromFuture<ISecureDebug>(
        secure_debug_proxy_data.GetProxyFuture(), "SecureDebug proxy", empty_token, std::chrono::milliseconds{0U});

    // secure_debug_proxy is valid
    ASSERT_NE(secure_debug_proxy, nullptr);
    TearOffTestEnvironmentForProxy<SecureDebug::AdaptiveProxy>();
}
TEST(Factory, CreateParamSetMapping)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::Factory::CreateParamSetMapping()");
    RecordProperty("Description",
                   "This test ensures that CreateParamSetMapping() returns a valid ParamSetMapping object");

    FactoryImpl unit;

    // When calling CreateParamSetMapping()
    const auto param_set_mapping = unit.CreateParamSetMapping();

    // Then the returned param_set_mapping instance must be valid
    auto* param_set_mapping_instance =
        dynamic_cast<score::config_management::config_daemon::coding::ParamSetMapping*>(param_set_mapping.get());
    ASSERT_NE(nullptr, param_set_mapping_instance) << "Factory did not return a valid ParamSetMapping object";
}

TEST(Factory, CreateCalibrationUpdateObserver)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::calibration::Factory::CreateCalibrationUpdateObserver()");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("Description",
                   "This test ensures that CreateCalibrationUpdateObserver() returns a valid "
                   "CalibrationUpdateObserver");

    FactoryImpl unit;
    auto calibration_update_observer = unit.CreateCalibrationUpdateObserver();
    ASSERT_NE(calibration_update_observer, nullptr);

    EXPECT_TRUE(calibration_update_observer->ReportParameterUpdate());
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
