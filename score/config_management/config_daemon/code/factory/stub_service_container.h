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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_STUB_SERVICE_CONTAINER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_STUB_SERVICE_CONTAINER_H

#include <cstddef>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

/// @brief Abstracts the communication mechanism being used.
/// @details This class wraps a ProvidedServiceContainer and provides a backend-agnostic API
///          using the Pimpl idiom to hide implementation details
class StubServiceContainer final
{
  public:
    /// @brief Default constructor
    StubServiceContainer() noexcept = default;

    StubServiceContainer& operator=(StubServiceContainer&&) & noexcept = default;
    StubServiceContainer& operator=(const StubServiceContainer&) & = delete;
    StubServiceContainer(StubServiceContainer&&) noexcept = default;
    StubServiceContainer(const StubServiceContainer&) = delete;

    ~StubServiceContainer() noexcept = default;

    /// @brief Get access to the underlying ProvidedServices instance
    /// @tparam ServiceDecorator the decorator class template parameter used for the ProvidedServices
    /// @return const pointer to the ProvidedServices instance if the dynamic_cast succeeds, nullptr otherwise
    template <template <typename> class ServiceDecorator>
    const auto* GetServices() const noexcept
    {
        return nullptr;
    }

    template <template <typename> class ServiceDecorator>
    auto* GetServices() noexcept
    {
        return nullptr;
    }

    /// @brief Get the total number of services contained in this container
    /// @return the number of services, or 0 if no services are contained
    std::size_t NumServices() const noexcept
    {
        return num_services_;
    }

    /// @brief Start all services contained in this container
    /// @details If no services are contained, this operation has no effect
    void StartServices() noexcept {}

    /// @brief Stop all services contained in this container
    /// @details If no services are contained, this operation has no effect
    void StopServices() noexcept {}

    /// @brief Allows to set the number of services contained in this container
    /// @param num_services the number of services to be considered as contained
    /// @details This is not part of the public API, but is provided to facilitate testing
    void SetNumServices(std::size_t num_services) noexcept
    {
        num_services_ = num_services;
    }

  private:
    std::size_t num_services_{0};
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_STUB_SERVICE_CONTAINER_H
