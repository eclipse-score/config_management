#ifndef CODE_APP_DETAILS_CONFIG_DAEMON_IMPL_H
#define CODE_APP_DETAILS_CONFIG_DAEMON_IMPL_H

#include "score/config_management/config_daemon/code/app/config_daemon.h"
#include "score/config_management/config_daemon/code/factory/factory.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/plugin.h"

#include "score/result/result.h"
#include "score/mw/log/logger.h"
#include "platform/aas/mw/service/provided_service_container.h"

#include "memory"
#include "vector"

namespace score
{
namespace config_management
{
namespace config_daemon
{

class ConfigDaemon final : public IConfigDaemon
{
  public:
    using ApplicationContext = score::mw::lifecycle::ApplicationContext;

    explicit ConfigDaemon(std::unique_ptr<IFactory> factory) noexcept;
    ConfigDaemon(const ConfigDaemon&) = delete;
    ConfigDaemon(ConfigDaemon&&) = delete;
    ConfigDaemon& operator=(const ConfigDaemon&) = delete;
    ConfigDaemon& operator=(ConfigDaemon&&) = delete;
    ~ConfigDaemon() override = default;

    std::int32_t Initialize(const ApplicationContext& context) override;
    std::int32_t Run(const score::cpp::stop_token& token) override;

  private:
    std::int32_t PreparePlugins();

    mw::log::Logger& logger_;
    std::unique_ptr<IFactory> factory_;
    std::shared_ptr<data_model::IParameterSetCollection> parameterset_collection_;
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter_;
    mw::service::ProvidedServiceContainer provided_services_container_;
    std::vector<std::shared_ptr<IPlugin>> plugins_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_APP_DETAILS_CONFIG_DAEMON_IMPL_H
