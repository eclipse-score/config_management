#ifndef CODE_APP_CONFIG_DAEMON_H
#define CODE_APP_CONFIG_DAEMON_H

#include "platform/aas/mw/lifecycle/application.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

class IConfigDaemon : public score::mw::lifecycle::Application
{
  public:
    IConfigDaemon() noexcept = default;
    IConfigDaemon(IConfigDaemon&&) = delete;
    IConfigDaemon(const IConfigDaemon&) = delete;
    IConfigDaemon& operator=(IConfigDaemon&&) = delete;
    IConfigDaemon& operator=(const IConfigDaemon&) = delete;
    virtual ~IConfigDaemon() noexcept = default;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_APP_CONFIG_DAEMON_H
