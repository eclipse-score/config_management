#ifndef SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H
#define SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

enum class FaultEventId : std::uint8_t
{
    kUnkownError,
};

}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_SCORE_TYPES_H
