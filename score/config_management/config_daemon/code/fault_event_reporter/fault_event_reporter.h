#ifndef SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_REPORTER_H
#define SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_REPORTER_H
#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{

namespace fault_event_reporter
{
class IFaultEventReporter
{
  public:
    IFaultEventReporter() noexcept = default;
    IFaultEventReporter(const IFaultEventReporter&) = delete;
    IFaultEventReporter(IFaultEventReporter&&) = delete;
    IFaultEventReporter& operator=(const IFaultEventReporter&) = delete;
    IFaultEventReporter& operator=(IFaultEventReporter&&) = delete;
    virtual ~IFaultEventReporter() noexcept = default;

    virtual void Initialize() = 0;
    virtual bool Report(const std::uint8_t fault_event_id, const bool is_fault_present) = 0;
};
}  // namespace fault_event_reporter
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_FAULT_EVENT_REPORTER_H
