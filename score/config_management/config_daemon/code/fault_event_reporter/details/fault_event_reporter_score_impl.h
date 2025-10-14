#ifndef SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H
#define SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H

#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

class FaultEventReporter : public IFaultEventReporter
{
  public:
    FaultEventReporter() = default;
    FaultEventReporter(const FaultEventReporter&) = delete;
    FaultEventReporter(FaultEventReporter&&) = delete;
    FaultEventReporter& operator=(const FaultEventReporter&) = delete;
    FaultEventReporter& operator=(FaultEventReporter&&) = delete;
    ~FaultEventReporter() override = default;
    void Initialize() override;
    bool Report(const std::uint8_t fault_event_id, [[maybe_unused]] const bool is_fault_present) override;

  private:
};
}  // namespace fault_event_reporter

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_SYSFUNC_CONFIGDAEMON_CODE_FAULT_EVENT_REPORTER_DETAILS_FAULT_EVENT_REPORTER_SCORE_IMPL_H
