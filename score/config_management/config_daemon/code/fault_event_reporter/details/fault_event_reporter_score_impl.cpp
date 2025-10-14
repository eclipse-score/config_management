#include "score/config_management/config_daemon/code/fault_event_reporter/details/fault_event_reporter_score_impl.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_score_types.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{

// LCOV_EXCL_START Testcase exists for this but that will run only for score.

bool FaultEventReporter::Report(const std::uint8_t fault_event_id, [[maybe_unused]] const bool is_fault_present)
{
    if (fault_event_id != (static_cast<std::uint8_t>(FaultEventId::kUnkownError)))
    {
        return false;
    }
    return true;
}
void FaultEventReporter::Initialize() {}
// LCOV_EXCL_STOP

}  // namespace fault_event_reporter

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
