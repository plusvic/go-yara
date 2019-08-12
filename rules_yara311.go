// +build !yara3.11

package yara

/*
#include <yara.h>
*/
import "C"

// ResetCosts resets the rules' cost counters to zero. The cost computation is
// cumulative, which means that everytime you scan some data with a set of Rules
// the counters are incremented according to the time spent by each rule, those
// counters are never reset to zero unless you call this function.
func (r *Rules) ResetCosts() {
	C.yr_rules_reset_profiling_info(r.cptr)
}
