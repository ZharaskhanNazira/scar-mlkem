/* Observational counters outside the arena, shared by every policy. No
 * controller decision reads them; all work remains in existing phase clocks. */
static uint64_t deadline_drain_calls,deadline_drain_passes,deadline_drain_rechecks;
static unsigned deadline_drain_max_passes;
static JointDeadlineDrainResult drain_ready_secrets(void){
 JointDeadlineDrainResult r=jc_deadline_drain(cache);
 CHECK(r.status==JC_DRAIN_OK);
 deadline_drain_calls++;deadline_drain_passes+=r.passes;
 deadline_drain_rechecks+=r.passes-1;
 if(r.passes>deadline_drain_max_passes)deadline_drain_max_passes=r.passes;
 return r;
}
static uint64_t wait_expiring(uint64_t target) {
 uint64_t active=0;
 for(;;){
  uint64_t b=now();
  JointDeadlineDrainResult r=drain_ready_secrets();
  uint64_t end=now();active+=end-b;
  /* A deadline can also cross during the final accounting clock/counters.
   * Give it priority over handing off an already-due request. */
  if(r.next_secret_deadline_ns!=UINT64_MAX&&r.next_secret_deadline_ns<=end)continue;
  if(end>=target)break;
  uint64_t wake=r.next_secret_deadline_ns<target?r.next_secret_deadline_ns:target;
  if(wake>end)wait_until(wake);
 }
 return active;
}
