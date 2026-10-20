/* The exact reviewed sieve_controller parent is compiled in a separate namespace.
 * Only the public-record and secret-core geometry is changed in the separately pinned reference.
 * The comparison tests baseline policy preservation at identical packed geometry. */
#define jc_init parent_jc_init
#define jc_policy_name parent_jc_policy_name
#define jc_policy_parse parent_jc_policy_parse
#define jc_lookup parent_jc_lookup
#define jc_observe parent_jc_observe
#define jc_plan parent_jc_plan
#define jc_plan_with_scratch parent_jc_plan_with_scratch
#define jc_scar_configure parent_jc_scar_configure
#define jc_scar_stats parent_jc_scar_stats
#define jc_scar_scratch_bytes parent_jc_scar_scratch_bytes
#define jc_retire_plan parent_jc_retire_plan
#define jc_retire_commit parent_jc_retire_commit
#define jc_commit parent_jc_commit
#define jc_pending parent_jc_pending
#define jc_publish parent_jc_publish
#define jc_expire parent_jc_expire
#define jc_next_deadline parent_jc_next_deadline
#define jc_expire_and_next parent_jc_expire_and_next
#define jc_clear_all parent_jc_clear_all
#define jc_pre_monitor_barrier parent_jc_pre_monitor_barrier
#define jc_rotate parent_jc_rotate
#define jc_generation parent_jc_generation
#define jc_stats parent_jc_stats
#define jc_entries parent_jc_entries
#define jc_check parent_jc_check
#define jc_header_bytes parent_jc_header_bytes
#define jc_entry_bytes parent_jc_entry_bytes
#define jc_plan_scratch_bytes parent_jc_plan_scratch_bytes
#define jc_deadline_drain parent_jc_deadline_drain
#include "reference/joint_controller.c"

/* Test-only construction of a legal plan through the parent's original
 * placement function. This wrapper changes no controller state. */
int parent_fixture_force_plan(JointCache*c,unsigned key,unsigned mask,
                              uint64_t now,JointPlan*p){
 memset(p,0,sizeof(*p));p->context=key;p->mask=mask;p->clock_ns=now;
 p->sequence=c->seq;p->revision=c->revision;int required=-1;
 return try_place(c,p,&required);
}
