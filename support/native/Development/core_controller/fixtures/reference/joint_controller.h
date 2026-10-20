#ifndef JOINT_CONTROLLER_H
#define JOINT_CONTROLLER_H
#include <stddef.h>
#include <stdint.h>

/* Public metadata only. Payload ownership belongs to the single-threaded arena.
 * All native measurements and functional gates remain pending for this module. */
typedef struct JointCache JointCache;
enum { JC_PUBLIC=0, JC_SECRET=1, JC_MAX_CONTEXTS=64, JC_MAX_OBJECTS=128 };
enum { JC_AGE=1u, JC_FORGET=2u, JC_COST=4u, JC_DEADLINE=8u,
       JC_ADMISSION=16u, JC_ALL_COMPONENTS=31u };
typedef enum {
 JC_NONE, JC_PUBLIC_S3, JC_SECRET_S3, JC_STATIC25, JC_STATIC50,
 JC_STATIC75, JC_LECAR, JC_LANDLORD, JC_TINY, JC_LOGISTIC, JC_SCAR,
 JC_SIEVE, JC_PUBLIC_SIEVE
} JointPolicy;
typedef struct {
 double state_ns[4]; /* indexed public*2 + secret: 00,01,10,11 */
 double add_public_ns,add_secret_ns,erase_public_ns,erase_secret_ns;
} JointCosts;
typedef struct {
 size_t arena_bytes; unsigned contexts,history_capacity,components;
 JointPolicy policy; uint64_t ttl_ns,guard_ns,horizon_ns,public_seed;
 JointCosts costs;
 uint64_t (*clock_ns)(void); /* NULL: metadata-only logical-time gate. */
} JointConfig;
typedef struct {
 uint32_t evict[JC_MAX_OBJECTS],place[2];
 unsigned evict_count,mask; double objective_ns;
 uint64_t sequence,revision,clock_ns; unsigned context;
} JointPlan;
typedef struct {
 uint64_t reserved_bytes,prefix_bytes,used_bytes,peak_used_bytes;
 uint64_t public_bytes,secret_bytes,entries,evictions,zeroizations;
 uint64_t max_residency_ns,late_clear_count,max_lateness_ns;
 uint64_t history_bytes,policy_bytes,bitmap_bytes;
} JointStats;
typedef struct {
 uint32_t offset,span,context,type; uint64_t generation,born_ns,last_use;
 unsigned valid;
} JointEntryView;

/* SCAR component masks describe this separately registered controller only.
 * Existing policy names and all cryptographic/lifetime parameters are shared. */
enum { SCAR_HISTORY=1u, SCAR_COST=2u, SCAR_ADMISSION=4u, SCAR_SPARSE=8u,
       SCAR_ALL_COMPONENTS=15u, SCAR_MAX_VICTIMS=4u };
typedef struct {unsigned cooldown_accesses,shrinkage;double reserve_fraction;} JointScarSettings;
typedef struct {
 double value[JC_MAX_CONTEXTS][4];
 unsigned char initial[JC_MAX_CONTEXTS],state[JC_MAX_CONTEXTS];
} JointScarScratch;
typedef struct {
 uint64_t observations,prefilter_rejects,cooldown_bypasses,full_searches;
 uint64_t candidate_masks,victim_proposals,forecast_contexts;
 uint64_t retirement_checks,retirement_commits,retired_public,retired_secret;
} JointScarStats;
typedef struct {
 uint64_t sequence,revision,clock_ns;
 unsigned mask,considered;double objective_ns;
} JointRetirePlan;

/* Storage must be disjoint, aligned32, and exactly config.arena_bytes long.
 * No heap allocation; all persistent state resides inside this mapping. */
JointCache *jc_init(void *storage,size_t bytes,const JointConfig *config);
const char *jc_policy_name(JointPolicy p);
int jc_policy_parse(const char *s,JointPolicy *p);
void *jc_lookup(JointCache *c,unsigned key,unsigned type,uint64_t now_ns);
void jc_observe(JointCache *c,unsigned key,uint64_t now_ns,uint64_t scheduled_ns);
int jc_plan(JointCache *c,unsigned key,uint64_t now_ns,JointPlan *plan);
/* SCAR requires caller-owned bounded scratch from the common locked Work map.
 * Other policies use their unchanged planner and do not touch this scratch.
 * Every SCAR call that uses scratch clears it before returning.
 * Cheap bypass paths do not read or write this already-cleared workspace. */
int jc_plan_with_scratch(JointCache *c,unsigned key,uint64_t now_ns,JointPlan *plan,
                         JointScarScratch *scratch,size_t scratch_bytes);
int jc_scar_configure(JointCache *c,const JointScarSettings *settings);
JointScarStats jc_scar_stats(const JointCache *c);
size_t jc_scar_scratch_bytes(void);
/* Retirement is permitted ONLY after the request's borrowed pointers have
 * ceased being used, pending entries were published, and ephemeral secrets
 * were cleared. The caller must end that scope; no concurrent borrower exists.
 * Plan chooses one global P/S/both projection. Commit validates the entire
 * targeted READY set and token before any erase, including current context. */
int jc_retire_plan(JointCache *c,uint64_t now_ns,JointRetirePlan *plan,
                   JointScarScratch *scratch,size_t scratch_bytes);
int jc_retire_commit(JointCache *c,const JointRetirePlan *plan,uint64_t now_ns);
/* Commit reserves unpublished slots; caller constructs/copies and then publishes.
 * Existing current-context objects are pinned by the planner. Every eviction
 * clears its payload before reuse. A stale plan is rejected without mutation. */
int jc_commit(JointCache *c,const JointPlan *plan,uint64_t secret_birth_ns);
void *jc_pending(JointCache *c,unsigned key,unsigned type);
int jc_publish(JointCache *c,unsigned key,unsigned type);
void jc_expire(JointCache *c,uint64_t now_ns);
uint64_t jc_next_deadline(const JointCache *c,uint64_t default_ns);
/* Equivalent idle pair at one supplied logical time; no retained deadline. */
uint64_t jc_expire_and_next(JointCache *c,uint64_t now_ns,uint64_t default_ns);
/* Fresh-clock drain at a single-threaded, no-secret-borrow boundary. Parent
 * arena validity is a precondition. No admission/publication or concurrent
 * mutation may occur; clock_ns must be a nonmutating monotonic callback.
 * PENDING entries remain untouched. Reacquire READY pointers after success.
 * Failure may follow completed erasures: it is NOT a rollback guarantee.
 * The native caller must stop and perform its existing full cleanup on failure.
 * No absolute real-time guarantee follows from a finite cooperative check. */
enum { JC_DRAIN_OK=0, JC_DRAIN_NO_CLOCK=1, JC_DRAIN_CLOCK_REVERSED=2,
       JC_DRAIN_PASS_LIMIT=3 };
typedef struct {
 uint64_t next_secret_deadline_ns,observed_end_ns;
 unsigned passes,pass_limit; int status;
} JointDeadlineDrainResult;
JointDeadlineDrainResult jc_deadline_drain(JointCache *c);
void jc_clear_all(JointCache *c,uint64_t now_ns);
/* Administrative pre-monitor boundary, shared by every policy. The caller must
 * have ended all borrowed-pointer use and cleared ephemeral request secrets.
 * No concurrent arena user is allowed. Prevalidate the entire arena and reject
 * any PENDING object before erasing anything. Rejection leaves the arena intact.
 * On success remove only READY secret objects using the existing zero/readback
 * completion endpoint, preserving public objects, generations and history.
 * Every success consumes the revision, including an empty boundary. Result is
 * returned by value so it cannot alias the arena. This is not a deadline proof. */
typedef struct { int success; unsigned erased; } JointMonitorBarrierResult;
JointMonitorBarrierResult jc_pre_monitor_barrier(JointCache *c,uint64_t now_ns);
int jc_rotate(JointCache *c,unsigned key,uint64_t generation,uint64_t now_ns);
uint64_t jc_generation(const JointCache *c,unsigned key);
JointStats jc_stats(const JointCache *c);
size_t jc_entries(const JointCache *c,JointEntryView *out,size_t capacity);
int jc_check(const JointCache *c);
size_t jc_header_bytes(void);
size_t jc_entry_bytes(unsigned type);
size_t jc_plan_scratch_bytes(void);
#endif
