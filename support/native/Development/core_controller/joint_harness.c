/* Joint-resource native request harness. Development only; no performance
 * result is implied by this source. All policies receive identical primitives.
 * Schedule functions and permutation/fixture rules are copied from the pinned
 * project Native/Development/resource_controller/scar_mlkem.c.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "mlkem_native.h"
#include "assisted_expansion.h"
#include "public_matrix.h"
#include "secret_core.h"
#include "joint_controller.h"

#define CHECK(x) do { if(!(x)){fprintf(stderr,"joint_harness_failed:%s:%d errno=%d\n",#x,__LINE__,errno);exit(1);} }while(0)
enum { CONTEXTS=64, MAXREQ=200000, MAXFIXTURE=6000 };
typedef struct { uint8_t seed[64]; ScarAssistedPublic public; } Key;
typedef struct { uint8_t sk[2400],out[32],coins[32]; JointScarScratch causal; } Work;
typedef struct { uint8_t ct[1088],ss[32]; } Fixture;
typedef struct {
 unsigned key,fixture; uint64_t due,arrival,service,response,cycles;
 uint64_t reconstruction,decapsulation,public_prepare,secret_copy,ephemeral_clear;
 uint64_t observe,lookup,planning,commit,publish,expiry,idle_maintenance;
 uint64_t used_bytes,public_bytes,secret_bytes,entries,evictions;
 double temperature,frequency; int success,public_hit,secret_hit,public_admitted,secret_admitted;
} Event;
_Static_assert(sizeof(Key)==1280,"exact common context record");
_Static_assert(sizeof(ScarAssistedPublic)==1216,"enrollment bytes");
_Static_assert(sizeof(JointScarScratch)==2176,"bounded common causal scratch");
_Static_assert(sizeof(Work)==4640,"common operation plus causal scratch");
_Static_assert(sizeof(Fixture)==1120,"fixture bytes");
static Key *keys;
static Work *work;
static Fixture *fixtures;
static void *cache_memory;
static Event *events;
static JointCache *cache;
static size_t keys_map,work_map,fixtures_map,cache_map;
static int perf_fd=-1;
static uint64_t rng_state;
static double drift_factor=1.;
static int causal_policy;
int joint_trace_main(int argc,char **argv);
int joint_controller_selftest(void);

static uint64_t clock_value(clockid_t id) {
 struct timespec t; CHECK(clock_gettime(id,&t)==0);
 return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t now(void) { return clock_value(CLOCK_MONOTONIC); }
static uint64_t cpu_now(void) { return clock_value(CLOCK_THREAD_CPUTIME_ID); }
static size_t page_round(size_t n,size_t page) {
 CHECK(page && n<=SIZE_MAX-(page-1)); return ((n+page-1)/page)*page;
}
static void *locked_map(size_t bytes) {
 void *p=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 CHECK(p!=MAP_FAILED);
 if(mlock(p,bytes)!=0||madvise(p,bytes,MADV_DONTDUMP)!=0){
  int saved=errno; explicit_bzero(p,bytes); (void)munlock(p,bytes); (void)munmap(p,bytes);
  errno=saved; CHECK(0);
 }
 return p;
}
static void unmap_clear(void *p,size_t bytes) {
 if(p){explicit_bzero(p,bytes); (void)munlock(p,bytes); (void)munmap(p,bytes);}
}
static void cleanup(void) {
 unmap_clear(cache_memory,cache_map); cache_memory=NULL; cache=NULL;
 unmap_clear(keys,keys_map); keys=NULL;
 unmap_clear(work,work_map); work=NULL;
 unmap_clear(fixtures,fixtures_map); fixtures=NULL;
 free(events); events=NULL;
 if(perf_fd>=0){(void)close(perf_fd);perf_fd=-1;}
}
static void entropy(void *p,size_t n) {
 uint8_t *b=p; while(n){ssize_t r=getrandom(b,n,0);if(r<0&&errno==EINTR)continue;
 CHECK(r>0);b+=(size_t)r;n-=(size_t)r;}
}
static double readnumber(const char *p,double scale) {
 FILE*f=fopen(p,"r");if(!f)return NAN;double n=NAN;
 if(fscanf(f,"%lf",&n)!=1)n=NAN;
 fclose(f);return n/scale;
}
static void wait_until(uint64_t target) {
 struct timespec ts={(time_t)(target/UINT64_C(1000000000)),(long)(target%UINT64_C(1000000000))};
 int r;do{r=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL);}while(r==EINTR);
 CHECK(r==0);
}
/* Same idle/expiry implementation is used by the fake-clock fixtures. */
#include "deadline_wait.inc"

static uint64_t rnd(void){uint64_t x=rng_state;x^=x>>12;x^=x<<25;x^=x>>27;rng_state=x;return x*2685821657736338717ULL;}
static double uniform(void){return ((double)(rnd()>>11)+0.5)/9007199254740992.0;}
static int choose_key(const char*kind,int i,int n,int k,double *gap){
    double u=uniform(); int v=0;
    if(!strcmp(kind,"uniform")||!strcmp(kind,"poisson"))v=(int)(u*k);
    else if(!strcmp(kind,"zipf")||!strcmp(kind,"nonstationary")){
        double total=0;for(int j=1;j<=k;j++)total+=1.0/pow(j,1.2);
        double target=u*total,acc=0;for(v=0;v<k-1;v++){acc+=1.0/pow(v+1,1.2);if(acc>=target)break;}
        if(!strcmp(kind,"nonstationary"))v=(v+(int)(i*k*drift_factor/n))%k;
    } else if(!strcmp(kind,"bursty")){v=(i/40+(int)(u*4))%k;*gap*=i%80<64?0.15:4.4;}
    else if(!strcmp(kind,"periodic")){v=(i%24<20?i%5:5+(int)(u*(k-5)));}
    else if(!strcmp(kind,"abrupt")){v=(u<0.9?(int)(uniform()*8):(int)(uniform()*k));if(i>=n/2)v=(v+k/2)%k;}
    else if(!strcmp(kind,"thrashing")){v=i%17;}
    else if(!strcmp(kind,"hotcold")){v=u<0.9?(int)(uniform()*8):(int)(uniform()*k);}
    else if(!strcmp(kind,"varying_contexts")){int active=8+(i/(n/4))*(k-8)/3;if(active>k)active=k;v=(int)(u*active);}
    else {fprintf(stderr,"unknown workload\n");exit(2);}
    if(!strcmp(kind,"poisson"))*gap*=-log(uniform());
    return v;
}
static uint64_t integer(const char *s) {
 char *end=NULL;errno=0;CHECK(s&&*s&&*s!='-'&&*s!='+');
 unsigned long long v=strtoull(s,&end,10);CHECK(errno==0&&end&&!*end);return (uint64_t)v;
}
static double number(const char *s) {
 char *end=NULL;errno=0;double v=strtod(s,&end);
 CHECK(errno==0&&end&&end!=s&&!*end&&isfinite(v));return v;
}
static void identifier(const char *s) {
 CHECK(s&&*s&&strlen(s)<128);
 for(;*s;s++)CHECK((*s>='a'&&*s<='z')||(*s>='A'&&*s<='Z')||
  (*s>='0'&&*s<='9')||*s=='_'||*s=='-'||*s=='.');
}
static uint64_t scaled_ns(const char *s,double scale) {
 double v=number(s)*scale;CHECK(v>=0&&v<1e15);return (uint64_t)v;
}
static void run_request(Event *e,int verify) {
 e->arrival=now();
 uint64_t cyc0=0,cyc1=0,b;
 if(!verify)CHECK(read(perf_fd,&cyc0,sizeof(cyc0))==sizeof(cyc0));
 b=now();
 (void)drain_ready_secrets();e->expiry=now()-b;
 b=now();jc_observe(cache,e->key,b,e->due);e->observe=now()-b;
 b=now();
 ScarPublicMatrix *p=jc_lookup(cache,e->key,JC_PUBLIC,b);
 uint8_t *s=jc_lookup(cache,e->key,JC_SECRET,b);
 e->lookup=now()-b;
 JointPlan plan;
 b=now();CHECK(jc_plan_with_scratch(cache,e->key,b,&plan,&work->causal,sizeof(work->causal))==0);e->planning=now()-b;
 uint64_t birth=now();
 b=birth;CHECK(jc_commit(cache,&plan,birth)==0);e->commit=now()-b;
 /* Commit must consume the unchanged plan first. Expire and reacquire after
  * it: a planning/preemption delay cannot turn a stale READY pointer into a
  * legitimate borrow. Expired prior S is reconstructed without extra admission. */
 b=now();(void)drain_ready_secrets();e->expiry+=now()-b;
 b=now();p=jc_lookup(cache,e->key,JC_PUBLIC,b);e->lookup+=now()-b;
 e->public_hit=p!=NULL;
 void *pending_public=jc_pending(cache,e->key,JC_PUBLIC);
 void *pending_secret=jc_pending(cache,e->key,JC_SECRET);
 e->public_admitted=pending_public!=NULL;e->secret_admitted=pending_secret!=NULL;
 uint64_t generation=jc_generation(cache,e->key);
 if(pending_public){
  CHECK(p==NULL);b=now();
  p=scar_public_init_in_place(pending_public,scar_public_record_bytes(),
                              keys[e->key].public.ek,1184,generation);
  CHECK(p==pending_public);e->public_prepare=now()-b;
 }
 b=now();(void)drain_ready_secrets();e->expiry+=now()-b;
 b=now();s=jc_lookup(cache,e->key,JC_SECRET,b);e->lookup+=now()-b;
 e->secret_hit=s!=NULL;
 /* A retained S is dkPKE only. Assemble the complete standard key from
  * the same context's immutable enrollment into locked operation scratch.
  * reconstruction includes this hit composition as well as miss expansion. */
 b=now();
 if(s){
  CHECK(scar_secret_compose(work->sk,2400,s,1152,keys[e->key].public.ek,1184,
          keys[e->key].public.h_ek,32,keys[e->key].seed+32,32)==0);
 } else scar_assisted_expand(work->sk,keys[e->key].seed,&keys[e->key].public,1);
 e->reconstruction=now()-b;s=work->sk;
 int used=-1;b=now();
 int result=scar_public_dec(work->out,32,fixtures[e->fixture].ct,1088,s,2400,p,generation,&used);
 e->decapsulation=now()-b;
 e->success=result==0&&used==(p!=NULL)&&!memcmp(work->out,fixtures[e->fixture].ss,32);
 CHECK(e->success);
 if(pending_secret){
  CHECK(!e->secret_hit);b=now();CHECK(scar_secret_extract(pending_secret,1152,work->sk,2400)==0);e->secret_copy=now()-b;
 }
 b=now();
 /* Publication follows complete construction/copy. No interleaved borrower or
  * eviction exists in this single-threaded transaction. */
 if(pending_public)CHECK(jc_publish(cache,e->key,JC_PUBLIC)==0);
 if(pending_secret)CHECK(jc_publish(cache,e->key,JC_SECRET)==0);
 e->publish=now()-b;
 b=now();explicit_bzero(work->sk,2400);explicit_bzero(work->out,32);
 e->ephemeral_clear=now()-b;
 b=now();(void)drain_ready_secrets();e->expiry+=now()-b;
 /* All current borrowed pointers have left their use scope. Retirement never
  * runs while crypto/payload-copy holds a borrowed object. Subsequent requests
  * reacquire; an extra mandatory expiry observes elapsed retirement work. */
 if(causal_policy){
  JointRetirePlan retirement;
  CHECK(jc_retire_plan(cache,now(),&retirement,&work->causal,sizeof(work->causal))==0);
  if(retirement.considered)CHECK(jc_retire_commit(cache,&retirement,now())==0);
  b=now();(void)drain_ready_secrets();e->expiry+=now()-b;
 }
 JointStats st=jc_stats(cache);
 CHECK(st.used_bytes<=st.reserved_bytes&&st.reserved_bytes==cache_map);
 e->used_bytes=st.used_bytes;e->public_bytes=st.public_bytes;e->secret_bytes=st.secret_bytes;
 e->entries=st.entries;e->evictions=st.evictions;
 if(!verify){CHECK(read(perf_fd,&cyc1,sizeof(cyc1))==sizeof(cyc1));e->cycles=cyc1-cyc0;}
 e->service=now()-e->arrival;
}
int main(int argc,char **argv) {
 if(argc>=2&&!strcmp(argv[1],"trace"))return joint_trace_main(argc,argv);
 if(argc==2&&!strcmp(argv[1],"selftest_controller"))return joint_controller_selftest();
 if(argc==2&&!strcmp(argv[1],"sizes")){
  printf("page_size=%ld key_record_bytes=%zu operation_scratch_bytes=%zu fixture_bytes=%zu "
         "event_bytes=%zu controller_header_bytes=%zu plan_declared_scratch_bytes=%zu "
         "public_record_bytes=%zu public_entry_bytes=%zu secret_entry_bytes=%zu\n",
         sysconf(_SC_PAGESIZE),sizeof(Key),sizeof(Work),sizeof(Fixture),sizeof(Event),
         jc_header_bytes(),jc_plan_scratch_bytes(),scar_public_record_bytes(),
         jc_entry_bytes(JC_PUBLIC),jc_entry_bytes(JC_SECRET));return 0;
 }
 if(argc!=25|| (strcmp(argv[1],"run")&&strcmp(argv[1],"verify"))){
  fprintf(stderr,"usage: joint_controller run|verify SESSION WORKLOAD SEED N CONTEXTS INTERVAL_US "
   "SPLIT POLICY ARENA_BYTES TTL_MS GUARD_US HORIZON_MS HISTORY_CAPACITY COMPONENTS "
   "C00 C01 C10 C11 ADDP ADDS ERASEP ERASES DRIFT\n");return 2;
 }
 int verify=!strcmp(argv[1],"verify");
 const char *session=argv[2],*kind=argv[3],*split=argv[8];
 identifier(session);identifier(kind);identifier(split);
 uint64_t seed=integer(argv[4]),request_count=integer(argv[5]),context_count=integer(argv[6]);
 CHECK(seed&&request_count>=100&&request_count<=MAXREQ&&context_count==CONTEXTS);
 unsigned n=(unsigned)request_count;double interval_us=number(argv[7]);
 CHECK(interval_us>=50&&interval_us<=1000000);
 JointConfig cfg={0};
 CHECK(jc_policy_parse(argv[9],&cfg.policy)==0);
 cfg.arena_bytes=(size_t)integer(argv[10]);
 CHECK(cfg.arena_bytes==32768||cfg.arena_bytes==65536);
 cfg.contexts=CONTEXTS;cfg.ttl_ns=scaled_ns(argv[11],1e6);
 cfg.guard_ns=scaled_ns(argv[12],1e3);cfg.horizon_ns=scaled_ns(argv[13],1e6);
 CHECK(cfg.ttl_ns>=1000000&&cfg.ttl_ns<=1000000000&&cfg.ttl_ns>cfg.guard_ns);
 CHECK(cfg.horizon_ns>=1000000&&cfg.horizon_ns<=100000000);
 uint64_t history=integer(argv[14]),components=integer(argv[15]);
 CHECK(history<=1000&&components<=JC_ALL_COMPONENTS);
 cfg.history_capacity=(unsigned)history;cfg.components=(unsigned)components;
 for(unsigned i=0;i<4;i++){cfg.costs.state_ns[i]=number(argv[16+i]);CHECK(cfg.costs.state_ns[i]>0);}
 cfg.costs.add_public_ns=number(argv[20]);cfg.costs.add_secret_ns=number(argv[21]);
 cfg.costs.erase_public_ns=number(argv[22]);cfg.costs.erase_secret_ns=number(argv[23]);
 CHECK(cfg.costs.add_secret_ns>=0&&cfg.costs.erase_public_ns>=0&&cfg.costs.erase_secret_ns>=0);
 /* add_public_ns is a signed paired incremental cold cost, not construction alone. */
 cfg.public_seed=seed^UINT64_C(0xd1b54a32d192ed03);cfg.clock_ns=now;
 drift_factor=number(argv[24]);CHECK(drift_factor>=0&&drift_factor<=100);
 struct rlimit lim={0,0};CHECK(setrlimit(RLIMIT_CORE,&lim)==0&&prctl(PR_SET_DUMPABLE,0)==0);
 CHECK(atexit(cleanup)==0);
 long native_page=sysconf(_SC_PAGESIZE);CHECK(native_page>0);
 size_t page=(size_t)native_page;
 keys_map=page_round(CONTEXTS*sizeof(Key),page);
 cache_map=page_round(cfg.arena_bytes,page);
 CHECK(keys_map==81920&&cache_map==cfg.arena_bytes);
 work_map=page_round(sizeof(Work),page);
 int reusable=n>MAXFIXTURE;unsigned fixture_count=reusable?2*CONTEXTS:n;
 fixtures_map=page_round((size_t)fixture_count*sizeof(Fixture),page);
 keys=locked_map(keys_map);work=locked_map(work_map);fixtures=locked_map(fixtures_map);
 cache_memory=locked_map(cache_map);
 CHECK(((uintptr_t)cache_memory%32)==0);
 CHECK(scar_public_record_bytes()==3520&&scar_public_alignment()==32);
 CHECK(jc_entry_bytes(JC_PUBLIC)==3584&&jc_entry_bytes(JC_SECRET)==1216);
 cache=jc_init(cache_memory,cache_map,&cfg);CHECK(cache&&jc_check(cache));
 causal_policy=cfg.policy==JC_SCAR;
 JointScarSettings scar_settings={0};
 if(causal_policy){
  const char *k=getenv("SCAR_K"),*nu=getenv("SCAR_NU"),*margin=getenv("SCAR_MARGIN");
  CHECK(k&&nu&&margin);
  uint64_t parsed_k=integer(k),parsed_nu=integer(nu);CHECK(parsed_k<=8&&parsed_nu<=2);
  scar_settings=(JointScarSettings){(unsigned)parsed_k,(unsigned)parsed_nu,number(margin)};
  CHECK(jc_scar_configure(cache,&scar_settings)==0);
 }
 events=calloc(n,sizeof(*events));CHECK(events);
 rng_state=seed;
 int permutation[CONTEXTS];for(int j=0;j<CONTEXTS;j++)permutation[j]=j;
 for(int j=CONTEXTS-1;j>0;j--){int q=(int)(rnd()%(uint64_t)(j+1));
  int tmp=permutation[j];permutation[j]=permutation[q];permutation[q]=tmp;}
 uint64_t enrollment_ns=0;
 for(unsigned j=0;j<CONTEXTS;j++){
  entropy(keys[j].seed,64);uint64_t b=now();
  CHECK(mlkem_keypair_derand(keys[j].public.ek,work->sk,keys[j].seed)==0);
  ScarAssistedPublic enrolled;
  CHECK(scar_assisted_enroll(&enrolled,keys[j].seed,keys[j].public.ek)==0);
  memcpy(&keys[j].public,&enrolled,sizeof(enrolled));explicit_bzero(&enrolled,sizeof(enrolled));
  explicit_bzero(work->sk,2400);enrollment_ns+=now()-b;
 }
 uint64_t relative=0;
 for(unsigned i=0;i<n;i++){
  double gap=interval_us;events[i].key=(unsigned)permutation[choose_key(kind,(int)i,(int)n,CONTEXTS,&gap)];
  relative+=(uint64_t)(gap*1000);events[i].due=relative;
  events[i].fixture=reusable?events[i].key*2+i%2:i;
  if(!reusable){entropy(work->coins,32);
   CHECK(mlkem_enc_derand(fixtures[i].ct,fixtures[i].ss,keys[events[i].key].public.ek,work->coins)==0);
   explicit_bzero(work->coins,32);}
 }
 if(reusable)for(unsigned f=0;f<fixture_count;f++){
  entropy(work->coins,32);CHECK(mlkem_enc_derand(fixtures[f].ct,fixtures[f].ss,keys[f/2].public.ek,work->coins)==0);
  explicit_bzero(work->coins,32);
 }
 /* Common warmup performs no cache admissions; every measured arena is cold. */
 for(unsigned i=0;i<100;i++){
  unsigned id=events[0].key;scar_assisted_expand(work->sk,keys[id].seed,&keys[id].public,1);
  CHECK(mlkem_dec(work->out,fixtures[events[0].fixture].ct,work->sk)==0);
  CHECK(!memcmp(work->out,fixtures[events[0].fixture].ss,32));
  explicit_bzero(work->sk,2400);explicit_bzero(work->out,32);
 }
 if(!verify){
  struct perf_event_attr pe={0};pe.type=PERF_TYPE_HARDWARE;pe.size=sizeof(pe);
  pe.config=PERF_COUNT_HW_CPU_CYCLES;pe.exclude_kernel=1;pe.exclude_hv=1;
  perf_fd=(int)syscall(SYS_perf_event_open,&pe,0,-1,-1,0);CHECK(perf_fd>=0);
 }
 uint64_t start=now()+UINT64_C(10000000),phase_cpu_begin=cpu_now(),phase_wall_begin=now();
 uint64_t monitor_barrier_calls=0,monitor_barrier_clears=0;
 double temp=NAN,freq=NAN;
 for(unsigned i=0;i<n;i++){
  Event *e=&events[i];uint64_t due=start+e->due;
  if(i%64==0){
   /* The prior request has ended all borrowing and cleared its ephemeral
    * secrets. Do not retain an expanded cache secret across blocking sysfs I/O.
    * This shared administrative boundary stays inside the original CPU phase. */
   JointMonitorBarrierResult barrier=jc_pre_monitor_barrier(cache,now());
   CHECK(barrier.success);monitor_barrier_calls++;monitor_barrier_clears+=barrier.erased;
   temp=readnumber("/sys/class/thermal/thermal_zone0/temp",1000);
   freq=readnumber("/sys/devices/system/cpu/cpu2/cpufreq/scaling_cur_freq",1000);}
  e->temperature=temp;e->frequency=freq;e->idle_maintenance=wait_expiring(due);
  run_request(e,verify);e->response=e->arrival+e->service-start-e->due;
 }
 /* Both dynamic tiers are erased inside the primary request-phase endpoints. */
 jc_clear_all(cache,now());
 uint64_t phase_wall=now()-phase_wall_begin,phase_cpu=cpu_now()-phase_cpu_begin;
 JointStats final=jc_stats(cache);CHECK(jc_check(cache)&&final.entries==0);
 CHECK(final.used_bytes==final.prefix_bytes&&final.peak_used_bytes<=cache_map);
 struct rusage ru;CHECK(getrusage(RUSAGE_SELF,&ru)==0);
 fprintf(stderr,"retained_context_bytes=%zu retained_arena_bytes=%zu total_retained_mapping_bytes=%zu "
  "native_page_bytes=%zu operation_scratch_payload_bytes=%zu operation_scratch_mapping_bytes=%zu "
  "fixture_count=%u fixture_mapping_bytes=%zu event_buffer_bytes=%zu total_mlocked_mapping_bytes=%zu "
  "controller_header_bytes=%zu controller_prefix_bytes=%" PRIu64 " history_bytes=%" PRIu64
  " policy_bytes=%" PRIu64 " bitmap_bytes=%" PRIu64 " plan_declared_scratch_bytes=%zu "
  "peak_occupied_bytes=%" PRIu64 " peak_rss_bytes=%ld\n",
  keys_map,cache_map,keys_map+cache_map,page,sizeof(Work),work_map,fixture_count,fixtures_map,
  (size_t)n*sizeof(Event),keys_map+cache_map+work_map+fixtures_map,jc_header_bytes(),
  final.prefix_bytes,final.history_bytes,final.policy_bytes,final.bitmap_bytes,
  jc_plan_scratch_bytes(),final.peak_used_bytes,ru.ru_maxrss*1024);
 fprintf(stderr,"native_success=1 session=%s policy=%s workload=%s seed=%" PRIu64
  " requests=%u contexts=64 components=%u secret_max_residency_ns=%" PRIu64
  " late_clear_count=%" PRIu64 " max_lateness_ns=%" PRIu64 " zeroizations=%" PRIu64
  " ttl_ns=%" PRIu64 " guard_ns=%" PRIu64 " fixture_mode=%s cpu=%d\n",
  session,jc_policy_name(cfg.policy),kind,seed,n,cfg.components,final.max_residency_ns,
  final.late_clear_count,final.max_lateness_ns,final.zeroizations,cfg.ttl_ns,cfg.guard_ns,
  reusable?"reused":"unique",sched_getcpu());
 JointScarStats causal=jc_scar_stats(cache);
 fprintf(stderr,"lifecycle_intervention=pre_monitor_ready_secret_barrier monitor_barrier_calls=%" PRIu64
  " monitor_barrier_clears=%" PRIu64 " monitor_period_requests=64 monitor_barrier_before_sysfs=1 "
  "monitor_barrier_in_phase_cpu=1 monitor_barrier_retains_public=1\n",
  monitor_barrier_calls,monitor_barrier_clears);
 fprintf(stderr,"deadline_maintenance=fresh_bounded_drain deadline_drain_calls=%" PRIu64
  " deadline_drain_passes=%" PRIu64 " deadline_drain_rechecks=%" PRIu64
  " deadline_drain_max_passes=%u deadline_drain_structural_bound=contexts_plus_one "
  "deadline_drain_uses_request_due_as_sentinel=0 deadline_drain_observer_counter_bytes=%zu\n",
  deadline_drain_calls,deadline_drain_passes,deadline_drain_rechecks,deadline_drain_max_passes,
  sizeof(deadline_drain_calls)+sizeof(deadline_drain_passes)+sizeof(deadline_drain_rechecks)+sizeof(deadline_drain_max_passes));
 fprintf(stderr,"controller_contract=causal_bounded_public_state public_transition_contract=conditional_signed_additive "
  "causal_scratch_payload_bytes=%zu causal_enabled=%d scar_k=%u scar_nu=%u scar_margin=%.17g "
  "scar_observations=%" PRIu64 " scar_prefilter_rejects=%" PRIu64 " scar_cooldown_bypasses=%" PRIu64
  " scar_full_searches=%" PRIu64 " scar_candidate_masks=%" PRIu64 " scar_victim_proposals=%" PRIu64
  " scar_forecast_contexts=%" PRIu64 " scar_retirement_checks=%" PRIu64 " scar_retirement_commits=%" PRIu64
  " scar_retired_public=%" PRIu64 " scar_retired_secret=%" PRIu64 "\n",
  jc_scar_scratch_bytes(),causal_policy,scar_settings.cooldown_accesses,scar_settings.shrinkage,
  scar_settings.reserve_fraction,causal.observations,causal.prefilter_rejects,causal.cooldown_bypasses,
  causal.full_searches,causal.candidate_masks,causal.victim_proposals,causal.forecast_contexts,
  causal.retirement_checks,causal.retirement_commits,causal.retired_public,causal.retired_secret);
 if(verify){
  printf("joint_functional_path=passed requests=%u policy=%s final_entries=0 "
   "timing_endpoints_emitted=0\n",n,jc_policy_name(cfg.policy));return 0;
 }
 fprintf(stderr,"accounting_profile=joint_complete_request_phase request_phase_thread_cpu_ns=%" PRIu64
  " request_phase_wall_ns=%" PRIu64 " request_count=%u includes_final_clear=1 "
  "final_clear_scope=both_dynamic_tiers request_phase_includes_initial_wait=1 "
  "planned_start_delay_ns=10000000 request_phase_includes_enrollment=0 "
  "includes_final_seed_fixture_scratch_mapping_destruction=0 enrollment_ns=%" PRIu64
  " enrollment_full_keygen_calls=128 no_electrical_energy_measurement=1\n",
  phase_cpu,phase_wall,n,enrollment_ns);
 puts("session_id,split,workload_id,policy,request_id,key_id,schedule_ns,arrival_ns,service_ns,response_ns,cpu_cycles,public_hit,secret_hit,public_admitted,secret_admitted,reconstruction_ns,decapsulation_ns,public_prepare_ns,secret_copy_ns,ephemeral_clear_ns,observe_ns,lookup_ns,planning_ns,commit_ns,publish_ns,expiry_ns,idle_maintenance_ns,arena_used_bytes,public_entry_bytes,secret_entry_bytes,entries,cumulative_evictions,temperature_c,cpu_frequency_mhz,success");
 for(unsigned i=0;i<n;i++){
  const Event *e=&events[i];
  printf("%s,%s,%s,%s,%u,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
   ",%d,%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
   ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
   ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%d\n",
   session,split,kind,jc_policy_name(cfg.policy),i,e->key,e->due,e->arrival,e->service,e->response,e->cycles,
   e->public_hit,e->secret_hit,e->public_admitted,e->secret_admitted,e->reconstruction,e->decapsulation,
   e->public_prepare,e->secret_copy,e->ephemeral_clear,e->observe,e->lookup,e->planning,e->commit,
   e->publish,e->expiry,e->idle_maintenance,e->used_bytes,e->public_bytes,e->secret_bytes,
   e->entries,e->evictions,e->temperature,e->frequency,e->success);
 }
 return 0;
}
