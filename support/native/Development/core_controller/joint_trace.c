/* Metadata-only deterministic fixtures. No cryptographic secrets, observations,
 * performance measurements, or scientific outcomes are generated here.
 * The notebook's independent reference checks this JSONL event/state stream. */
#define _GNU_SOURCE
#include "joint_controller.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static JointConfig fixture_config(JointPolicy policy,size_t bytes,unsigned mask) {
 JointConfig c={0};c.arena_bytes=bytes;c.contexts=64;c.history_capacity=1000;
 c.components=mask;c.policy=policy;c.ttl_ns=10000000;c.guard_ns=500000;
 c.horizon_ns=10000000;c.public_seed=19;c.clock_ns=NULL;
 c.costs=(JointCosts){{60000,56000,50000,46000},100,50,50,50};
 return c;
}
static int fixture_cost_profile(JointConfig *c,const char *profile) {
 if(!strcmp(profile,"default"))return 0;
 if(!strcmp(profile,"negative_interaction"))c->costs=(JointCosts){{60000,56000,50000,56000},100,50,50,50};
 else if(!strcmp(profile,"nonpositive"))c->costs=(JointCosts){{50000,51000,52000,54000},100,50,50,50};
 else if(!strcmp(profile,"zero_gain"))c->costs=(JointCosts){{60000,60000,60000,60000},100,50,50,50};
 else if(!strcmp(profile,"signed_add_public"))c->costs=(JointCosts){{50000,51000,52000,54000},-2000,50,50,50};
 else if(!strcmp(profile,"tie"))c->costs=(JointCosts){{60000,56000,50000,46000},3125,1137.5,50,50};
 else return -1;
 return 0;
}
static int decimal(const char *s,uint64_t *value) {
 char *end=NULL;errno=0;if(!s||!*s||*s=='-'||*s=='+')return -1;
 unsigned long long v=strtoull(s,&end,10);
 if(errno||!end||*end)return -1;
 *value=(uint64_t)v;return 0;
}
static void entries_json(const JointEntryView *v,size_t n) {
 putchar('[');
 for(size_t j=0;j<n;j++){
  if(j)putchar(',');
  printf("{\"offset_bytes\":%u,\"span_bytes\":%u,\"context\":%u,\"type\":%u,"
   "\"generation\":%" PRIu64 ",\"born_ns\":%" PRIu64 ",\"last_use\":%" PRIu64 ",\"valid\":%u}",
   v[j].offset,v[j].span,v[j].context,v[j].type,v[j].generation,v[j].born_ns,v[j].last_use,v[j].valid);
 }
 putchar(']');
}
static void stats_json(JointStats s) {
 printf("{\"reserved_bytes\":%" PRIu64 ",\"prefix_bytes\":%" PRIu64 ",\"used_bytes\":%" PRIu64
  ",\"peak_used_bytes\":%" PRIu64 ",\"public_bytes\":%" PRIu64 ",\"secret_bytes\":%" PRIu64
  ",\"entries\":%" PRIu64 ",\"evictions\":%" PRIu64 ",\"zeroizations\":%" PRIu64
  ",\"max_residency_ns\":%" PRIu64 ",\"late_clear_count\":%" PRIu64 ",\"max_lateness_ns\":%" PRIu64
  ",\"history_bytes\":%" PRIu64 ",\"policy_bytes\":%" PRIu64 ",\"bitmap_bytes\":%" PRIu64 "}",
  s.reserved_bytes,s.prefix_bytes,s.used_bytes,s.peak_used_bytes,s.public_bytes,s.secret_bytes,
  s.entries,s.evictions,s.zeroizations,s.max_residency_ns,s.late_clear_count,s.max_lateness_ns,
  s.history_bytes,s.policy_bytes,s.bitmap_bytes);
}
static int fill_publish(JointCache *c,unsigned key) {
 for(unsigned t=0;t<2;t++){
  void *p=jc_pending(c,key,t);if(!p)continue;
  memset(p,t?0x3c:0xa5,jc_entry_bytes(t)-64);
  if(jc_publish(c,key,t))return -1;
 }
 return jc_check(c)?0:-1;
}
int joint_trace_main(int argc,char **argv) {
 JointPolicy policy;uint64_t bytes,mask;
 if((argc!=5&&argc!=6)||jc_policy_parse(argv[2],&policy)||decimal(argv[3],&bytes)||decimal(argv[4],&mask)||
  (bytes!=32768&&bytes!=65536)||mask>JC_ALL_COMPONENTS){
  fprintf(stderr,"usage: joint_controller trace POLICY ARENA_BYTES COMPONENT_MASK [COST_PROFILE] < time_context.txt\n");return 2;
 }
 void *storage=aligned_alloc(32,(size_t)bytes);if(!storage)return 1;
 JointConfig cfg=fixture_config(policy,(size_t)bytes,(unsigned)mask);
 const char *profile=argc==6?argv[5]:"default";
 if(fixture_cost_profile(&cfg,profile)){free(storage);return 2;}
 JointCache *c=jc_init(storage,(size_t)bytes,&cfg);if(!c){free(storage);return 1;}
 JointScarSettings settings={0};JointScarScratch scratch={0};
 if(policy==JC_SCAR){
  const char *ks=getenv("SCAR_K"),*ns=getenv("SCAR_NU"),*ms=getenv("SCAR_MARGIN");uint64_t k,nu;
  if(!ks||!ns||!ms||decimal(ks,&k)||decimal(ns,&nu)||k>8||nu>2){free(storage);return 2;}
  char *end=NULL;errno=0;double margin=strtod(ms,&end);
  if(errno||end==ms||*end||!isfinite(margin)){free(storage);return 2;}
  settings=(JointScarSettings){(unsigned)k,(unsigned)nu,margin};
  if(jc_scar_configure(c,&settings)){free(storage);return 2;}
 }
 JointStats st=jc_stats(c);
 printf("{\"kind\":\"config\",\"config\":{\"policy\":\"%s\",\"components\":%u,\"contexts\":64,"
  "\"arena_bytes\":%" PRIu64 ",\"prefix_bytes\":%" PRIu64 ",\"arena_header_bytes\":%zu,"
  "\"entry_header_bytes\":64,\"public_entry_bytes\":%zu,\"secret_entry_bytes\":%zu,"
  "\"ttl_ns\":10000000,\"guard_ns\":500000,\"horizon_ns\":10000000,\"history_capacity\":1000,"
  "\"scar_k\":%u,\"scar_nu\":%u,\"scar_margin\":%.17g,\"scar_scratch_bytes\":%zu,\"costs\":{\"state_ns\":[%.17g,%.17g,%.17g,%.17g],\"add_public_ns\":%.17g,\"add_secret_ns\":%.17g,"
  "\"erase_public_ns\":%.17g,\"erase_secret_ns\":%.17g},\"cost_origin\":\"synthetic_metadata_fixture_not_measurement\",\"cost_profile\":\"%s\"}}\n",
  jc_policy_name(policy),(unsigned)mask,bytes,st.prefix_bytes,jc_header_bytes(),jc_entry_bytes(0),jc_entry_bytes(1),
  settings.cooldown_accesses,settings.shrinkage,settings.reserve_fraction,jc_scar_scratch_bytes(),
  cfg.costs.state_ns[0],cfg.costs.state_ns[1],cfg.costs.state_ns[2],cfg.costs.state_ns[3],
  cfg.costs.add_public_ns,cfg.costs.add_secret_ns,cfg.costs.erase_public_ns,cfg.costs.erase_secret_ns,profile);
 uint64_t last=0,sequence=0;char line[160];int status=0;
 while(fgets(line,sizeof(line),stdin)){
  char a[80],b[80],extra;uint64_t t,key;
  if(sscanf(line,"%79s %79s %c",a,b,&extra)!=2||decimal(a,&t)||decimal(b,&key)||
   key>=64||t<last||t>UINT64_C(1000000000000)){
   fprintf(stderr,"invalid monotone metadata trace row\n");status=2;break;
  }
  last=t;
  JointEntryView before[JC_MAX_OBJECTS],expired[JC_MAX_OBJECTS],after[JC_MAX_OBJECTS];
  size_t nb=jc_entries(c,before,JC_MAX_OBJECTS);jc_expire(c,t);
  size_t ne=jc_entries(c,expired,JC_MAX_OBJECTS);
  jc_observe(c,(unsigned)key,t,t);JointPlan plan;
  if(jc_plan_with_scratch(c,(unsigned)key,t,&plan,&scratch,sizeof(scratch))||jc_commit(c,&plan,t)||fill_publish(c,(unsigned)key)){
   fprintf(stderr,"metadata trace transaction failed\n");status=1;break;
  }
  size_t na=jc_entries(c,after,JC_MAX_OBJECTS);sequence++;last=t;
  JointRetirePlan retire;
  if(jc_retire_plan(c,t,&retire,&scratch,sizeof(scratch))||(retire.considered&&jc_retire_commit(c,&retire,t))){status=1;break;}
  jc_expire(c,t);
  JointEntryView retired[JC_MAX_OBJECTS];size_t nr=jc_entries(c,retired,JC_MAX_OBJECTS);
  printf("{\"kind\":\"event\",\"t_ns\":%" PRIu64 ",\"context\":%" PRIu64 ",\"sequence\":%" PRIu64 ",\"before_expire\":",t,key,sequence);
  entries_json(before,nb);printf(",\"after_expire\":");entries_json(expired,ne);
  printf(",\"plan\":{\"evict_bytes\":[");
  for(unsigned j=0;j<plan.evict_count;j++){if(j)putchar(',');printf("%u",plan.evict[j]*32);}
  printf("],\"place_bytes\":[%u,%u],\"mask\":%u,\"objective_ns\":%.17g,\"clock_ns\":%" PRIu64
   ",\"context\":%u,\"revision\":%" PRIu64 "},\"after_publish\":",
   plan.place[0]*32,plan.place[1]*32,plan.mask,plan.objective_ns,plan.clock_ns,plan.context,plan.revision);
  entries_json(after,na);printf(",\"retirement\":{\"mask\":%u,\"considered\":%u,\"objective_ns\":%.17g,\"revision\":%" PRIu64 "},\"after_retire\":",retire.mask,retire.considered,retire.objective_ns,retire.revision);
  entries_json(retired,nr);printf(",\"stats\":");stats_json(jc_stats(c));printf("}\n");
 }
 if(ferror(stdin))status=1;
 jc_clear_all(c,last);
 if(!status){printf("{\"kind\":\"final\",\"t_ns\":%" PRIu64 ",\"entries\":[],\"stats\":",last);stats_json(jc_stats(c));printf("}\n");}
 explicit_bzero(storage,(size_t)bytes);free(storage);return status;
}

/* A bounded public-API smoke gate, not crypto or scientific execution. */
int joint_controller_selftest(void){
 void *storage=aligned_alloc(32,32768);if(!storage)return 1;
 JointConfig cfg=fixture_config(JC_SCAR,32768,SCAR_ALL_COMPONENTS);
 JointCache*c=jc_init(storage,32768,&cfg);JointScarSettings set={0,2,0};
 JointScarScratch scratch={0};int failed=!c||jc_scar_configure(c,&set);
 for(unsigned i=0;i<256&&!failed;i++){
  uint64_t t=1000+(uint64_t)i*100000;unsigned key=(i/32)%8;
  jc_expire(c,t);jc_observe(c,key,t,t);JointPlan p;JointRetirePlan r;
  failed=jc_plan_with_scratch(c,key,t,&p,&scratch,sizeof(scratch))||p.evict_count>SCAR_MAX_VICTIMS||jc_commit(c,&p,t)||fill_publish(c,key);
  if(!failed)failed=jc_retire_plan(c,t,&r,&scratch,sizeof(scratch))||(r.considered&&jc_retire_commit(c,&r,t));
  if(!failed)failed=!jc_check(c);
 }
 if(c){jc_clear_all(c,25600000);failed|=!jc_check(c);}
 explicit_bzero(storage,32768);free(storage);
 if(!failed)puts("controller_literal_fixtures=passed metadata_only=1");
 return failed?1:0;
}
