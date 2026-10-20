/* Exact saved SIEVE package compiled separately as parent. No SCAR comparison:
 * its intended architecture changed. Every other policy retains full state. */
#include <stdio.h>
#include <stdlib.h>
#include "../joint_controller.c"
JointCache*parent_jc_init(void*,size_t,const JointConfig*);
void parent_jc_observe(JointCache*,unsigned,uint64_t,uint64_t);
int parent_jc_plan(JointCache*,unsigned,uint64_t,JointPlan*);
int parent_jc_commit(JointCache*,const JointPlan*,uint64_t);
void*parent_jc_pending(JointCache*,unsigned,unsigned);
int parent_jc_publish(JointCache*,unsigned,unsigned);
void parent_jc_expire(JointCache*,uint64_t);
void parent_jc_clear_all(JointCache*,uint64_t);
int parent_jc_rotate(JointCache*,unsigned,uint64_t,uint64_t);
int parent_jc_check(const JointCache*);
static unsigned char a[65536] __attribute__((aligned(32))),b[65536] __attribute__((aligned(32)));
static unsigned long checks,events,cases;
#define T(x) do{checks++;if(!(x)){fprintf(stderr,"parity_fail line=%d expression=%s case=%lu event=%lu\n",__LINE__,#x,cases,events);exit(1);}}while(0)
int main(void){
 for(unsigned policy=0;policy<=JC_PUBLIC_SIEVE;policy++)if(policy!=JC_SCAR)for(unsigned bytes=32768;bytes<=65536;bytes*=2)for(unsigned profile=0;profile<3;profile++){
  JointConfig cfg={.arena_bytes=bytes,.contexts=64,.history_capacity=1000,.components=31,.policy=(JointPolicy)policy,
   .ttl_ns=10000000,.guard_ns=500000,.horizon_ns=10000000,.public_seed=7,.costs={{30000,26000,20000,15000},-100,50,200,100}};
  if(profile==1)cfg.costs=(JointCosts){{30000,31000,32000,35000},100,100,200,200};
  if(profile==2)cfg.costs=(JointCosts){{30000,23000,20000,16000},-500,0,0,0};
  JointCache*c=jc_init(a,bytes,&cfg),*r=parent_jc_init(b,bytes,&cfg);T(c&&r);cases++;
  uint64_t now=100,rng=13;
  for(unsigned j=0;j<300;j++){
   rng=rng*6364136223846793005ULL+1;unsigned key=j%3?(j/9)%5:(unsigned)(rng>>32)%64;now+=j%37?500000:11000000;
   jc_expire(c,now);parent_jc_expire(r,now);jc_observe(c,key,now,now);parent_jc_observe(r,key,now,now);
   JointPlan x,y;T(jc_plan(c,key,now,&x)==parent_jc_plan(r,key,now,&y));
   T(x.mask==y.mask&&x.evict_count==y.evict_count&&x.objective_ns==y.objective_ns);
   T(!memcmp(x.evict,y.evict,sizeof(x.evict))&&!memcmp(x.place,y.place,sizeof(x.place)));
   T(x.sequence==y.sequence&&x.revision==y.revision&&x.clock_ns==y.clock_ns&&x.context==y.context);
   T(jc_commit(c,&x,now)==parent_jc_commit(r,&y,now));
   for(unsigned t=0;t<2;t++){void*u=jc_pending(c,key,t),*v=parent_jc_pending(r,key,t);T((u!=NULL)==(v!=NULL));if(u){memset(u,0x42,t?1152:3520);memset(v,0x42,t?1152:3520);T(jc_publish(c,key,t)==parent_jc_publish(r,key,t));}}
   if(j%61==0){uint64_t gen=jc_generation(c,key)+1;T(jc_rotate(c,key,gen,now)==parent_jc_rotate(r,key,gen,now));}
   T(jc_check(c)&&parent_jc_check(r));T(!memcmp(a,b,bytes));events++;
  }
  jc_clear_all(c,now);parent_jc_clear_all(r,now);T(!memcmp(a,b,bytes));
 }
 printf("control_parity_pass=1 controls=12 cases=%lu request_events=%lu checks=%lu crypto_linked=0 timing_endpoints=0\n",cases,events,checks);return 0;
}
