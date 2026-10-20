/* Fake payloads/logical time only. Independent object-list enumeration and
 * one-bit allocation oracle; no cryptographic or empirical workload input. */
#include <stdio.h>
#include <stdlib.h>
static unsigned link_steps,placement_probes;
#define SCAR_TEST_LINK() (link_steps++)
#define SCAR_TEST_PROBE() (placement_probes++)
#include "../joint_controller.c"
static unsigned long checks,events,streams,targets,searches,rejections,pruned_probes,exact_parity;
static unsigned active_mask,active_profile,active_event;
#define T(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line=%d expression=%s mask=%u profile=%u event=%u\n",__LINE__,#x,active_mask,active_profile,active_event);exit(1);}}while(0)
static unsigned char arena[65536] __attribute__((aligned(32)));
static unsigned char saved[65536] __attribute__((aligned(32)));
static JointScarScratch scratch,unpruned_scratch;
typedef struct {unsigned key,type,off,span,ready,seen;uint64_t born;} Object;
typedef struct {Object o[128];unsigned n;int hand;} Snapshot;
static int locate(const Snapshot*r,unsigned off){for(unsigned i=0;i<r->n;i++)if(r->o[i].off==off)return (int)i;return -1;}
static Snapshot snapshot(const JointCache*c){
 Snapshot r={0};r.hand=-1;const SieveState*s=sieve_state(c);
 for(unsigned off=s->head;off;off=entry(c,off)->next){const Entry*e=entry(c,off);T(r.n<128);r.o[r.n++]=(Object){e->key,e->type,off,e->span,e->state==READY,e->seen,e->born};}
 if(s->hand){r.hand=locate(&r,s->hand);T(r.hand>=0);}return r;
}
static unsigned state_of(const Snapshot*r,unsigned key){unsigned x=0;for(unsigned i=0;i<r->n;i++)if(r->o[i].key==key)x|=1u<<r->o[i].type;return x;}
static double ref_rate(const History*h,uint64_t now){
 if(!h->count)return 0.;double d=h->mean;
 if(d<(double)(now-h->last))d=(double)(now-h->last);if(d<50000.)d=50000.;
 return ((double)h->count/((double)h->count+2.))/d;
}
static double ref_benefit(const JointCache*c,const Snapshot*r,unsigned key,unsigned state,uint64_t now){
 const CausalState*z=(const CausalState*)(base(c)+c->history_at);
 double q=(c->cfg.components&SCAR_CONTEXT)?ref_rate((History*)(base(c)+z->histories_at)+key,now):ref_rate(&z->global,now)/c->cfg.contexts;
 uint64_t born=now;for(unsigned i=0;i<r->n;i++)if(r->o[i].key==key&&r->o[i].type==1)born=r->o[i].born;
 uint64_t age=now-born,span=c->cfg.ttl_ns-c->cfg.guard_ns;
 double R=age>=span?0.:(double)(span-age),H=(double)c->cfg.horizon_ns;if(R>H)R=H;
 const double*v=c->cfg.costs.state_ns;double p=state&1,s=(state>>1)&1;
 return q*(H*p*(v[0]-v[2])+R*s*(v[0]-v[1])+R*p*s*(v[2]+v[1]-v[0]-v[3]));
}
static int contains(const unsigned*ids,unsigned n,unsigned id){for(unsigned i=0;i<n;i++)if(ids[i]==id)return 1;return 0;}
/* This oracle charges each newly admitted erase exactly once and enumerates
 * each context's complete before/after state, independently of prefix memos. */
static double ref_score(const JointCache*c,const Snapshot*r,unsigned key,unsigned mask,const unsigned*ids,unsigned n,uint64_t now){
 unsigned current=state_of(r,key);double u=ref_benefit(c,r,key,current|mask,now)-ref_benefit(c,r,key,current,now);
 const JointCosts*d=&c->cfg.costs;
 if(mask&1)u-=d->add_public_ns+((current&2)?0.:d->state_ns[2]+d->state_ns[1]-d->state_ns[0]-d->state_ns[3])+d->erase_public_ns;
 if(mask&2)u-=d->add_secret_ns+d->erase_secret_ns;
 u-=d->state_ns[0]/32.;
 for(unsigned k=0;k<c->cfg.contexts;k++){
  unsigned before=state_of(r,k),after=before;
  for(unsigned i=0;i<r->n;i++)if(r->o[i].key==k&&contains(ids,n,i))after&=~(1u<<r->o[i].type);
  if(before!=after)u+=ref_benefit(c,r,k,after,now)-ref_benefit(c,r,k,before,now);
 }
 return u-n*d->state_ns[0]/1024.;
}
static int ref_fit(const JointCache*c,const Snapshot*r,unsigned mask,const unsigned*ids,unsigned n,unsigned place[2]){
 unsigned char occupied[2048]={0};unsigned end=(unsigned)c->bytes/32;
 for(unsigned i=0;i<c->prefix_units;i++)occupied[i]=1;
 for(unsigned i=0;i<r->n;i++)if(!contains(ids,n,i))for(unsigned j=0;j<r->o[i].span;j++)occupied[r->o[i].off+j]=1;
 for(unsigned t=0;t<2;t++){
  place[t]=0;if(!(mask&(1u<<t)))continue;unsigned need=t?38:112;
  for(unsigned start=c->prefix_units;start+need<=end;start++){
   unsigned free=1;for(unsigned j=0;j<need;j++)if(occupied[start+j]){free=0;break;}
   if(free){place[t]=start;for(unsigned j=0;j<need;j++)occupied[start+j]=1;break;}
  }
  if(!place[t])return 0;
 }return 1;
}
static int ref_better(const Snapshot*r,const JointPlan*a,const JointPlan*b){
 /* Different summation order may differ by a few ulps; targeted tie cases
  * below use exact integers. Never turn an appreciable difference into a tie. */
 double delta=a->objective_ns-b->objective_ns;
 if(fabs(delta)>1e-8)return delta>0;
 int64_t net[2][2]={{0}};const JointPlan*p[2]={a,b};
 for(unsigned j=0;j<2;j++){
  net[j][0]=(p[j]->mask&2)?1216:0;net[j][1]=net[j][0]+((p[j]->mask&1)?3584:0);
  for(unsigned i=0;i<p[j]->evict_count;i++){int at=locate(r,p[j]->evict[i]);T(at>=0);net[j][1]-=r->o[at].span*32;if(r->o[at].type)net[j][0]-=r->o[at].span*32;}
 }
 return net[0][0]<net[1][0]||(net[0][0]==net[1][0]&&(net[0][1]<net[1][1]||(net[0][1]==net[1][1]&&a->mask<b->mask)));
}
static JointPlan reference_joint(JointCache*c,Snapshot*r,unsigned key,uint64_t now,unsigned*walked,unsigned*probes){
 JointPlan best={0};unsigned missing=3u&~state_of(r,key),prefix[4]={0},n=0;
 if(!(c->cfg.components&SCAR_SECRET))missing&=1;
 *walked=*probes=0;if(!missing)return best;
 int gate=(c->cfg.components&SCAR_ADMISSION)!=0,found=0;
 double max=-INFINITY;for(unsigned m=1;m<=3;m++)if(!(m&~missing)){double u=ref_score(c,r,key,m,prefix,0,now);if(u>max)max=u;}
 if(gate&&max<=0)return best;
 for(unsigned m=1;m<=3;m++)if(!(m&~missing)){
  JointPlan p={0};p.mask=m;p.objective_ns=ref_score(c,r,key,m,prefix,0,now);(*probes)++;
  if(ref_fit(c,r,m,prefix,0,p.place)&&(!gate||p.objective_ns>0)&&(!found||ref_better(r,&p,&best))){best=p;found=1;}
 }
 if(found)return best;
 unsigned limit=2*r->n;
 int at=r->hand<0?(int)r->n-1:r->hand;
 while(at>=0&&*walked<limit&&n<4){
  Object*o=r->o+at;(*walked)++;r->hand=at?at-1:-1;
  if(o->ready&&o->key!=key&&!contains(prefix,n,(unsigned)at)){if(o->seen)o->seen=0;else prefix[n++]=(unsigned)at;}
  at=r->hand<0?(int)r->n-1:r->hand;
 }
 for(unsigned m=1;m<=3;m++)if(!(m&~missing))for(unsigned k=1;k<=n;k++){
  JointPlan p={0};p.mask=m;p.evict_count=k;for(unsigned j=0;j<k;j++)p.evict[j]=r->o[prefix[j]].off;
  p.objective_ns=ref_score(c,r,key,m,prefix,k,now);(*probes)++;
  if(ref_fit(c,r,m,prefix,k,p.place)&&(!gate||p.objective_ns>0)&&(!found||ref_better(r,&p,&best))){best=p;found=1;}
 }
 return best;
}
/* Separate list-based oracle. Public prefixes are enumerated via snapshot
 * objects and one-bit placement; S uses an independent conditional cost
 * difference C[p,0]-C[p,1], not the implementation's four-value memo. */
static JointPlan reference_conditional(JointCache*c,Snapshot*r,unsigned key,uint64_t now,unsigned*walked,unsigned*probes){
 JointPlan chosen={0};unsigned current=state_of(r,key),prefix[4]={0},n=0;
 int gate=(c->cfg.components&SCAR_ADMISSION)!=0;*walked=*probes=0;
 if(!(current&1)){
  double profit=ref_score(c,r,key,1,prefix,0,now);
  if(!gate||profit>0){
   JointPlan candidate={0};candidate.mask=1;candidate.objective_ns=profit;(*probes)++;
   if(ref_fit(c,r,1,prefix,0,candidate.place))chosen=candidate;
   else {
    unsigned limit=2*r->n;int at=r->hand<0?(int)r->n-1:r->hand;
    while(at>=0&&*walked<limit&&n<4){
     Object*o=r->o+at;(*walked)++;r->hand=at?at-1:-1;
     if(o->ready&&o->key!=key&&!contains(prefix,n,(unsigned)at)){
      if(o->seen)o->seen=0;else prefix[n++]=(unsigned)at;
     }
     at=r->hand<0?(int)r->n-1:r->hand;
    }
    for(unsigned count=1;count<=n;count++){
     candidate=(JointPlan){0};candidate.mask=1;candidate.evict_count=count;
     for(unsigned j=0;j<count;j++)candidate.evict[j]=r->o[prefix[j]].off;
     candidate.objective_ns=ref_score(c,r,key,1,prefix,count,now);(*probes)++;
     if(ref_fit(c,r,1,prefix,count,candidate.place)&&(!gate||candidate.objective_ns>0)&&
        (!chosen.mask||ref_better(r,&candidate,&chosen)))chosen=candidate;
    }
   }
  }
 }
 if(!(current&2)&&(c->cfg.components&SCAR_SECRET)){
  const CausalState*z=(const CausalState*)(base(c)+c->history_at);
  double q=(c->cfg.components&SCAR_CONTEXT)?ref_rate((History*)(base(c)+z->histories_at)+key,now):ref_rate(&z->global,now)/c->cfg.contexts;
  double life=(double)(c->cfg.ttl_ns-c->cfg.guard_ns);if(life>c->cfg.horizon_ns)life=(double)c->cfg.horizon_ns;
  unsigned has_public=(current|chosen.mask)&1;
  const JointCosts*cost=&c->cfg.costs;
  double margin=q*life*(cost->state_ns[2*has_public]-cost->state_ns[2*has_public+1])-cost->add_secret_ns-cost->erase_secret_ns-cost->state_ns[0]/32.;
  if(!gate||margin>0){
   JointPlan candidate=chosen;candidate.mask|=2;candidate.objective_ns+=margin;
   unsigned ids[4];for(unsigned j=0;j<chosen.evict_count;j++)ids[j]=(unsigned)locate(r,chosen.evict[j]);
   (*probes)++;if(ref_fit(c,r,candidate.mask,ids,chosen.evict_count,candidate.place))chosen=candidate;
  }
 }
 return chosen;
}
static JointPlan reference(JointCache*c,Snapshot*r,unsigned key,uint64_t now,unsigned*walked,unsigned*probes){
 if(c->cfg.components&SCAR_FACTORED)return reference_conditional(c,r,key,now,walked,probes);
 return reference_joint(c,r,key,now,walked,probes);
}
static JointCache*init(unsigned mask,unsigned bytes,unsigned profile){
 const JointCosts costs[]={{{31762.1675,28648.68833333333,22274.76875,19150.25375},-24.082916666667,394.085,655.0416666667,480.7858333333},
  {{30000,26000,20000,15000},-100,50,200,100},{{30000,23000,20000,16000},-100,50,200,100},
  {{30000,31000,32000,35000},100,100,200,200},{{30000,20000,20000,10000},-500,0,0,0},
  {{30000,26000,20000,15000},20000,20000,20000,20000}};
 active_mask=mask;active_profile=profile;JointConfig cfg={.arena_bytes=bytes,.contexts=64,.history_capacity=1000,.components=mask,.policy=JC_SCAR,
 .ttl_ns=10000000,.guard_ns=500000,.horizon_ns=10000000,.public_seed=1,.costs=costs[profile]};
 JointCache*c=jc_init(arena,bytes,&cfg);T(c!=NULL);JointScarSettings set={0,2,0};T(jc_scar_configure(c,&set)==0);T(jc_check(c));
 CausalState*z=scar_state(c);T(z->histories_at&&z->cooldowns_at&&z->queue_at);T(z->queue_at>=z->cooldowns_at+64);T(z->cooldowns_at>=z->histories_at+64*sizeof(History));
 memset(&scratch,0,sizeof(scratch));return c;
}
static JointPlan check_plan(JointCache*c,unsigned key,uint64_t now){
 Snapshot r=snapshot(c);unsigned steps,probes;JointPlan wanted=reference(c,&r,key,now,&steps,&probes),p;
 JointCache*unpruned=NULL;JointPlan exhaustive={0};
 if(c->cfg.components&SCAR_PRUNED){
  memcpy(saved,arena,c->bytes);unpruned=(JointCache*)saved;unpruned->cfg.components&=~SCAR_PRUNED;
  memset(&unpruned_scratch,0,sizeof(unpruned_scratch));
  T(jc_plan_with_scratch(unpruned,key,now,&exhaustive,&unpruned_scratch,sizeof(unpruned_scratch))==0);
 }
 uint64_t forecast=scar_state(c)->stats.forecast_contexts;link_steps=placement_probes=0;
 T(jc_plan_with_scratch(c,key,now,&p,&scratch,sizeof(scratch))==0);
 T(p.mask==wanted.mask&&p.evict_count==wanted.evict_count);
 T(!memcmp(p.evict,wanted.evict,sizeof(p.evict))&&!memcmp(p.place,wanted.place,sizeof(p.place)));
 T(fabs(p.objective_ns-wanted.objective_ns)<1e-7*(1+fabs(wanted.objective_ns)));
 T(link_steps==steps&&placement_probes<=probes&&probes<=((c->cfg.components&SCAR_FACTORED)?6u:15u));
 if(c->cfg.components&SCAR_PRUNED){
  T(p.mask==exhaustive.mask&&p.evict_count==exhaustive.evict_count&&p.sequence==exhaustive.sequence&&p.revision==exhaustive.revision&&p.clock_ns==exhaustive.clock_ns&&p.context==exhaustive.context);
  T(!memcmp(p.evict,exhaustive.evict,sizeof(p.evict))&&!memcmp(p.place,exhaustive.place,sizeof(p.place))&&!memcmp(&p.objective_ns,&exhaustive.objective_ns,sizeof(double)));
  unpruned->cfg.components=c->cfg.components;
  scar_state(unpruned)->stats=scar_state(c)->stats;
  T(!memcmp(saved,arena,c->bytes));exact_parity++;pruned_probes+=probes-placement_probes;
 }else T(placement_probes==probes);
 T(scar_state(c)->stats.forecast_contexts-forecast<=5);
 T(link_steps<=2*r.n);
 Snapshot actual=snapshot(c);T(actual.n==r.n&&actual.hand==r.hand);
 for(unsigned i=0;i<r.n;i++)T(actual.o[i].seen==r.o[i].seen);
 for(unsigned i=0;i<sizeof(scratch);i++)T(!((unsigned char*)&scratch)[i]);
 T(jc_check(c));if(link_steps)searches++;if(!p.mask)rejections++;return p;
}
static void publish(JointCache*c,unsigned key){for(unsigned t=0;t<2;t++){void*p=jc_pending(c,key,t);if(p){memset(p,0x51,t?1152:3520);T(jc_publish(c,key,t)==0);}}}
static void force(JointCache*c,unsigned key,unsigned mask,uint64_t now,int ready){
 JointPlan p={0};p.context=key;p.mask=mask;p.clock_ns=now;p.sequence=c->seq;p.revision=c->revision;int need=-1;
 T(try_place(c,&p,&need));T(jc_commit(c,&p,now)==0);if(ready)publish(c,key);
}
static void stream_checks(void){
 const unsigned masks[]={31,30,29,27,23,15,14,13,11,7};
 for(unsigned mi=0;mi<sizeof(masks)/sizeof(masks[0]);mi++)for(unsigned bi=0;bi<2;bi++)for(unsigned profile=0;profile<6;profile++)for(unsigned pattern=0;pattern<4;pattern++){
  JointCache*c=init(masks[mi],bi?65536:32768,profile);uint64_t now=1000,rng=97;streams++;
  for(unsigned j=0;j<240;j++){
   active_event=j;rng=rng*6364136223846793005ULL+1;unsigned key;
   if(pattern==0)key=(unsigned)(rng>>32)%64;else if(pattern==1)key=(j/24)%4;
   else if(pattern==2)key=j%9;else key=j<120?j%3:20+j%23;
   now+=j%73==0?11000000:50000; jc_expire(c,now);jc_observe(c,key,now,now);
   JointPlan p=check_plan(c,key,now);T(jc_commit(c,&p,now)==0);publish(c,key);
   T(jc_commit(c,&p,now)==-1);T(jc_check(c));events++;
   CausalState*z=scar_state(c);for(unsigned k=0;k<64;k++)T(!base(c)[z->cooldowns_at+k]);
   if(!(masks[mi]&SCAR_CONTEXT))for(unsigned k=0;k<64*sizeof(History);k++)T(!base(c)[z->histories_at+k]);
   if(j%47==0){T(jc_rotate(c,key,jc_generation(c,key)+1,now)==0);T(jc_check(c));}
  }
  jc_clear_all(c,now);T(jc_check(c));T(jc_stats(c).entries==0);T(sieve_state(c)->count==0);
 }
}
static void targeted_checks(void){
 /* All current/missing states, signed interactions, a P/S pair from one
  * victim context and one-time admission erase liability. */
 for(unsigned profile=0;profile<6;profile++)for(unsigned current=0;current<4;current++){
  JointCache*c=init(15,65536,profile);if(current)force(c,0,current,100,1);force(c,1,3,100,1);
  jc_observe(c,0,200,200);jc_observe(c,0,50200,50200);jc_observe(c,1,50200,50200);jc_observe(c,1,100200,100200);
  Snapshot r=snapshot(c);double values[4];scar_values(c,0,100200,values);
  for(unsigned m=1;m<=3;m++)if(!(m&current)){
   double u=values[current|m]-values[current]-scar_setup(c,0,m)-c->cfg.costs.state_ns[0]/32.;
   unsigned ids[2];unsigned n=0;for(unsigned i=0;i<r.n;i++)if(r.o[i].key==1)ids[n++]=i;T(n==2);
   T(fabs(u-ref_score(c,&r,0,m,ids,0,100200))<1e-7);
   double v[4];scar_values(c,1,100200,v);T(fabs(u+v[0]-v[3]-2*c->cfg.costs.state_ns[0]/1024.-ref_score(c,&r,0,m,ids,2,100200))<1e-7);
  }
  (void)check_plan(c,0,100200);jc_clear_all(c,100200);targets++;
 }
 /* Cold negative surplus bypass vs removal of BOTH profitability gates. */
 JointCache*c=init(15,32768,5);jc_observe(c,0,100,100);JointPlan p=check_plan(c,0,100);T(!p.mask&&!link_steps&&!placement_probes);targets++;
 c=init(11,32768,5);jc_observe(c,0,100,100);p=check_plan(c,0,100);T(p.mask&&p.objective_ns<0&&!link_steps);targets++;
 /* Same full memory reservation in every ablation. */
 uint64_t prefix=0;const unsigned masks[]={31,30,29,27,23,15,14,13,11,7};for(unsigned i=0;i<sizeof(masks)/sizeof(masks[0]);i++){c=init(masks[i],32768,0);uint64_t x=jc_stats(c).prefix_bytes;if(i)T(x==prefix);prefix=x;}targets++;
 /* PENDING/current protections and all-visited traversal. */
 c=init(11,65536,0);for(unsigned k=0;k<20;k++)force(c,k,2,100,1);force(c,30,1,100,0);
 for(unsigned off=sieve_state(c)->head;off;off=entry(c,off)->next)entry(c,off)->seen=1;
 uint32_t ids[4];unsigned protected_offset=indexes(c)[0].offset[1],pending=indexes(c)[30].offset[0];
 uint64_t revision=c->revision;link_steps=0;unsigned n=scar_prefix(c,0,ids);T(n==4&&link_steps>8&&link_steps<=2*sieve_state(c)->count);T(entry(c,protected_offset)->seen==1&&entry(c,pending)->seen==1);T(c->revision==revision);targets++;
 /* The public planning entry consumes revision even when no action fits;
  * direct private prefix above is used solely to inspect the walk. */
 p=check_plan(c,40,100);T(c->revision>revision);T(jc_check(c));targets++;
 c=init(3,32768,0);for(unsigned k=0;k<3;k++)force(c,k,2,100,1);
 for(unsigned off=sieve_state(c)->head;off;off=entry(c,off)->next)entry(c,off)->seen=1;
 link_steps=0;n=scar_prefix(c,63,ids);T(n==3&&link_steps==6);T(ids[0]!=ids[1]&&ids[1]!=ids[2]);targets++;
 /* Zero-prefix success never ages a resident queue. */
 c=init(11,32768,0);force(c,0,1,100,1);entry(c,indexes(c)[0].offset[0])->seen=1;p=check_plan(c,1,100);T(p.mask&&link_steps==0&&entry(c,indexes(c)[0].offset[0])->seen==1);targets++;
 /* Conditional S cannot create victims when an existing requested P is
  * pinned and its arena has no S-sized hole; unrestricted joint search can. */
 for(unsigned mi=0;mi<2;mi++){
  c=init(mi?7:15,32768,0);for(unsigned k=0;k<64&&c->bytes-c->used>=3584;k++)force(c,k,1,100,1);for(unsigned k=60;k<64&&c->bytes-c->used>=1216;k++)force(c,k,2,100,1);T(c->bytes-c->used<1216);
  jc_observe(c,0,200,200);jc_observe(c,0,50200,50200);
  p=check_plan(c,0,50200);
  if(mi)T(p.mask==2&&p.evict_count>0);else T(!p.mask&&!p.evict_count&&!link_steps&&placement_probes==1);
  jc_clear_all(c,50200);targets++;
 }
 /* Aggregate free-space rejection occurs before forecast or allocation. */
 c=init(31,32768,0);for(unsigned k=0;k<64&&c->bytes-c->used>=3584;k++)force(c,k,1,100,1);for(unsigned k=60;k<64&&c->bytes-c->used>=1216;k++)force(c,k,2,100,1);T(c->bytes-c->used<1216);
 jc_observe(c,0,200,200);jc_observe(c,0,50200,50200);
 uint64_t before_forecast=scar_state(c)->stats.forecast_contexts;
 p=check_plan(c,0,50200);T(!p.mask&&!link_steps&&!placement_probes);
 T(scar_state(c)->stats.forecast_contexts==before_forecast);targets++;
 /* Positive conditional S combines with P using the exact same victim set. */
 c=init(15,32768,0);jc_observe(c,0,200,200);jc_observe(c,0,50200,50200);
 p=check_plan(c,0,50200);T(p.mask==3&&p.evict_count==0&&placement_probes==2);targets++;
 /* Pending requested context rejected atomically. */
 c=init(15,32768,0);force(c,0,1,100,0);memcpy(saved,arena,32768);T(jc_plan_with_scratch(c,0,100,&p,&scratch,sizeof(scratch))==-1);T(!memcmp(saved,arena,32768));targets++;
 /* Deadline endpoint unchanged; birth never renews on a hit. */
 c=init(15,32768,0);force(c,0,2,100,1);jc_observe(c,0,200,200);T(entry(c,indexes(c)[0].offset[1])->born==100);
 jc_expire(c,9500099);T(indexes(c)[0].offset[1]);jc_expire(c,9500100);T(!indexes(c)[0].offset[1]&&jc_stats(c).zeroizations==1&&jc_stats(c).max_residency_ns==9500000);targets++;
 /* Equal timestamps do not invent positive gaps; count saturates. */
 c=init(15,32768,0);jc_observe(c,0,100,100);jc_observe(c,0,100,100);CausalState*z=scar_state(c);History*h=(History*)(base(c)+z->histories_at);T(!h->count);jc_observe(c,0,50100,50100);T(h->count==1&&h->mean==50000.);h->count=UINT32_MAX;jc_observe(c,0,150100,150100);T(h->count==UINT32_MAX&&h->mean==75000.);targets++;
 /* No retirement token; ordinary secret clear remains usable. */
 JointRetirePlan rp;T(jc_retire_plan(c,150100,&rp,&scratch,sizeof(scratch))==0&&!rp.considered&&!rp.mask);T(jc_retire_commit(c,&rp,150100)==-1);targets++;
 jc_clear_all(c,150100);T(jc_check(c));
}
int main(void){T(38u*32u==64u+1152u&&112u*32u==64u+3520u);targeted_checks();stream_checks();T(searches>0&&rejections>0&&exact_parity>0&&pruned_probes>0);printf("exact_action_arena_parity=%lu skipped_placement_probes=%lu\n",exact_parity,pruned_probes);printf("admission_metadata_pass=1 streams=%lu request_events=%lu targeted=%lu checks=%lu searched=%lu bypassed=%lu crypto_linked=0 timing_endpoints=0\n",streams,events,targets,checks,searches,rejections);return 0;}
