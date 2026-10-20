/* SCAR-MLKEM: one bounded joint-admission decision, no global retirement.
 * Only public causal history and fixed shared costs enter the surrogate.
 * See Reports/FeasibilityPruning/Preparation/PROTOCOL.md.
 */
#ifndef SCAR_TEST_LINK
#define SCAR_TEST_LINK() ((void)0)
#endif
#ifndef SCAR_TEST_PROBE
#define SCAR_TEST_PROBE() ((void)0)
#endif
static CausalState *scar_state(const JointCache*c){return (CausalState*)(base(c)+c->history_at);}
size_t jc_scar_scratch_bytes(void){return sizeof(JointScarScratch);}
JointScarStats jc_scar_stats(const JointCache*c){JointScarStats z={0};return c&&c->cfg.policy==JC_SCAR?scar_state(c)->stats:z;}
int jc_scar_configure(JointCache*c,const JointScarSettings*s){
 if(!c||!s||c->cfg.policy!=JC_SCAR||c->seq||c->used!=(uint64_t)c->prefix_units*Q||scar_state(c)->configured)return -1;
 if(s->cooldown_accesses!=0||s->shrinkage!=2||s->reserve_fraction!=0.)return -1;
 scar_state(c)->settings=*s;scar_state(c)->configured=1;c->revision++;return 0;
}
static double scar_rate(const History*h,uint64_t now){
 if(!h->count)return 0.;
 assert(h->seen&&now>=h->last);
 return ((double)h->count/((double)h->count+2.))/fmax(50000.,fmax(h->mean,(double)(now-h->last)));
}
static unsigned scar_current(const JointCache*c,unsigned key){
 return (indexes(c)[key].offset[0]?1u:0u)|(indexes(c)[key].offset[1]?2u:0u);
}
static double scar_remaining(const JointCache*c,uint64_t birth,uint64_t now){
 assert(now>=birth);
 uint64_t age=now-birth,span=c->cfg.ttl_ns-c->cfg.guard_ns;
 return fmin((double)c->cfg.horizon_ns,age>=span?0.:(double)(span-age));
}
static void scar_values(JointCache*c,unsigned key,uint64_t now,double v[4]){
 CausalState*z=scar_state(c);double q;
 if(c->cfg.components&SCAR_CONTEXT)q=scar_rate((History*)(base(c)+z->histories_at)+key,now);
 else q=scar_rate(&z->global,now)/c->cfg.contexts;
 Entry*s=entry(c,indexes(c)[key].offset[1]);
 double H=(double)c->cfg.horizon_ns,R=scar_remaining(c,s?s->born:now,now),dp,ds,di;
 gains(c,&dp,&ds,&di);
 for(unsigned state=0;state<4;state++){
  unsigned p=state&1u,t=(state>>1)&1u;
  v[state]=q*(H*p*dp+R*t*ds+fmin(H,R)*p*t*di);
 }
 z->stats.forecast_contexts++;
}
static double scar_setup(const JointCache*c,unsigned key,unsigned mask){
 return (mask&1?public_transition_cost((JointCache*)c,key)+c->cfg.costs.erase_public_ns:0.)+
        (mask&2?c->cfg.costs.add_secret_ns+c->cfg.costs.erase_secret_ns:0.);
}
static int scar_better(const JointCache*c,const JointPlan*a,const JointPlan*b){
 if(a->objective_ns!=b->objective_ns)return a->objective_ns>b->objective_ns;
 /* Net newly retained bytes; loss of an existing S reduces resident exposure. */
 int64_t secret[2]={0,0},total[2]={0,0};const JointPlan*p[2]={a,b};
 for(unsigned i=0;i<2;i++){
  secret[i]=(p[i]->mask&2)?(int64_t)jc_entry_bytes(1):0;
  total[i]=secret[i]+((p[i]->mask&1)?(int64_t)jc_entry_bytes(0):0);
  for(unsigned j=0;j<p[i]->evict_count;j++){
   Entry*e=entry(c,p[i]->evict[j]);total[i]-=(int64_t)e->span*Q;
   if(e->type==1)secret[i]-=(int64_t)e->span*Q;
  }
 }
 return secret[0]<secret[1]||(secret[0]==secret[1]&&(total[0]<total[1]||(total[0]==total[1]&&a->mask<b->mask)));
}
/* One total queue walk. Protected and already-proposed nodes still cost a
 * link examination, but their bits are untouched. Hand progress survives
 * unsuccessful admission; no payload is removed until validated commit. */
static unsigned scar_prefix(JointCache*c,unsigned key,uint32_t selected[4]){
 SieveState*s=sieve_state(c);unsigned limit=2*s->count,n=0;
 uint32_t off=s->hand?s->hand:s->tail;
 for(unsigned step=0;off&&step<limit&&n<4;step++){
  SCAR_TEST_LINK();
  Entry*e=entry(c,off);unsigned prior=0;
  for(unsigned i=0;i<n;i++)prior|=selected[i]==off;
  s->hand=e->prev;
  if(e->state==READY&&e->key!=key&&!prior){
   if(e->seen)e->seen=0;else selected[n++]=off;
  }
  off=s->hand?s->hand:s->tail;
 }
 return n;
}
static void scar_clear_scratch(JointScarScratch*w,unsigned count){
 explicit_bzero(w->value,count*sizeof(w->value[0]));
 explicit_bzero(w->initial,count);explicit_bzero(w->state,count);
}
static int scar_joint_plan(JointCache*c,unsigned key,uint64_t now,JointPlan*out,JointScarScratch*w,size_t bytes){
 if(!c||!out)return -1;
 if(c->cfg.policy!=JC_SCAR)return jc_plan(c,key,now,out);
 if(key>=c->cfg.contexts||!w||bytes<sizeof(*w)||!scar_state(c)->configured)return -1;
 /* Production calls follow a no-borrow drain. Reject a pending requested
  * context instead of treating its incomplete payload as an observed hit. */
 for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e&&e->state!=READY)return -1;}
 memset(out,0,sizeof(*out));out->context=key;out->clock_ns=now;out->sequence=c->seq;
 c->revision++;out->revision=c->revision;CausalState*z=scar_state(c);
 unsigned current=scar_current(c,key),missing=3u&~current;
 if(!(c->cfg.components&SCAR_SECRET))missing&=1;
 if(!missing)return 0;
 int admission=(c->cfg.components&SCAR_ADMISSION)!=0;
 double v[4],score[4]={0},best=-INFINITY;
 scar_values(c,key,now,v);
 for(unsigned mask=1;mask<=3;mask++)if(!(mask&~missing)){
  score[mask]=v[current|mask]-v[current]-scar_setup(c,key,mask)-c->cfg.costs.state_ns[0]/32.;
  if(score[mask]>best)best=score[mask];
 }
 if(admission&&best<=0.){z->stats.prefilter_rejects++;return 0;}
 PlacementOccupancy occupancy;placement_occupancy(c,&occupancy);
 int found=0;
 /* Cache free-placement outcomes by returning immediately when any acceptable
  * free action exists. Prefix zero is never probed a second time. */
 for(unsigned mask=1;mask<=3;mask++)if(!(mask&~missing)){
  JointPlan p={0};p.context=key;p.clock_ns=now;p.sequence=c->seq;p.revision=c->revision;
  p.mask=mask;p.objective_ns=score[mask];int required=-1;z->stats.candidate_masks++;
  SCAR_TEST_PROBE();int fit_ok=try_place_occupancy(c,&p,&required,&occupancy);
  if(fit_ok&&isfinite(p.objective_ns)&&(!admission||p.objective_ns>0.)&&(!found||scar_better(c,&p,out))){*out=p;found=1;}
 }
 if(found)return 0;
 z->stats.full_searches++;
 uint32_t prefix[4]={0};unsigned n=scar_prefix(c,key,prefix);z->stats.victim_proposals+=n;
 if(!n)return 0;
 /* Five memo slots: requested context plus at most four victim contexts.
  * The common 2176-byte Work reservation remains charged to all policies. */
 memcpy(w->value[0],v,sizeof(v));w->initial[0]=(unsigned char)key;w->state[0]=(unsigned char)current;
 unsigned memo=1;double loss[5]={0};
 for(unsigned i=0;i<n;i++){
  Entry*e=entry(c,prefix[i]);unsigned slot=0;
  while(slot<memo&&w->initial[slot]!=e->key)slot++;
  if(slot==memo){assert(memo<5);scar_values(c,e->key,now,w->value[slot]);w->initial[slot]=(unsigned char)e->key;w->state[slot]=(unsigned char)scar_current(c,e->key);memo++;}
  unsigned before=w->state[slot],after=before&~(1u<<e->type);
  loss[i+1]=loss[i]+w->value[slot][after]-w->value[slot][before];w->state[slot]=(unsigned char)after;
 }
 for(unsigned mask=1;mask<=3;mask++)if(!(mask&~missing))for(unsigned i=1;i<=n;i++){
  JointPlan p={0};p.context=key;p.clock_ns=now;p.sequence=c->seq;p.revision=c->revision;
  p.mask=mask;p.evict_count=i;memcpy(p.evict,prefix,i*sizeof(prefix[0]));
  p.objective_ns=score[mask]+loss[i]-i*c->cfg.costs.state_ns[0]/1024.;
  int required=-1;SCAR_TEST_PROBE();int fit_ok=try_place_occupancy(c,&p,&required,&occupancy);
  if(fit_ok&&isfinite(p.objective_ns)&&(!admission||p.objective_ns>0.)&&(!found||scar_better(c,&p,out))){*out=p;found=1;}
 }
 scar_clear_scratch(w,memo);return 0;
}
/* Conditional admission: P chooses its own victims; S may use only the
 * resulting free placement. The S marginal test can never add a victim. */
static int scar_conditional_plan(JointCache*c,unsigned key,uint64_t now,
                                JointPlan*out,JointScarScratch*w,size_t bytes){
 if(!c||!out)return -1;
 if(c->cfg.policy!=JC_SCAR)return jc_plan(c,key,now,out);
 if(key>=c->cfg.contexts||!w||bytes<sizeof(*w)||!scar_state(c)->configured)return -1;
 for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e&&e->state!=READY)return -1;}
 memset(out,0,sizeof(*out));out->context=key;out->clock_ns=now;out->sequence=c->seq;
 c->revision++;out->revision=c->revision;CausalState*z=scar_state(c);
 unsigned current=scar_current(c,key),missing=3u&~current;
 if(!(c->cfg.components&SCAR_SECRET))missing&=1;
 if(!missing)return 0;
 int prune=(c->cfg.components&SCAR_PRUNED)!=0;
 /* With requested P present, conditional S can never create a victim. */
 if(prune&&missing==2&&c->bytes-c->used<jc_entry_bytes(JC_SECRET))return 0;
 int gate=(c->cfg.components&SCAR_ADMISSION)!=0;
 double v[4];scar_values(c,key,now,v);
 PlacementOccupancy occupancy;int have_occupancy=0;
 if(missing&1){
  double public_score=v[current|1]-v[current]-scar_setup(c,key,1)-c->cfg.costs.state_ns[0]/32.;
  if(gate&&public_score<=0.)z->stats.prefilter_rejects++;
  else {
   JointPlan p=*out;p.mask=1;p.objective_ns=public_score;int required=-1;
   uint64_t prefix_free=c->bytes-c->used;
   int free_fit=0;
   /* Aggregate capacity is necessary, never sufficient for first-fit. */
   if(!prune||prefix_free>=jc_entry_bytes(JC_PUBLIC)){
    placement_occupancy(c,&occupancy);have_occupancy=1;
    z->stats.candidate_masks++;SCAR_TEST_PROBE();
    free_fit=try_place_occupancy(c,&p,&required,&occupancy);
   }
   if(free_fit&&isfinite(p.objective_ns))*out=p;
   else {
    z->stats.full_searches++;
    uint32_t prefix[4]={0};unsigned n=scar_prefix(c,key,prefix);z->stats.victim_proposals+=n;
    if(n){
     unsigned memo=1;double loss=0.;int found=0;
     double dp,ds,di;gains(c,&dp,&ds,&di);
     int monotone=prune&&isfinite(dp)&&isfinite(ds)&&isfinite(di)&&dp>=0.&&ds>=0.&&di>=0.&&c->cfg.costs.state_ns[0]>0.;
     memcpy(w->value[0],v,sizeof(v));w->initial[0]=(unsigned char)key;w->state[0]=(unsigned char)current;
     for(unsigned i=0;i<n;i++){
      Entry*e=entry(c,prefix[i]);unsigned slot=0;
      while(slot<memo&&w->initial[slot]!=e->key)slot++;
      if(slot==memo){assert(memo<5);scar_values(c,e->key,now,w->value[slot]);
       w->initial[slot]=(unsigned char)e->key;w->state[slot]=(unsigned char)scar_current(c,e->key);memo++;}
      unsigned before=w->state[slot],after=before&~(1u<<e->type);
      loss+=w->value[slot][after]-w->value[slot][before];w->state[slot]=(unsigned char)after;
      JointPlan test={0};test.context=key;test.clock_ns=now;test.sequence=c->seq;test.revision=c->revision;
      test.mask=1;test.evict_count=i+1;memcpy(test.evict,prefix,(i+1)*sizeof(prefix[0]));
      test.objective_ns=public_score+loss-(i+1)*c->cfg.costs.state_ns[0]/1024.;
      prefix_free+=(uint64_t)e->span*Q;
      int fits=0;
      if(!prune||prefix_free>=jc_entry_bytes(JC_PUBLIC)){
       if(!have_occupancy){placement_occupancy(c,&occupancy);have_occupancy=1;}
       required=-1;SCAR_TEST_PROBE();
       fits=try_place_occupancy(c,&test,&required,&occupancy);
      }
      if(fits&&isfinite(test.objective_ns)&&(!gate||test.objective_ns>0.)&&(!found||scar_better(c,&test,out))){*out=test;found=1;}
      if(monotone&&i+1<n){
       /* Future losses cannot increase. Strict bound keeps rounded ties. */
       double upper=public_score+loss-(i+2)*c->cfg.costs.state_ns[0]/1024.;
       if(isfinite(upper)&&((found&&upper<out->objective_ns)||(gate&&upper<=0.)))break;
      }
     }
     scar_clear_scratch(w,memo);
    }
   }
  }
 }
 uint64_t spare=c->bytes-c->used;
 if(prune&&(missing&2)){
  for(unsigned i=0;i<out->evict_count;i++)spare+=(uint64_t)entry(c,out->evict[i])->span*Q;
  if(out->mask&1){assert(spare>=jc_entry_bytes(JC_PUBLIC));spare-=jc_entry_bytes(JC_PUBLIC);}
 }
 if((missing&2)&&(!prune||spare>=jc_entry_bytes(JC_SECRET))){
  unsigned after_public=current|out->mask;
  double marginal=v[after_public|2]-v[after_public]-scar_setup(c,key,2)-c->cfg.costs.state_ns[0]/32.;
  if(gate&&marginal<=0.)z->stats.prefilter_rejects++;
  else if(isfinite(marginal)){
   if(!have_occupancy)placement_occupancy(c,&occupancy);
   JointPlan both=*out;both.mask|=2;both.objective_ns+=marginal;
   int required=-1;z->stats.candidate_masks++;SCAR_TEST_PROBE();
   if(try_place_occupancy(c,&both,&required,&occupancy))*out=both;
  }
 }
 return 0;
}
int jc_plan_with_scratch(JointCache*c,unsigned key,uint64_t now,JointPlan*out,JointScarScratch*w,size_t bytes){
 if(c&&c->cfg.policy==JC_SCAR&&(c->cfg.components&SCAR_FACTORED))
  return scar_conditional_plan(c,key,now,out,w,bytes);
 return scar_joint_plan(c,key,now,out,w,bytes);
}
int jc_retire_plan(JointCache*c,uint64_t now,JointRetirePlan*out,JointScarScratch*w,size_t bytes){
 (void)w;(void)bytes;if(!c||!out)return -1;
 memset(out,0,sizeof(*out));out->sequence=c->seq;out->revision=c->revision;out->clock_ns=now;
 return 0; /* No scoring-driven retirement. Common expiry/cleanup still run. */
}
int jc_retire_commit(JointCache*c,const JointRetirePlan*p,uint64_t now){
 (void)c;(void)p;(void)now;return -1; /* No retirement token is ever issued. */
}
