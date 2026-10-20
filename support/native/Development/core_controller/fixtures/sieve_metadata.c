/* Fake payloads only; independent list/bit-array model. No crypto or timing. */
#include <stdio.h>
#include <stdlib.h>
#include "../joint_controller.c"
static unsigned long checks,events,streams,targets;
#define T(x) do{checks++;if(!(x)){fprintf(stderr,"fixture_fail line=%d expression=%s events=%lu targets=%lu\n",__LINE__,#x,events,targets);exit(1);}}while(0)
typedef struct {int id;uint32_t off;unsigned span,ready,seen;uint64_t born;} Obj;
typedef struct {Obj objects[128];unsigned n;int hand;} Model;
static unsigned char arena[65536] __attribute__((aligned(32)));
static unsigned char saved[65536] __attribute__((aligned(32)));
static uint64_t fake_time;
static uint64_t fake_clock(void){return fake_time;}
static int position(const Model*m,int id){for(unsigned i=0;i<m->n;i++)if(m->objects[i].id==id)return (int)i;return -1;}
static void model_insert(Model*m,int id,unsigned off,unsigned span,uint64_t born){
 T(position(m,id)<0&&m->n<128);memmove(m->objects+1,m->objects,m->n*sizeof(Obj));m->objects[0]=(Obj){id,off,span,0,0,born};m->n++;
}
static void model_remove(Model*m,int id){int i=position(m,id);T(i>=0);if(m->hand==id)m->hand=i?m->objects[i-1].id:-1;memmove(m->objects+i,m->objects+i+1,(m->n-(unsigned)i-1)*sizeof(Obj));m->n--;if(!m->n)m->hand=-1;}
static int in_list(int id,const int*ids,unsigned n){for(unsigned i=0;i<n;i++)if(ids[i]==id)return 1;return 0;}
static int model_victim(Model*m,unsigned key,int type,const int*excluded_ids,unsigned n){
 if(!m->n)return -1;
 int i=m->hand<0?(int)m->n-1:position(m,m->hand);T(i>=0);
 for(unsigned steps=0;steps<2*m->n;steps++){
  Obj*o=m->objects+i;
  if(o->ready&&(unsigned)o->id/2!=key&&!in_list(o->id,excluded_ids,n)&&(type<0||(o->id%2)==type)){
   if(!o->seen){m->hand=i?m->objects[i-1].id:-1;return o->id;}o->seen=0;
  }
  i=i?i-1:(int)m->n-1;
 }
 return -1;
}
static void compare(JointCache*c,const Model*m){
 T(jc_check(c)==1);const SieveState*s=sieve_state(c);T(s->count==m->n);
 unsigned off=s->head;for(unsigned i=0;i<m->n;i++){
  T(off==m->objects[i].off);const Entry*e=entry(c,off);
  T((int)(2*e->key+e->type)==m->objects[i].id);T(e->seen==m->objects[i].seen);
  T((e->state==READY)==m->objects[i].ready);T(e->born==m->objects[i].born);
  off=e->next;
 }
 T(off==0);T((s->hand?(int)(2*entry(c,s->hand)->key+entry(c,s->hand)->type):-1)==m->hand);
 T((s->tail?s->tail:0)==(m->n?m->objects[m->n-1].off:0));
}
static JointCache*init(Model*m,JointPolicy policy,unsigned bytes){
 JointConfig cfg={.arena_bytes=bytes,.contexts=64,.history_capacity=1000,.components=31,.policy=policy,.ttl_ns=10000,.guard_ns=500,.horizon_ns=10000,.public_seed=1,.costs={{30000,26000,20000,15000},-100,50,200,100}};
 memset(m,0,sizeof(*m));m->hand=-1;JointCache*c=jc_init(arena,bytes,&cfg);T(c!=NULL);T(jc_check(c));
 JointStats st=jc_stats(c);T(st.policy_bytes==32&&st.history_bytes==0);T(jc_header_bytes()==352);T(jc_entry_bytes(0)==3584&&jc_entry_bytes(1)==1216);return c;
}
/* Separate one-bit first-fit reference, including complete byte occupancy and
 * protected PENDING objects. No production placement helper is called. */
static int model_fit(JointCache*c,const Model*m,unsigned mask,const int*ids,unsigned n,unsigned places[2],int*need){
 unsigned char occupied[2048]={0};uint64_t by_type[2]={0};unsigned end=(unsigned)c->bytes/32;
 for(unsigned i=0;i<c->prefix_units;i++)occupied[i]=1;
 for(unsigned i=0;i<m->n;i++)if(!in_list(m->objects[i].id,ids,n)){
  const Obj*o=m->objects+i;by_type[o->id%2]+=(uint64_t)o->span*32;
  for(unsigned j=o->off;j<o->off+o->span;j++)occupied[j]=1;
 }
 for(unsigned t=0;t<2;t++)if(mask&(1u<<t))by_type[t]+=t?1216:3584;
 uint64_t quota=c->bytes-(uint64_t)c->prefix_units*32;
 for(unsigned t=0;t<2;t++)if(by_type[t]>(t&&c->cfg.policy==JC_PUBLIC_SIEVE?0:quota)){*need=(int)t;return 0;}
 for(unsigned t=0;t<2;t++){
  places[t]=0;if(!(mask&(1u<<t)))continue;unsigned span=t?38:112,run=0;
  for(unsigned i=c->prefix_units;i<end;i++){
   run=occupied[i]?0:run+1;if(run==span){places[t]=i+1-span;break;}
  }
  if(!places[t]){*need=-1;return 0;}
  for(unsigned i=places[t];i<places[t]+span;i++)occupied[i]=1;
 }
 return 1;
}
static JointPlan expected_plan(JointCache*c,Model*m,unsigned key){
 unsigned missing=0;for(unsigned t=0;t<2;t++)if(position(m,2*(int)key+(int)t)<0)missing|=1u<<t;
 if(c->cfg.policy==JC_PUBLIC_SIEVE)missing&=1;
 int victims[128];unsigned nv=0,places[2]={0};int placed=1,need=-1;
 if(missing){placed=model_fit(c,m,missing,victims,nv,places,&need);while(!placed&&nv<128){int id=model_victim(m,key,need,victims,nv);if(id<0)break;victims[nv++]=id;placed=model_fit(c,m,missing,victims,nv,places,&need);}}
 JointPlan result={0};if(placed){result.mask=missing;result.evict_count=nv;for(unsigned i=0;i<nv;i++)result.evict[i]=m->objects[position(m,victims[i])].off;result.place[0]=places[0];result.place[1]=places[1];}return result;
}
static void request(JointCache*c,Model*m,unsigned key,uint64_t now,int publish){
 jc_observe(c,key,now,now);for(unsigned i=0;i<m->n;i++)if((unsigned)m->objects[i].id/2==key&&m->objects[i].ready)m->objects[i].seen=1;
 JointPlan expected=expected_plan(c,m,key);
 unsigned missing=expected.mask,nv=expected.evict_count,places[2]={expected.place[0],expected.place[1]};int victims[128];
 for(unsigned i=0;i<nv;i++){const Entry*e=entry(c,expected.evict[i]);victims[i]=(int)(2*e->key+e->type);}
 int placed=1;
 JointPlan p;T(jc_plan(c,key,now,&p)==0);compare(c,m);
 T(p.mask==(placed?missing:0));T(p.evict_count==(placed?nv:0));
 if(placed&&missing){for(unsigned i=0;i<nv;i++)T(p.evict[i]==m->objects[position(m,victims[i])].off);T(p.place[0]==places[0]&&p.place[1]==places[1]);}
 T(jc_commit(c,&p,now)==0);
 if(placed&&missing){
  for(unsigned i=0;i<nv;i++)model_remove(m,victims[i]);
  for(unsigned t=0;t<2;t++)if(missing&(1u<<t)){
   model_insert(m,(int)(2*key+t),places[t],t?38:112,now);
   void*payload=jc_pending(c,key,t);T(payload);memset(payload,0xa5,t?1152:3520);
   if(publish){T(jc_publish(c,key,t)==0);m->objects[position(m,(int)(2*key+t))].ready=1;}
  }
 }
 compare(c,m);events++;
}
static void expire(JointCache*c,Model*m,uint64_t now){
 jc_expire(c,now);for(unsigned k=0;k<64;k++){int i=position(m,(int)(2*k+1));if(i>=0&&m->objects[i].ready&&now>=m->objects[i].born&&now-m->objects[i].born>=9500)model_remove(m,(int)(2*k+1));}compare(c,m);
}
static uint64_t rng=0x1e2d3c4b5a697887ULL;
static unsigned draw(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng>>16);}
static void random_streams(void){
 for(unsigned policy=JC_SIEVE;policy<=JC_PUBLIC_SIEVE;policy++)for(unsigned budget=32768;budget<=65536;budget+=32768)for(unsigned stream=0;stream<16;stream++){
  Model m;JointCache*c=init(&m,(JointPolicy)policy,budget);uint64_t now=1;
  for(unsigned j=0;j<600;j++){
   now+=draw()%61;
   if(j%17==0)expire(c,&m,now);
   if(j%53==0){unsigned key=draw()%64;T(jc_rotate(c,key,j+2,now)==0);for(unsigned t=0;t<2;t++)if(position(&m,(int)(2*key+t))>=0)model_remove(&m,(int)(2*key+t));compare(c,&m);}
   if(j%64==0){JointMonitorBarrierResult b=jc_pre_monitor_barrier(c,now);T(b.success);unsigned n=0;for(unsigned k=0;k<64;k++)if(position(&m,(int)(2*k+1))>=0){model_remove(&m,(int)(2*k+1));n++;}T(b.erased==n);compare(c,&m);}
   request(c,&m,draw()%64,now,1);
  }
  jc_clear_all(c,now);m.n=0;m.hand=-1;compare(c,&m);streams++;
 }
}
static void targeted(void){
 Model m;JointCache*c=init(&m,JC_SIEVE,32768);
 /* Mixed PENDING/READY protection, reference hand wrap and visited clearing. */
 request(c,&m,0,1,0);request(c,&m,1,2,1);request(c,&m,2,3,1);request(c,&m,3,4,1);targets++;
 for(unsigned i=0;i<m.n;i++)if(m.objects[i].ready){m.objects[i].seen=1;entry(c,m.objects[i].off)->seen=1;}
 JointPlan p={.context=3};int ids[128];unsigned n=0;
 for(unsigned j=0;j<2;j++){
  int expected=model_victim(&m,3,-1,ids,n);Entry*e=sieve_victim(c,&p,-1);T(expected>=0&&e);T((int)(e->key*2+e->type)==expected);ids[n++]=expected;p.evict[p.evict_count++]=offset(c,e);compare(c,&m);
 }targets++;
 /* All remaining legal entries excluded: bounded failure, no pending/current victim. */
 for(unsigned i=0;i<m.n;i++)if(m.objects[i].ready&&(unsigned)m.objects[i].id/2!=3&&!in_list(m.objects[i].id,ids,n)){ids[n++]=m.objects[i].id;p.evict[p.evict_count++]=m.objects[i].off;}
 T(model_victim(&m,3,-1,ids,n)<0);T(sieve_victim(c,&p,-1)==NULL);compare(c,&m);targets++;
 /* PENDING rejects administrative barrier before any erase or revision change. */
 memcpy(saved,arena,32768);JointMonitorBarrierResult b=jc_pre_monitor_barrier(c,10);T(!b.success&&!b.erased);T(!memcmp(saved,arena,32768));targets++;
 /* Publishing retains bit zero; mandatory expiry repairs an exact hand target. */
 for(unsigned t=0;t<2;t++){T(jc_publish(c,0,t)==0);m.objects[position(&m,(int)t)].ready=1;}
 unsigned so=indexes(c)[1].offset[1];T(so);sieve_state(c)->hand=so;m.hand=3;expire(c,&m,9502);targets++;
 /* Rotation repairs middle/tail/head and rejects stale pre-rotation commit. */
 (void)expected_plan(c,&m,20);JointPlan stale;T(jc_plan(c,20,9503,&stale)==0);T(jc_rotate(c,3,2,9503)==0);for(unsigned t=0;t<2;t++)if(position(&m,6+(int)t)>=0)model_remove(&m,6+(int)t);
 memcpy(saved,arena,32768);T(jc_commit(c,&stale,9503)==-1);T(!memcmp(saved,arena,32768));compare(c,&m);targets++;
 /* Forged duplicate victim and placement leave arena byte-identical. */
 for(unsigned k=4;k<8;k++)request(c,&m,k,9504+k,1);
 (void)expected_plan(c,&m,30);T(jc_plan(c,30,9600,&p)==0);compare(c,&m);T(p.evict_count>0);JointPlan bad=p;bad.evict[1]=bad.evict[0];bad.evict_count=2;
 memcpy(saved,arena,32768);T(jc_commit(c,&bad,9600)==-1);T(!memcmp(saved,arena,32768));bad=p;bad.place[0]++;
 T(jc_commit(c,&bad,9600)==-1);T(!memcmp(saved,arena,32768));targets++;
 /* Malformed queue cycles/hand/visited rejected without mutating cache. */
 SieveState before=*sieve_state(c);sieve_state(c)->hand=(uint32_t)(c->bytes/Q+1);T(!jc_check(c));*sieve_state(c)=before;
 Entry*head=entry(c,before.head);unsigned old=head->next;head->next=before.head;T(!jc_check(c));head->next=old;head->seen=2;T(!jc_check(c));head->seen=m.objects[0].seen;T(jc_check(c));targets++;
 jc_clear_all(c,9600);m.n=0;m.hand=-1;compare(c,&m);
 /* Original post-readback clock and late counter retained. */
 c=init(&m,JC_SIEVE,32768);c->cfg.clock_ns=fake_clock;request(c,&m,0,1,1);fake_time=10002;
 jc_expire(c,9501);T(jc_stats(c).late_clear_count==1&&jc_stats(c).max_lateness_ns==1);targets++;
 jc_clear_all(c,10002);
 /* Public-only repeated requests never retain S; ready/empty deadline drain. */
 c=init(&m,JC_PUBLIC_SIEVE,65536);c->cfg.clock_ns=fake_clock;fake_time=5;
 for(unsigned k=0;k<20;k++)request(c,&m,k,k+1,1);
 T(jc_stats(c).secret_bytes==0);JointDeadlineDrainResult d=jc_deadline_drain(c);T(d.status==JC_DRAIN_OK&&d.next_secret_deadline_ns==UINT64_MAX&&d.passes==1);compare(c,&m);targets++;
 jc_clear_all(c,100);
 /* Fill capacity with PENDING objects: replacement cannot free them. A failed
  * admission returns a no-change plan while preserving queue/index validity. */
 c=init(&m,JC_SIEVE,32768);for(unsigned k=0;k<8;k++)request(c,&m,k,k+1,0);
 T(m.n==2*((32768-(uint64_t)c->prefix_units*32)/(3584+1216)));T(c->bytes-c->used<3584+1216);unsigned entries_before=m.n;request(c,&m,40,10,1);T(m.n==entries_before);targets++;
 jc_clear_all(c,20);m.n=0;m.hand=-1;compare(c,&m);
 /* Queue completion covers explicit head/tail deletion and singleton cleanup. */
 c=init(&m,JC_PUBLIC_SIEVE,32768);request(c,&m,0,1,1);request(c,&m,1,2,1);request(c,&m,2,3,1);
 T(jc_rotate(c,0,2,4)==0);model_remove(&m,0);compare(c,&m);
 T(jc_rotate(c,2,2,4)==0);model_remove(&m,4);compare(c,&m);
 sieve_state(c)->hand=indexes(c)[1].offset[0];m.hand=2;
 T(jc_rotate(c,1,2,4)==0);model_remove(&m,2);compare(c,&m);targets++;
 /* Independent type-restricted walk leaves the other tier's visited bits and
  * protected key alone, including when all matching entries are visited. */
 c=init(&m,JC_SIEVE,65536);for(unsigned k=0;k<3;k++)request(c,&m,k,k+1,1);
 for(unsigned i=0;i<m.n;i++){m.objects[i].seen=1;entry(c,m.objects[i].off)->seen=1;}
 p=(JointPlan){.context=2};n=0;
 for(int type=0;type<2;type++){
  int expected=model_victim(&m,2,type,ids,n);Entry*e=sieve_victim(c,&p,type);
  T(expected>=0&&e&&(int)(2*e->key+e->type)==expected);
  ids[n++]=expected;p.evict[p.evict_count++]=offset(c,e);compare(c,&m);
 }targets++;jc_clear_all(c,10);
}
int main(void){random_streams();targeted();printf("sieve_metadata_pass=1 streams=%lu request_events=%lu targeted=%lu checks=%lu crypto_linked=0 timing_endpoints=0\n",streams,events,targets,checks);return 0;}
