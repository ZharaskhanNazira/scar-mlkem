#define _GNU_SOURCE
#include "joint_controller.h"
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#ifdef NDEBUG
#error "Post-clear readback requires assertions enabled"
#endif

#define Q 32u
#define MAGIC UINT64_C(0x4a4f494e54415245)
#define ROUND(n) (((n)+31u)&~31u)
#define MAX_BITMAP 256u
#define PUBLIC_BYTES 3520u
#define SECRET_BYTES 1152u
#define READY 1u
#define PENDING 2u

typedef struct {uint64_t generation;uint32_t offset[2];} Index;
typedef struct {uint64_t last;double mean;uint32_t count,seen;} History;
typedef struct {uint64_t time;uint32_t key,pad;} HistoryEvent;
/* Arena-charged public state; no secret or cryptographic output is a feature. */
typedef struct {
 JointScarSettings settings; History global;
 uint32_t histories_at,cooldowns_at,configured,reserved;
 JointScarStats stats; JointRetirePlan retirement;
} CausalState;
typedef struct {
 uint64_t generation,born,last,order; double credit;
 uint32_t key,span,next,prev; uint16_t frequency;
 uint8_t type,state,queue,seen;uint16_t auxiliary;
} Entry;
typedef struct {uint32_t key,type;uint64_t order;} Ghost;
typedef struct {uint32_t key,type,expert,valid;uint64_t frequency,step;} LcGhost;
typedef struct {uint8_t count[4][256],door[128];uint64_t samples;} Tiny;
/* SIEVE links/visited use the existing common 64-byte Entry header. The
 * policy-only queue anchor occupies one rounded 32-byte arena block. */
typedef struct {uint32_t head,tail,hand,count;} SieveState;
_Static_assert(sizeof(SieveState)==16,"SIEVE queue anchor, rounded to 32 in arena");
typedef struct {uint64_t used[2],quota[2];} PlacementOccupancy;
_Static_assert(sizeof(PlacementOccupancy)==32,"transient placement occupancy bytes");
struct JointCache {
 uint64_t magic,bytes,used,peak,seq,revision,evictions,zeroizations,max_life,late,max_lateness;
 JointConfig cfg;
 uint32_t index_at,bitmap_at,bitmap_bytes,prefix_units,history_at;
 uint32_t ghost_at,ghost_count,ghost_capacity,tiny_at,lc_at,lc_capacity;
 uint32_t lr_at,lr_count,lr_head,lr_weights_at;
 uint64_t queue_clock,random_state,lc_restore[2]; double lc_weights[2][2],landlord_clock;
};
_Static_assert(sizeof(Index)==16,"index bytes");
_Static_assert(sizeof(History)==24,"history bytes");
_Static_assert(sizeof(HistoryEvent)==16,"feature history bytes");
_Static_assert(sizeof(Entry)==64,"common entry header bytes");
_Static_assert(sizeof(JointCosts)==64,"four-state and transition costs");
static const char *names[]={"none","public_s3","secret_s3","static25","static50","static75","lecar","landlord","tiny","logistic","scar","sieve","public_sieve"};
const char *jc_policy_name(JointPolicy p){return p>=JC_NONE&&p<=JC_PUBLIC_SIEVE?names[p]:"invalid";}
int jc_policy_parse(const char*s,JointPolicy*p){for(unsigned i=0;i<=JC_PUBLIC_SIEVE;i++)if(!strcmp(s,names[i])){*p=(JointPolicy)i;return 0;}return -1;}
static unsigned char *base(const JointCache*c){return (unsigned char *)(uintptr_t)c;}
static Index *indexes(const JointCache*c){return (Index*)(base(c)+c->index_at);}
static unsigned char *bitmap(const JointCache*c){return base(c)+c->bitmap_at;}
static Entry *entry(const JointCache*c,uint32_t off){return off?(Entry*)(base(c)+(size_t)off*Q):NULL;}
static uint32_t offset(const JointCache*c,const Entry*e){return (uint32_t)(((const unsigned char*)e-base(c))/Q);}
static unsigned units(unsigned type){return (unsigned)((sizeof(Entry)+(type==JC_PUBLIC?PUBLIC_BYTES:SECRET_BYTES))/Q);}
size_t jc_header_bytes(void){return ROUND(sizeof(JointCache));}
size_t jc_entry_bytes(unsigned type){return type<=JC_SECRET?(size_t)units(type)*Q:0;}
/* Declared bounded objects, not a measured compiler stack-frame bound. The
 * common mapped Work payload is unchanged; this extra object is on the stack. */
size_t jc_plan_scratch_bytes(void){return 2*sizeof(JointPlan)+MAX_BITMAP+2*JC_MAX_OBJECTS*sizeof(uint32_t)+sizeof(PlacementOccupancy);}
static int bit(const unsigned char*b,unsigned i){return (b[i/8]>>(i%8))&1;}
/* Public allocation bits only. Partial endpoint bytes preserve every other
 * bit; complete bytes need neither alignment-sensitive loads nor wide shifts. */
static void bits(unsigned char*b,unsigned off,unsigned n,int value){
 if(n&&(off%8)){
  unsigned take=8-off%8;if(take>n)take=n;
  unsigned char mask=(unsigned char)(((1u<<take)-1u)<<(off%8));
  if(value)b[off/8]|=mask;else b[off/8]&=(unsigned char)~mask;
  off+=take;n-=take;
 }
 unsigned whole=n/8;
 if(whole)memset(b+off/8,value?255:0,whole);
 off+=whole*8;n-=whole*8;
 if(n){unsigned char mask=(unsigned char)((1u<<n)-1u);if(value)b[off/8]|=mask;else b[off/8]&=(unsigned char)~mask;}
}
/* Used only on a local shadow. As in the original one-bit loop, failure may
 * leave earlier bits marked; the caller discards that shadow immediately. */
static int mark_unoccupied(unsigned char*b,unsigned off,unsigned n){
 while(n){
  unsigned take=8-off%8;if(take>n)take=n;
  unsigned char mask=(unsigned char)(((1u<<take)-1u)<<(off%8));
  if(b[off/8]&mask)return 0;
  b[off/8]|=mask;off+=take;n-=take;
 }
 return 1;
}
static uint32_t fit(unsigned char*b,unsigned start,unsigned end,unsigned n){
 unsigned run=0,i=start;
 /* Production spans are positive; preserve even the old zero-span result
  * for complete differential coverage of this private helper. */
 if(!n){for(;i<end;i++)if(bit(b,i))return i+1;return 0;}
 while(i<end){
  if(!(i%8)&&end-i>=8){
   unsigned char byte=b[i/8];
   if(!byte){if(n-run<=8)return i-run;run+=8;i+=8;continue;}
   if(byte==255){run=0;i+=8;continue;}
  }
  run=bit(b,i)?0:run+1;
  if(run==n)return i+1-n;
  i++;
 }
 return 0;
}
static uint64_t clock_end(JointCache*c,uint64_t logical){return c->cfg.clock_ns?c->cfg.clock_ns():logical;}
static int is_s3(JointPolicy p){return p>=JC_PUBLIC_S3&&p<=JC_STATIC75;}
static int is_sieve(JointPolicy p){return p==JC_SIEVE||p==JC_PUBLIC_SIEVE;}
static int public_only(JointPolicy p){return p==JC_PUBLIC_S3||p==JC_PUBLIC_SIEVE;}
static int is_scored(JointPolicy p){return p==JC_LOGISTIC;}
static uint32_t hash32(uint32_t x){x^=x>>16;x*=0x7feb352dU;x^=x>>15;x*=0x846ca68bU;return x^(x>>16);}
static unsigned char *reserve(JointCache*c,size_t*n,size_t bytes,uint32_t*out){*n=ROUND(*n);if(*n+ROUND(bytes)>c->bytes)return NULL;*out=(uint32_t)*n;unsigned char*p=base(c)+*n;*n+=ROUND(bytes);return p;}
JointCache *jc_init(void*storage,size_t bytes,const JointConfig*cfg){
 if(!storage||!cfg||((uintptr_t)storage%Q)||bytes!=cfg->arena_bytes||bytes<32768||bytes>65536||bytes%Q||cfg->contexts==0||cfg->contexts>64||cfg->policy<JC_NONE||cfg->policy>JC_PUBLIC_SIEVE||cfg->components>JC_ALL_COMPONENTS||cfg->ttl_ns<=cfg->guard_ns||!cfg->horizon_ns)return NULL;
 for(unsigned i=0;i<4;i++)if(!isfinite(cfg->costs.state_ns[i])||cfg->costs.state_ns[i]<=0)return NULL;
 if(!isfinite(cfg->costs.add_public_ns)||!isfinite(cfg->costs.add_secret_ns)||!isfinite(cfg->costs.erase_public_ns)||!isfinite(cfg->costs.erase_secret_ns)||cfg->costs.add_secret_ns<0||cfg->costs.erase_public_ns<0||cfg->costs.erase_secret_ns<0)return NULL;
 if(cfg->policy==JC_LOGISTIC&&(cfg->history_capacity==0||cfg->history_capacity>1000))return NULL;
 memset(storage,0,bytes);JointCache*c=storage;c->magic=MAGIC;c->revision=1;c->bytes=bytes;c->cfg=*cfg;c->random_state=cfg->public_seed?cfg->public_seed:1;
 for(unsigned t=0;t<2;t++)c->lc_weights[t][0]=c->lc_weights[t][1]=.5;
 size_t at=ROUND(sizeof(*c));
 if(!reserve(c,&at,cfg->contexts*sizeof(Index),&c->index_at))return NULL;
 c->bitmap_bytes=(uint32_t)((bytes/Q+7)/8);
 if(!reserve(c,&at,c->bitmap_bytes,&c->bitmap_at))return NULL;
 if(cfg->policy==JC_SCAR){
  if(cfg->components>SCAR_ALL_COMPONENTS||!reserve(c,&at,sizeof(CausalState),&c->history_at))return NULL;
  CausalState*z=(CausalState*)(base(c)+c->history_at);
  if((cfg->components&SCAR_HISTORY)&&!reserve(c,&at,cfg->contexts*sizeof(History),&z->histories_at))return NULL;
  if((cfg->components&SCAR_SPARSE)&&!reserve(c,&at,cfg->contexts,&z->cooldowns_at))return NULL;
 }
 if(is_sieve(cfg->policy)&&!reserve(c,&at,sizeof(SieveState),&c->history_at))return NULL;
 if(is_s3(cfg->policy)){
  /* At most this many entries can fit even before charging their ghosts.
   * A context-count-sized ghost array would needlessly reduce S3 capacity. */
  c->ghost_capacity=(uint32_t)((bytes-at)/jc_entry_bytes(JC_SECRET));
  if(!reserve(c,&at,c->ghost_capacity*sizeof(Ghost),&c->ghost_at))return NULL;
 }
 if(cfg->policy==JC_TINY&&!reserve(c,&at,sizeof(Tiny),&c->tiny_at))return NULL;
 if(cfg->policy==JC_LECAR){
  c->lc_capacity=(uint32_t)(2*(bytes-at)/jc_entry_bytes(JC_SECRET));
  if(!reserve(c,&at,c->lc_capacity*sizeof(LcGhost),&c->lc_at))return NULL;
 }
 if(cfg->policy==JC_LOGISTIC){
  if(!reserve(c,&at,cfg->history_capacity*sizeof(HistoryEvent),&c->lr_at)||!reserve(c,&at,12*sizeof(double),&c->lr_weights_at))return NULL;
  /* Exact frozen training-only coefficients from canonical model_lr.h. */
  const double w[]={3.117341769902426,-.21935368623530802,.30043715486677114,-.010543090423235863,-.28120576617540205,-.020772842772261973,-.01882146031186761,-.99150447828849142,-.30802308174001319,.20645911797598696,.39120840416686797,-1.8530707082968119};
  memcpy(base(c)+c->lr_weights_at,w,sizeof(w));
 }
 c->prefix_units=(uint32_t)(at/Q);c->used=c->peak=at;
 if(at+jc_entry_bytes(JC_PUBLIC)+jc_entry_bytes(JC_SECRET)>bytes)return NULL;
 bits(bitmap(c),0,c->prefix_units,1);
 for(unsigned k=0;k<cfg->contexts;k++)indexes(c)[k].generation=1;
 return c;
}
static double random_unit(JointCache*c){uint64_t x=c->random_state;x^=x>>12;x^=x<<25;x^=x>>27;c->random_state=x;return (double)((x*2685821657736338717ULL)>>11)/9007199254740992.;}
static int excluded(uint32_t off,const JointPlan*p){for(unsigned i=0;i<p->evict_count;i++)if(p->evict[i]==off)return 1;return 0;}
static SieveState *sieve_state(const JointCache*c){return (SieveState*)(base(c)+c->history_at);}
/* Head is newest; prev points toward newer objects, next toward older. P then
 * S construction means S precedes P at the head. PENDING entries are linked
 * immediately, but neither hits nor replacement may promote/evict them. */
static void sieve_insert(JointCache*c,Entry*e){
 SieveState*s=sieve_state(c);uint32_t off=offset(c,e);
 e->seen=0;e->prev=0;e->next=s->head;
 if(s->head)entry(c,s->head)->prev=off;else s->tail=off;
 s->head=off;s->count++;
}
/* All actual removals (TTL, rotation, barrier, abort/final, replacement) use
 * this one unlink. NULL hand retains its reference meaning: restart at tail. */
static void sieve_unlink(JointCache*c,Entry*e){
 SieveState*s=sieve_state(c);uint32_t off=offset(c,e);
 if(s->hand==off)s->hand=e->prev;
 if(e->prev)entry(c,e->prev)->next=e->next;else s->head=e->next;
 if(e->next)entry(c,e->next)->prev=e->prev;else s->tail=e->prev;
 assert(s->count);s->count--;
 if(!s->count){assert(!s->head&&!s->tail);s->hand=0;}
}
/* Exact queue membership is checked in addition to the unchanged common
 * index/bitmap/span checks. No unbounded traversal or unvalidated link read. */
static int sieve_check(const JointCache*c){
 if(!c->history_at||c->history_at%Q||c->history_at+ROUND(sizeof(SieveState))>(uint64_t)c->prefix_units*Q)return 0;
 const SieveState*s=sieve_state(c);unsigned indexed=0;
 for(unsigned k=0;k<c->cfg.contexts;k++)for(unsigned t=0;t<2;t++)indexed+=indexes(c)[k].offset[t]!=0;
 if(s->count!=indexed||s->count>2*c->cfg.contexts)return 0;
 if(!s->count)return !s->head&&!s->tail&&!s->hand;
 uint32_t off=s->head,previous=0;unsigned count=0,hand_seen=!s->hand;
 while(off){
  if(++count>s->count||off<c->prefix_units||(uint64_t)off+sizeof(Entry)/Q>c->bytes/Q)return 0;
  const Entry*e=entry(c,off);
  if(e->key>=c->cfg.contexts||e->type>1||indexes(c)[e->key].offset[e->type]!=off||e->prev!=previous||e->seen>1)return 0;
  hand_seen|=off==s->hand;previous=off;off=e->next;
 }
 return count==s->count&&previous==s->tail&&hand_seen;
}
/* Local lifecycle adaptation: skip pinned current context, PENDING and victims
 * already proposed by this transaction. Those excluded nodes remain linked
 * until independent commit validation succeeds. Skipping them gives the same
 * eligible walk as virtual removal, without ever freeing borrowed storage.
 * Each eligible visited bit can be cleared once, so two complete traversals
 * suffice to find an eligible unvisited entry or prove none is available.
 * Like the existing queue baselines, attempted planning retains bit/hand work
 * even if allocation later fails. This policy side effect consumes revision. */
static Entry *sieve_victim(JointCache*c,const JointPlan*p,int type){
 SieveState*s=sieve_state(c);uint32_t off=s->hand?s->hand:s->tail;
 for(unsigned steps=0;off&&steps<2*s->count;steps++){
  Entry*e=entry(c,off);uint32_t next=e->prev?e->prev:s->tail;
  if(e->state==READY&&e->key!=p->context&&!excluded(off,p)&&(type<0||(unsigned)type==e->type)){
   if(!e->seen){s->hand=e->prev;return e;}
   e->seen=0;
  }
  off=next;
 }
 return NULL;
}
static int ghost_find(JointCache*c,unsigned key,unsigned type){Ghost*g=(Ghost*)(base(c)+c->ghost_at);for(unsigned i=0;i<c->ghost_count;i++)if(g[i].key==key&&g[i].type==type)return (int)i;return -1;}
static void ghost_add(JointCache*c,unsigned key,unsigned type){Ghost*g=(Ghost*)(base(c)+c->ghost_at);int old=ghost_find(c,key,type);if(old>=0){memmove(g+old,g+old+1,(c->ghost_count-(unsigned)old-1)*sizeof(*g));c->ghost_count--;}
 if(c->ghost_count==c->ghost_capacity){memmove(g,g+1,(c->ghost_count-1)*sizeof(*g));c->ghost_count--;}
 g[c->ghost_count++]=(Ghost){key,type,++c->queue_clock};
}
/* Same all-zero predicate as the original per-byte assertions. Read exactly
 * bytes unsigned characters, without alignment assumptions or early success.
 * Actual optimized post-clear loads must be checked before deployment; this
 * source expression alone is not proof of physical erasure or constant time. */
static int payload_is_zero(const unsigned char*p,size_t bytes){
 unsigned char combined=0;
 for(size_t j=0;j<bytes;j++)combined|=p[j];
 return combined==0;
}
static void remove_entry(JointCache*c,Entry*e,uint64_t now,int evict){
 unsigned type=e->type,key=e->key;uint32_t off=offset(c,e),span=e->span;
 if(evict&&is_s3(c->cfg.policy)&&e->queue==0)ghost_add(c,key,type);
 if(evict&&c->cfg.policy==JC_LECAR&&e->auxiliary<2){
  LcGhost*g=(LcGhost*)(base(c)+c->lc_at);unsigned target=0;
  for(unsigned i=0;i<c->lc_capacity;i++)if(!g[i].valid){target=i;break;}else if(g[i].step<g[target].step)target=i;
  g[target]=(LcGhost){key,type,e->auxiliary,1,e->frequency,c->seq};
 }
 if(evict&&c->cfg.policy==JC_LANDLORD)c->landlord_clock=fmax(c->landlord_clock,e->credit);
 explicit_bzero(e+1,(size_t)span*Q-sizeof(*e));
 assert(payload_is_zero((const unsigned char*)(e+1),(size_t)span*Q-sizeof(*e)));
 if(type==JC_SECRET&&e->state==READY){uint64_t end=clock_end(c,now);assert(end>=e->born);uint64_t life=end-e->born;c->zeroizations++;if(life>c->max_life)c->max_life=life;if(life>c->cfg.ttl_ns){c->late++;if(life-c->cfg.ttl_ns>c->max_lateness)c->max_lateness=life-c->cfg.ttl_ns;}}
 if(is_sieve(c->cfg.policy))sieve_unlink(c,e);
 indexes(c)[key].offset[type]=0;bits(bitmap(c),off,span,0);c->used-=(uint64_t)span*Q;explicit_bzero(e,sizeof(*e));if(evict)c->evictions++;c->revision++;
}
void jc_expire(JointCache*c,uint64_t now){if(c->cfg.policy==JC_NONE||public_only(c->cfg.policy)||c->used==(uint64_t)c->prefix_units*Q)return;for(unsigned k=0;k<c->cfg.contexts;k++){Entry*e=entry(c,indexes(c)[k].offset[JC_SECRET]);if(e&&e->state==READY&&now>=e->born&&now-e->born>=c->cfg.ttl_ns-c->cfg.guard_ns)remove_entry(c,e,now,0);}}
uint64_t jc_next_deadline(const JointCache*c,uint64_t end){if(c->cfg.policy==JC_NONE||public_only(c->cfg.policy)||c->used==(uint64_t)c->prefix_units*Q)return end;for(unsigned k=0;k<c->cfg.contexts;k++){const Entry*e=entry(c,indexes(c)[k].offset[JC_SECRET]);if(e&&e->state==READY){uint64_t d=e->born+c->cfg.ttl_ns-c->cfg.guard_ns;if(d<end)end=d;}}return end;}
/* Only the adjacent idle expire/next-deadline pair is fused. Use the same
 * supplied time and ascending context erasure order as the separate calls.
 * Do not cache this result across mutations or replace borrow-time expiry. */
uint64_t jc_expire_and_next(JointCache*c,uint64_t now,uint64_t end){
 if(c->cfg.policy==JC_NONE||public_only(c->cfg.policy)||c->used==(uint64_t)c->prefix_units*Q)return end;
 for(unsigned k=0;k<c->cfg.contexts;k++){
  Entry*e=entry(c,indexes(c)[k].offset[JC_SECRET]);
  if(!e||e->state!=READY)continue;
  if(now>=e->born&&now-e->born>=c->cfg.ttl_ns-c->cfg.guard_ns)remove_entry(c,e,now,0);
  else {uint64_t d=e->born+c->cfg.ttl_ns-c->cfg.guard_ns;if(d<end)end=d;}
 }
 return end;
}
/* No retained scheduler/index is added. UINT64_MAX means no READY-secret
 * deadline; request due times must not be supplied as that sentinel. Existing
 * expire_and_next preserves its guarded predicate and ascending erasure order. */
JointDeadlineDrainResult jc_deadline_drain(JointCache*c){
 JointDeadlineDrainResult r={UINT64_MAX,0,0,0,JC_DRAIN_NO_CLOCK};
 if(!c||!c->cfg.clock_ns)return r;
 /* The structural cap avoids a second counting traversal. Valid arenas have
  * at most one secret per context. The proof is stronger: at most initial
  * READY-secret count + 1 passes, without computing that count at runtime. */
 r.pass_limit=c->cfg.contexts+1;
 uint64_t previous_end=0;
 for(unsigned pass=0;pass<r.pass_limit;pass++){
  uint64_t begin=c->cfg.clock_ns();
  if(pass&&begin<previous_end){r.status=JC_DRAIN_CLOCK_REVERSED;return r;}
  r.next_secret_deadline_ns=jc_expire_and_next(c,begin,UINT64_MAX);
  r.passes++;r.observed_end_ns=c->cfg.clock_ns();
  if(r.observed_end_ns<begin){r.status=JC_DRAIN_CLOCK_REVERSED;return r;}
  if(r.next_secret_deadline_ns==UINT64_MAX||
     r.next_secret_deadline_ns>r.observed_end_ns){r.status=JC_DRAIN_OK;return r;}
  previous_end=r.observed_end_ns;
 }
 /* Under valid arena/nonmutating monotonic-clock preconditions, every repeat
  * removes at least one previously remaining READY S; this is unreachable. */
 r.status=JC_DRAIN_PASS_LIMIT;return r;
}
void *jc_lookup(JointCache*c,unsigned key,unsigned type,uint64_t now){if(key>=c->cfg.contexts||type>1)return NULL;Entry*e=entry(c,indexes(c)[key].offset[type]);if(!e||e->state!=READY||e->generation!=indexes(c)[key].generation)return NULL;if(type==JC_SECRET&&now>=e->born&&now-e->born>=c->cfg.ttl_ns-c->cfg.guard_ns)return NULL;return e+1;}
static void tiny_observe(JointCache*c,unsigned key){
 Tiny*t=(Tiny*)(base(c)+c->tiny_at);static const uint32_t salt[]={17,101,4099,65537};unsigned h[4],seen=1;
 for(unsigned r=0;r<4;r++){h[r]=hash32(key^salt[r])&255u;unsigned d=r*256+h[r];seen&=(t->door[d/8]>>(d%8))&1u;t->door[d/8]|=(unsigned char)(1u<<(d%8));}
 if(seen){unsigned low=15;for(unsigned r=0;r<4;r++)if(t->count[r][h[r]]<low)low=t->count[r][h[r]];if(low<15)for(unsigned r=0;r<4;r++)if(t->count[r][h[r]]==low)t->count[r][h[r]]++;}
 if(++t->samples>=640){for(unsigned r=0;r<4;r++)for(unsigned j=0;j<256;j++)t->count[r][j]>>=1;memset(t->door,0,sizeof(t->door));t->samples/=2;}
}
static double tiny_frequency(JointCache*c,unsigned key){Tiny*t=(Tiny*)(base(c)+c->tiny_at);static const uint32_t salt[]={17,101,4099,65537};unsigned low=15,seen=1;for(unsigned r=0;r<4;r++){unsigned h=hash32(key^salt[r])&255u,d=r*256+h;if(t->count[r][h]<low)low=t->count[r][h];seen&=(t->door[d/8]>>(d%8))&1u;}return low+seen;}
void jc_observe(JointCache*c,unsigned key,uint64_t now,uint64_t scheduled){
 assert(key<c->cfg.contexts);c->seq++;c->revision++;
 if(c->cfg.policy==JC_NONE)return;
 c->lc_restore[0]=c->lc_restore[1]=1;
 if(c->cfg.policy==JC_SCAR){
  CausalState*z=(CausalState*)(base(c)+c->history_at);assert(z->configured);
  z->stats.observations++;
  if(z->histories_at){
   History*local=(History*)(base(c)+z->histories_at)+key;
   History*hs[2]={local,&z->global};
   for(unsigned j=0;j<2;j++){History*h=hs[j];if(h->seen){assert(now>=h->last);if(now>h->last){double gap=(double)(now-h->last);if(h->count<UINT32_MAX)h->count++;h->mean=h->count==1?gap:h->mean+.5*(gap-h->mean);}}h->last=now;h->seen=1;}
  }
  if(z->cooldowns_at){unsigned char*d=base(c)+z->cooldowns_at;if(d[key])d[key]--;}
 }
 if(c->cfg.policy==JC_TINY)tiny_observe(c,key);
 if(c->cfg.policy==JC_LOGISTIC){HistoryEvent*h=(HistoryEvent*)(base(c)+c->lr_at);if(c->lr_count==c->cfg.history_capacity){unsigned oldest=c->lr_head;assert(scheduled>=h[oldest].time&&scheduled-h[oldest].time>50000000ULL);}else c->lr_count++;h[c->lr_head]=(HistoryEvent){scheduled,key,0};c->lr_head=(c->lr_head+1)%c->cfg.history_capacity;}
 for(unsigned type=0;type<2;type++){
  Entry*e=entry(c,indexes(c)[key].offset[type]);
  /* SIEVE needs only its bit plus shared last-use audit metadata on a hit. */
  if(e&&e->state==READY&&is_sieve(c->cfg.policy)){e->last=c->seq;e->seen=1;continue;}
  if(e&&e->state==READY){e->last=c->seq;if(e->frequency<UINT16_MAX)e->frequency++;if(is_s3(c->cfg.policy)&&e->frequency>3)e->frequency=3;if(c->cfg.policy==JC_LANDLORD){double gain=c->cfg.costs.state_ns[0]-c->cfg.costs.state_ns[type==0?2:1];e->credit=c->landlord_clock+fmax(0.,gain)/jc_entry_bytes(type);}}
  else if(c->cfg.policy==JC_LECAR){LcGhost*g=(LcGhost*)(base(c)+c->lc_at);for(unsigned i=0;i<c->lc_capacity;i++)if(g[i].valid&&g[i].key==key&&g[i].type==type){double penalty=exp(-.45*(double)(c->seq-g[i].step)/(double)c->cfg.contexts);unsigned expert=g[i].expert;c->lc_weights[type][expert]*=exp(-.45*penalty);double z=c->lc_weights[type][0]+c->lc_weights[type][1];for(unsigned a=0;a<2;a++)c->lc_weights[type][a]=fmax(.0001,c->lc_weights[type][a]/z);z=c->lc_weights[type][0]+c->lc_weights[type][1];for(unsigned a=0;a<2;a++)c->lc_weights[type][a]/=z;c->lc_restore[type]=g[i].frequency+1;g[i].valid=0;}}
 }
}
static double logistic_probability(JointCache*c,unsigned key){
 HistoryEvent*h=(HistoryEvent*)(base(c)+c->lr_at);unsigned newest=(c->lr_head+c->cfg.history_capacity-1)%c->cfg.history_capacity;uint64_t t=h[newest].time,prev=0;unsigned have=0,ngap=0,g5=0,g50=0;double mean=0,m2=0,x[11]={0};x[4]=x[5]=50.;
 unsigned first=(c->lr_head+c->cfg.history_capacity-c->lr_count)%c->cfg.history_capacity;
 for(unsigned j=0;j<c->lr_count;j++){HistoryEvent*e=h+(first+j)%c->cfg.history_capacity;if(t-e->time>50000000ULL)continue;uint64_t age=t-e->time;g50++;g5+=age<=5000000ULL;if(e->key!=key)continue;x[0]+=age<=5000000ULL;x[1]+=age<=10000000ULL;x[2]+=age<=20000000ULL;x[3]++;x[7]+=exp(-(double)age/10000000.);if(have){double d=(double)(e->time-prev)/1e6;ngap++;double delta=d-mean;mean+=delta/ngap;m2+=delta*(d-mean);x[4]=d;}prev=e->time;have=1;}
 if(ngap){x[5]=mean;if(ngap>=2&&mean>0)x[6]=sqrt(fmax(0,m2/ngap))/mean;}if(!g50||!g5)return 0.;x[8]=fabs(x[0]/g5-(x[3]-x[0])/fmax(1.,(double)g50-g5));x[9]=g5/5.;x[10]=g50/50.;
 const double*w=(const double*)(base(c)+c->lr_weights_at);double z=w[0];for(unsigned j=0;j<11;j++)z+=w[j+1]*x[j];return z>=0?1/(1+exp(-z)):exp(z)/(1+exp(z));
}
static double rate(JointCache*c,unsigned key,uint64_t now){(void)now;assert(c->cfg.policy==JC_LOGISTIC);return logistic_probability(c,key)/(double)c->cfg.horizon_ns;}
static void gains(const JointCache*c,double*dP,double*dS,double*dI){const double*a=c->cfg.costs.state_ns;*dP=a[0]-a[2];*dS=a[0]-a[1];*dI=a[2]+a[1]-a[0]-a[3];}
/* Calibration addP includes the CURRENT public improvement with S already hit.
 * Transfer to S-miss adds dI, assuming constructor cost is S-independent.
 * This signed additive-model correction is shared by every economic policy.
 * A newly copied secret never retroactively saves current reconstruction. */
static double public_transition_cost(const JointCache*c,unsigned key){double dp,ds,di;gains(c,&dp,&ds,&di);(void)dp;(void)ds;return c->cfg.costs.add_public_ns+(indexes(c)[key].offset[JC_SECRET]?0.:di);}
static double value(JointCache*c,unsigned key,int p,int s,uint64_t birth,uint64_t now){double dp,ds,di;gains(c,&dp,&ds,&di);uint64_t R=c->cfg.horizon_ns;if(s&&(c->cfg.policy!=JC_SCAR||(c->cfg.components&JC_DEADLINE))){uint64_t deadline=birth+c->cfg.ttl_ns-c->cfg.guard_ns;R=deadline>now?deadline-now:0;if(R>c->cfg.horizon_ns)R=c->cfg.horizon_ns;}double r=rate(c,key,now);return r*((p?c->cfg.horizon_ns*dp:0.)+(s?R*ds:0.)+(p&&s?R*di:0.))-(s&&R?c->cfg.costs.erase_secret_ns:0.);}
static double marginal(JointCache*c,Entry*e,const JointPlan*p,uint64_t now){Index*x=indexes(c)+e->key;Entry*a=entry(c,x->offset[0]),*s=entry(c,x->offset[1]);int pa=a&&!excluded(x->offset[0],p),ps=s&&!excluded(x->offset[1],p);uint64_t born=s?s->born:now;return value(c,e->key,pa,ps,born,now)-value(c,e->key,e->type==0?0:pa,e->type==1?0:ps,born,now);}
static void quotas(const JointCache*c,uint64_t out[2]){uint64_t avail=c->bytes-(uint64_t)c->prefix_units*Q;out[0]=out[1]=avail;unsigned percent=c->cfg.policy==JC_STATIC25?25:c->cfg.policy==JC_STATIC50||c->cfg.policy==JC_LECAR?50:c->cfg.policy==JC_STATIC75?75:0;if(percent){out[0]=((avail*percent/100)/Q)*Q;out[1]=avail-out[0];}if(public_only(c->cfg.policy))out[1]=0;if(c->cfg.policy==JC_SECRET_S3)out[0]=0;}
/* Bounded transient public integers, never retained in the arena or passed to
 * commit. Build only after the caller's existing no-work/cheap-reject paths.
 * Queue/RNG/victim scoring may change during a plan; ownership and spans do not. */
static void placement_occupancy(const JointCache*c,PlacementOccupancy*s){
 s->used[0]=s->used[1]=0;quotas(c,s->quota);
 for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){
  const Entry*e=entry(c,indexes(c)[key].offset[t]);
  if(e)s->used[t]+=(uint64_t)e->span*Q; /* Includes indexed PENDING entries. */
 }
}
/* Private planner contract: all victims are distinct indexed live entries
 * selected by the existing victim functions. No externally supplied plan may
 * reach this helper; jc_commit below retains the fresh independent scan. */
static int try_place_occupancy(JointCache*c,JointPlan*p,int*required_type,const PlacementOccupancy*s){
 unsigned char b[MAX_BITMAP];memcpy(b,bitmap(c),c->bitmap_bytes);
 uint64_t used[2]={s->used[0],s->used[1]};
 for(unsigned j=0;j<p->evict_count;j++){
  const Entry*e=entry(c,p->evict[j]);
  used[e->type]-=(uint64_t)e->span*Q;bits(b,p->evict[j],e->span,0);
 }
 for(unsigned t=0;t<2;t++)if(p->mask&(1u<<t))used[t]+=jc_entry_bytes(t);
 /* Keep quota-before-placement and P-before-S failure side effects exactly. */
 for(unsigned t=0;t<2;t++)if(used[t]>s->quota[t]){*required_type=(int)t;return 0;}
 for(unsigned t=0;t<2;t++){p->place[t]=0;if(p->mask&(1u<<t)){uint32_t off=fit(b,c->prefix_units,(unsigned)(c->bytes/Q),units(t));if(!off){*required_type=-1;return 0;}p->place[t]=off;bits(b,off,units(t),1);}}
 return 1;
}
/* Fresh validation path: reconstruct occupancy and exclusions from current
 * indexes for every commit. It trusts no planner snapshot or prior probe. */
static int try_place(JointCache*c,JointPlan*p,int*required_type){
 unsigned char b[MAX_BITMAP];memcpy(b,bitmap(c),c->bitmap_bytes);uint64_t used[2]={0},quota[2];quotas(c,quota);
 for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){uint32_t off=indexes(c)[key].offset[t];Entry*e=entry(c,off);if(!e)continue;if(excluded(off,p))bits(b,off,e->span,0);else used[t]+=(uint64_t)e->span*Q;}
 for(unsigned t=0;t<2;t++)if(p->mask&(1u<<t))used[t]+=jc_entry_bytes(t);
 for(unsigned t=0;t<2;t++)if(used[t]>quota[t]){*required_type=(int)t;return 0;}
 for(unsigned t=0;t<2;t++){p->place[t]=0;if(p->mask&(1u<<t)){uint32_t off=fit(b,c->prefix_units,(unsigned)(c->bytes/Q),units(t));if(!off){*required_type=-1;return 0;}p->place[t]=off;bits(b,off,units(t),1);}}
 return 1;
}
static int tie_before(const Entry*a,const Entry*b){return !b||a->last<b->last||(a->last==b->last&&(a->key<b->key||(a->key==b->key&&a->type<b->type)));}
static Entry *victim(JointCache*c,JointPlan*p,int type,uint64_t now){
 if(is_sieve(c->cfg.policy))return sieve_victim(c,p,type);
 Entry*best=NULL;double bestv=INFINITY;
 /* Fixed-size S3 per tier: FIFO small/main queues and capped second chances.
  * Selection mutates only public queue state; no payload is freed until commit. */
 if(is_s3(c->cfg.policy)){
  for(unsigned rounds=0;rounds<8*JC_MAX_OBJECTS;rounds++){
   unsigned count[2][2]={{0}};Entry*old[2][2]={{NULL}};
   for(unsigned k=0;k<c->cfg.contexts;k++)for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[k].offset[t]);if(!e||k==p->context||excluded(offset(c,e),p)||(type>=0&&(unsigned)type!=t))continue;unsigned q=e->queue;count[t][q]++;if(!old[t][q]||e->order<old[t][q]->order)old[t][q]=e;}
   unsigned selected=type>=0?(unsigned)type:(!old[0][0]&&!old[0][1]?1:!old[1][0]&&!old[1][1]?0:((old[0][0]?old[0][0]:old[0][1])->order<(old[1][0]?old[1][0]:old[1][1])->order?0:1));
   unsigned total=count[selected][0]+count[selected][1],small=total/10?total/10:1;Entry*e=count[selected][0]>=small?old[selected][0]:old[selected][1];if(!e)e=old[selected][0];if(!e)return NULL;
   if(!e->queue&&e->frequency>1){e->queue=1;e->frequency=0;e->order=++c->queue_clock;continue;}
   if(e->queue&&e->frequency){e->frequency--;e->order=++c->queue_clock;continue;}
   return e;
  }return NULL;
 }
 if(c->cfg.policy==JC_LECAR){
  /* Each partition compares its own expert's units. When contiguous placement
   * needs either tier, choose the older of the two tier candidates; never
   * compare an LFU count numerically with another tier's LRU sequence. */
  unsigned expert[2];Entry*candidate[2]={NULL,NULL};double score[2]={INFINITY,INFINITY};
  for(unsigned t=0;t<2;t++)expert[t]=random_unit(c)<c->lc_weights[t][0]?0:1;
  for(unsigned k=0;k<c->cfg.contexts;k++)for(unsigned t=0;t<2;t++){
   Entry*e=entry(c,indexes(c)[k].offset[t]);
   if(!e||k==p->context||excluded(offset(c,e),p)||(type>=0&&(unsigned)type!=t))continue;
   double v=expert[t]?e->frequency:(double)e->last;
   if(v<score[t]||(v==score[t]&&tie_before(e,candidate[t]))){candidate[t]=e;score[t]=v;}
  }
  best=candidate[0];if(candidate[1]&&tie_before(candidate[1],best))best=candidate[1];
  if(best)best->auxiliary=(uint16_t)expert[best->type];
  return best;
 }
 for(unsigned k=0;k<c->cfg.contexts;k++)for(unsigned t=0;t<2;t++){
  Entry*e=entry(c,indexes(c)[k].offset[t]);if(!e||k==p->context||excluded(offset(c,e),p)||(type>=0&&(unsigned)type!=t))continue;
  double v;
  if(is_scored(c->cfg.policy))v=marginal(c,e,p,now)/((double)e->span*Q);
  else if(c->cfg.policy==JC_LANDLORD)v=e->credit;
  else if(c->cfg.policy==JC_TINY)v=(double)e->last; /* LRU victim set, aggregate admission below. */
  else v=(double)e->last;
  if(v<bestv||(v==bestv&&tie_before(e,best))){best=e;bestv=v;}
 }
 return best;
}
static double objective(JointCache*c,const JointPlan*p,uint64_t now){
 double total=0.;
 if(is_scored(c->cfg.policy))for(unsigned k=0;k<c->cfg.contexts;k++){
  Index*x=indexes(c)+k;Entry*a=entry(c,x->offset[0]),*s=entry(c,x->offset[1]);int beforeP=a!=NULL,beforeS=s!=NULL,afterP=beforeP&&!excluded(x->offset[0],p),afterS=beforeS&&!excluded(x->offset[1],p);uint64_t birth=s?s->born:now;
  if(k==p->context){afterP|=(p->mask&1)!=0;afterS|=(p->mask&2)!=0;}
  if(afterP==beforeP&&afterS==beforeS)continue;
  total+=value(c,k,afterP,afterS,birth,now)-value(c,k,beforeP,beforeS,birth,now);
 }
 if(c->cfg.policy==JC_TINY){double dp,ds,di;gains(c,&dp,&ds,&di);(void)di;double f=tiny_frequency(c,p->context);total=f*((p->mask&1?dp:0)+(p->mask&2?ds:0));for(unsigned j=0;j<p->evict_count;j++){Entry*e=entry(c,p->evict[j]);total-=tiny_frequency(c,e->key)*(e->type==0?dp:ds);}}
 for(unsigned j=0;j<p->evict_count;j++){Entry*e=entry(c,p->evict[j]);total-=e->type==JC_PUBLIC?c->cfg.costs.erase_public_ns:c->cfg.costs.erase_secret_ns;}
 if(p->mask&1)total-=public_transition_cost(c,p->context);
 if(p->mask&2)total-=c->cfg.costs.add_secret_ns;
 return total;
}
int jc_plan(JointCache*c,unsigned key,uint64_t now,JointPlan*out){
 if(!c||key>=c->cfg.contexts||!out||c->cfg.policy==JC_SCAR)return -1;
 memset(out,0,sizeof(*out));out->context=key;out->clock_ns=now;out->sequence=c->seq;out->revision=c->revision;
 if(c->cfg.policy==JC_NONE)return 0;
 unsigned missing=0;for(unsigned t=0;t<2;t++)if(!indexes(c)[key].offset[t])missing|=1u<<t;
 if(public_only(c->cfg.policy))missing&=1;
 if(c->cfg.policy==JC_SECRET_S3)missing&=2;
 if(!missing)return 0;
 int scored=is_scored(c->cfg.policy)||c->cfg.policy==JC_TINY;
 int admission=c->cfg.policy!=JC_SCAR||(c->cfg.components&JC_ADMISSION);
 /* S3/LeCaR/SIEVE probe one fixed mask. Their queue/RNG updates are request
  * processing, explicitly charged even if no legal placement remains.
  * Scored/Tiny multi-mask probes do not mutate policy metadata. */
 if(is_s3(c->cfg.policy)||c->cfg.policy==JC_LECAR||is_sieve(c->cfg.policy))c->revision++;
 out->revision=c->revision;int found=0;
 PlacementOccupancy occupancy;placement_occupancy(c,&occupancy);
 unsigned begin=scored?1:missing,end=scored?3:missing;
 for(unsigned mask=begin;mask<=end;mask++){
  if(mask&~missing)continue;
  JointPlan p={0};p.context=key;p.clock_ns=now;p.sequence=c->seq;p.revision=c->revision;p.mask=mask;int need=-1;
  /* A placement probe mutates only this plan's scratch fields. Keep its last
   * result, including the probe after the last permitted victim. Commit still
   * independently validates all victims and first-fit placements. */
  int placed=try_place_occupancy(c,&p,&need,&occupancy);
  while(!placed&&p.evict_count<JC_MAX_OBJECTS){Entry*e=victim(c,&p,need,now);if(!e)break;p.evict[p.evict_count++]=offset(c,e);placed=try_place_occupancy(c,&p,&need,&occupancy);}
  if(!placed)continue;
  p.objective_ns=scored?objective(c,&p,now):0.;
  if(!scored){*out=p;break;}
  int take=(!admission&&!found)||p.objective_ns>out->objective_ns+1e-12;
  if(!take&&p.mask&&out->mask&&fabs(p.objective_ns-out->objective_ns)<=1e-12){
   int64_t ps=(p.mask&2)?(int64_t)jc_entry_bytes(1):0,os=(out->mask&2)?(int64_t)jc_entry_bytes(1):0;
   int64_t pt=ps+((p.mask&1)?(int64_t)jc_entry_bytes(0):0),ot=os+((out->mask&1)?(int64_t)jc_entry_bytes(0):0);
   for(unsigned j=0;j<p.evict_count;j++){Entry*e=entry(c,p.evict[j]);pt-=(int64_t)e->span*Q;if(e->type)ps-=(int64_t)e->span*Q;}
   for(unsigned j=0;j<out->evict_count;j++){Entry*e=entry(c,out->evict[j]);ot-=(int64_t)e->span*Q;if(e->type)os-=(int64_t)e->span*Q;}
   take=ps<os||(ps==os&&(pt<ot||(pt==ot&&p.mask<out->mask)));
  }
  if(take){*out=p;found=1;}
 }
 return 0;
}
int jc_commit(JointCache*c,const JointPlan*p,uint64_t birth){
 if(!c||!p||p->sequence!=c->seq||p->revision!=c->revision||p->context>=c->cfg.contexts||p->mask>3||p->evict_count>JC_MAX_OBJECTS||(!p->mask&&p->evict_count)||birth<p->clock_ns||!isfinite(p->objective_ns))return -1;
 /* Common no-change path: no allocator work is needed, but stale plans and
  * nonzero forged placements are still rejected, and commit remains single-use. */
 if(!p->mask){if(p->place[0]||p->place[1])return -1;c->revision++;return 0;}
 /* Validate all victims and first-fit placements in a shadow bitmap BEFORE
  * clearing even one byte. This includes duplicates, bounds and live identity. */
 for(unsigned j=0;j<p->evict_count;j++){
  uint32_t off=p->evict[j];if(off<c->prefix_units||(uint64_t)off+sizeof(Entry)/Q>c->bytes/Q)return -1;
  for(unsigned i=0;i<j;i++)if(p->evict[i]==off)return -1;
  Entry*e=entry(c,off);
  if(e->state!=READY||e->key>=c->cfg.contexts||e->type>1||e->key==p->context||e->span!=units(e->type)||off+e->span>c->bytes/Q||indexes(c)[e->key].offset[e->type]!=off)return -1;
 }
 for(unsigned type=0;type<2;type++)if((p->mask&(1u<<type))&&indexes(c)[p->context].offset[type])return -1;
 JointPlan check=*p;int required=-1;
 if(!try_place(c,&check,&required)||check.place[0]!=p->place[0]||check.place[1]!=p->place[1])return -1;
 c->revision++; /* consume even an empty action: duplicate commit is stale */
 for(unsigned j=0;j<p->evict_count;j++)remove_entry(c,entry(c,p->evict[j]),p->clock_ns,1);
 for(unsigned type=0;type<2;type++)if(p->mask&(1u<<type)){
  uint32_t off=p->place[type];Entry*e=entry(c,off);memset(e,0,sizeof(*e));
  e->generation=indexes(c)[p->context].generation;e->born=birth;e->last=c->seq;e->order=++c->queue_clock;e->key=p->context;e->span=units(type);e->type=(uint8_t)type;e->state=PENDING;e->frequency=1;e->auxiliary=2;
  if(is_s3(c->cfg.policy)){e->frequency=0;int found=ghost_find(c,e->key,type);e->queue=found>=0;if(found>=0){Ghost*g=(Ghost*)(base(c)+c->ghost_at);memmove(g+found,g+found+1,(c->ghost_count-(unsigned)found-1)*sizeof(*g));c->ghost_count--;}}
  if(c->cfg.policy==JC_LECAR)e->frequency=(uint16_t)(c->lc_restore[type]>UINT16_MAX?UINT16_MAX:c->lc_restore[type]);
  double dp,ds,di;gains(c,&dp,&ds,&di);(void)di;e->credit=c->landlord_clock+fmax(0.,type==0?dp:ds)/jc_entry_bytes(type);
  if(is_sieve(c->cfg.policy))sieve_insert(c,e);
  bits(bitmap(c),off,e->span,1);indexes(c)[e->key].offset[type]=off;c->used+=(uint64_t)e->span*Q;if(c->used>c->peak)c->peak=c->used;
 }
 return jc_check(c)?0:-1;
}
void *jc_pending(JointCache*c,unsigned key,unsigned type){if(key>=c->cfg.contexts||type>1)return NULL;Entry*e=entry(c,indexes(c)[key].offset[type]);return e&&e->state==PENDING?e+1:NULL;}
int jc_publish(JointCache*c,unsigned key,unsigned type){if(key>=c->cfg.contexts||type>1)return -1;Entry*e=entry(c,indexes(c)[key].offset[type]);if(!e||e->state!=PENDING)return -1;e->state=READY;c->revision++;return 0;}
void jc_clear_all(JointCache*c,uint64_t now){if(c->used==(uint64_t)c->prefix_units*Q)return;for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e)remove_entry(c,e,now,0);}}
JointMonitorBarrierResult jc_pre_monitor_barrier(JointCache*c,uint64_t now){
 JointMonitorBarrierResult result={0,0};
 if(!jc_check(c))return result;
 unsigned secrets=0;
 /* Complete prevalidation precedes the first revision update or erase. Even a
  * pending public entry rejects this post-request boundary without mutation. */
 for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned type=0;type<2;type++){
  const Entry*e=entry(c,indexes(c)[key].offset[type]);
  if(e&&(e->state!=READY||(type==JC_SECRET&&now<e->born)))return result;
  if(e&&type==JC_SECRET)secrets++;
 }
 c->revision++; /* Invalidate pre-boundary plans even if no S was retained. */
 /* Proven empty-of-S: only the revision changed, so neither an erase pass nor
  * a second invariant reconstruction is needed. This applies to every policy. */
 if(!secrets){result.success=1;return result;}
 for(unsigned key=0;key<c->cfg.contexts;key++){
  Entry*e=entry(c,indexes(c)[key].offset[JC_SECRET]);
  if(e){remove_entry(c,e,now,0);result.erased++;}
 }
 assert(jc_check(c));
 result.success=1;return result;
}
int jc_rotate(JointCache*c,unsigned key,uint64_t generation,uint64_t now){if(key>=c->cfg.contexts||!generation||generation==indexes(c)[key].generation)return -1;for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e)remove_entry(c,e,now,0);}indexes(c)[key].generation=generation;c->revision++;return 0;}
uint64_t jc_generation(const JointCache*c,unsigned key){return key<c->cfg.contexts?indexes(c)[key].generation:0;}
JointStats jc_stats(const JointCache*c){JointStats s={0};s.reserved_bytes=c->bytes;s.prefix_bytes=(uint64_t)c->prefix_units*Q;s.used_bytes=c->used;s.peak_used_bytes=c->peak;s.evictions=c->evictions;s.zeroizations=c->zeroizations;s.max_residency_ns=c->max_life;s.late_clear_count=c->late;s.max_lateness_ns=c->max_lateness;s.bitmap_bytes=c->bitmap_bytes;s.history_bytes=c->cfg.policy==JC_SCAR?(((CausalState*)(base(c)+c->history_at))->histories_at?(c->cfg.contexts+1)*sizeof(History):0):c->lr_at?c->cfg.history_capacity*sizeof(HistoryEvent):0;s.policy_bytes=s.prefix_bytes-ROUND(sizeof(*c))-ROUND(c->cfg.contexts*sizeof(Index))-ROUND(c->bitmap_bytes);if(c->used==s.prefix_bytes)return s;for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e){s.entries++;if(t)s.secret_bytes+=(uint64_t)e->span*Q;else s.public_bytes+=(uint64_t)e->span*Q;}}return s;}
size_t jc_entries(const JointCache*c,JointEntryView*out,size_t cap){size_t n=0;for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){Entry*e=entry(c,indexes(c)[key].offset[t]);if(e){if(n<cap)out[n]=(JointEntryView){offset(c,e)*Q,e->span*Q,key,t,e->generation,e->born,e->last,e->state==READY};n++;}}return n;}
int jc_check(const JointCache*c){
 if(!c||c->magic!=MAGIC||c->bytes>65536||c->bytes<32768||c->used>c->bytes||c->peak>c->bytes||c->prefix_units>c->bytes/Q)return 0;
 unsigned char b[MAX_BITMAP]={0};bits(b,0,c->prefix_units,1);
 uint64_t used=(uint64_t)c->prefix_units*Q,by_type[2]={0},quota[2];quotas(c,quota);
 for(unsigned key=0;key<c->cfg.contexts;key++)for(unsigned t=0;t<2;t++){
  uint32_t off=indexes(c)[key].offset[t];if(!off)continue;
  if(off<c->prefix_units||(uint64_t)off+sizeof(Entry)/Q>c->bytes/Q)return 0;
  Entry*e=entry(c,off);
  if(e->key!=key||e->type!=t||e->span!=units(t)||(uint64_t)off+e->span>c->bytes/Q||e->generation!=indexes(c)[key].generation||(e->state!=READY&&e->state!=PENDING))return 0;
  /* This bitmap is local scratch: an overlap may leave a partially marked
   * shadow, which is discarded. Cache bytes and every invariant stay intact. */
  if(!mark_unoccupied(b,off,e->span))return 0;
  used+=(uint64_t)e->span*Q;by_type[t]+=(uint64_t)e->span*Q;
 }
 if(is_sieve(c->cfg.policy)&&!sieve_check(c))return 0;
 return used==c->used&&by_type[0]<=quota[0]&&by_type[1]<=quota[1]&&!memcmp(b,bitmap(c),c->bitmap_bytes);
}

#include "causal_policy.inc"
