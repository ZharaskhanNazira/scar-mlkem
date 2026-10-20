/* Independent C implementations of public-metadata admission policies.
 * TinyLFU: Einziger/Friedman/Manes, arXiv:1512.00727v2, sections 3.2--3.4.
 * LeCaR equations: Vietri et al., HotStorage 2018; reference commit recorded in docs.
 * Adaptations (mandatory TTL, C RNG, float64 weights) are explicitly documented. */
#ifndef SCAR_POLICY_SUPPORT_H
#define SCAR_POLICY_SUPPORT_H
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
typedef struct {uint8_t count[4][1024],door[512];unsigned width,sample,window;} TinySketch;
static TinySketch tiny_sketch;
static uint32_t policy_hash(uint32_t x){x^=x>>16;x*=0x7feb352dU;x^=x>>15;x*=0x846ca68bU;return x^(x>>16);}
static const uint32_t hash_salt[4]={0x9e3779b9U,0x85ebca6bU,0xc2b2ae35U,0x27d4eb2fU};
static void tiny_init(unsigned capacity){memset(&tiny_sketch,0,sizeof(tiny_sketch));unsigned w=1;while(w<8*capacity)w*=2;assert(w<=1024);tiny_sketch.width=w;tiny_sketch.window=10*capacity;}
static unsigned tiny_door(int key,int set){unsigned present=1;for(int r=0;r<4;r++){unsigned h=policy_hash((uint32_t)key^hash_salt[r])%(4*tiny_sketch.width);present&=(tiny_sketch.door[h/8]>>(h%8))&1U;if(set)tiny_sketch.door[h/8]|=(uint8_t)(1U<<(h%8));}return present;}
static unsigned tiny_estimate(int key){unsigned value=15;for(int r=0;r<4;r++){unsigned h=policy_hash((uint32_t)key^hash_salt[r])&(tiny_sketch.width-1);if(tiny_sketch.count[r][h]<value)value=tiny_sketch.count[r][h];}return value+tiny_door(key,0);}
static void tiny_observe(int key){
 unsigned seen=tiny_door(key,1);
 if(seen){unsigned low=15;unsigned h[4];for(int r=0;r<4;r++){h[r]=policy_hash((uint32_t)key^hash_salt[r])&(tiny_sketch.width-1);if(tiny_sketch.count[r][h[r]]<low)low=tiny_sketch.count[r][h[r]];}
  if(low<15)for(int r=0;r<4;r++)if(tiny_sketch.count[r][h[r]]==low)tiny_sketch.count[r][h[r]]++;
 }
 if(++tiny_sketch.sample>=tiny_sketch.window){for(int r=0;r<4;r++)for(unsigned j=0;j<tiny_sketch.width;j++)tiny_sketch.count[r][j]>>=1;memset(tiny_sketch.door,0,sizeof(tiny_sketch.door));tiny_sketch.sample/=2;}
}
typedef struct {int valid,key;uint64_t frequency,step;} LeCarGhost;
static LeCarGhost lc_history[2][128];
static double lc_weight[2];static uint64_t lc_rng;
static void lc_init(uint64_t seed){memset(lc_history,0,sizeof(lc_history));lc_weight[0]=lc_weight[1]=.5;lc_rng=seed?seed:123;}
static double lc_uniform(void){uint64_t x=lc_rng;x^=x>>12;x^=x<<25;x^=x>>27;lc_rng=x;return (double)((x*2685821657736338717ULL)>>11)/9007199254740992.;}
static uint64_t lc_miss(int key,uint64_t step,int capacity){
 for(int policy=0;policy<2;policy++)for(int j=0;j<capacity;j++)if(lc_history[policy][j].valid&&lc_history[policy][j].key==key){
  LeCarGhost g=lc_history[policy][j];lc_history[policy][j].valid=0;
  double penalty=pow(.005,(double)(step-g.step)/capacity);
  lc_weight[policy]*=exp(-.45*penalty);double sum=lc_weight[0]+lc_weight[1];lc_weight[0]/=sum;lc_weight[1]/=sum;
  lc_weight[0]=fmin(.99,fmax(.01,lc_weight[0]));lc_weight[1]=1-lc_weight[0];return g.frequency+1;
 }
 return 1;
}
static void lc_remember(int key,uint64_t frequency,uint64_t step,int policy,int capacity){
 if(policy<0){return;}
 int target=-1;
 for(int j=0;j<capacity;j++)if(!lc_history[policy][j].valid){target=j;break;}
 if(target<0){target=0;for(int j=1;j<capacity;j++)if(lc_history[policy][j].step<lc_history[policy][target].step)target=j;}
 lc_history[policy][target]=(LeCarGhost){1,key,frequency,step};
}
static void support_selftest(void){
 tiny_init(16);assert(tiny_estimate(37)==0);tiny_observe(37);assert(tiny_estimate(37)==1);tiny_observe(37);assert(tiny_estimate(37)==2);
 for(int i=2;i<159;i++){tiny_observe(37);}
 assert(tiny_estimate(37)==16);tiny_observe(37);assert(tiny_estimate(37)==7&&tiny_sketch.sample==80);
 lc_init(123);lc_remember(4,3,1,0,4);assert(lc_miss(4,2,4)==4&&lc_weight[0]<.5);double w=lc_weight[0];assert(lc_miss(4,3,4)==1&&lc_weight[0]==w);
 for(int i=0;i<9;i++){lc_remember(i,1,(uint64_t)i,1,4);}
 int count=0;for(int i=0;i<4;i++)count+=lc_history[1][i].valid;assert(count==4);
 assert(lc_uniform()>=0&&lc_uniform()<1);
}
#endif
