#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <time.h>
#include <inttypes.h>
#include "mlkem_native.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failure line=%d errno=%d\n",__LINE__,errno);exit(1);}}while(0)
static uint64_t now(void){struct timespec t;CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0);return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
static void entropy(void*p,size_t n){unsigned char*b=p;while(n){ssize_t r=getrandom(b,n,0);if(r<0&&errno==EINTR)continue;CHECK(r>0);b+=r;n-=(size_t)r;}}
typedef struct {unsigned char seed[64],coins[32],pk[1184],sk[2400],ct[1088],ss[32],out[32];} Arena;
int main(int argc,char**argv){
 CHECK(argc==3);int n=atoi(argv[2]);CHECK(n>=100&&n<=100000);
 struct rlimit lim={0,0};CHECK(setrlimit(RLIMIT_CORE,&lim)==0&&prctl(PR_SET_DUMPABLE,0)==0);
 Arena*s=mmap(NULL,sizeof(*s),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(s!=MAP_FAILED);
 CHECK(mlock(s,sizeof(*s))==0&&madvise(s,sizeof(*s),MADV_DONTDUMP)==0);
 uint64_t*rows=calloc((size_t)n*6,sizeof(uint64_t));CHECK(rows);
 entropy(s->seed,64);
 for(int i=-200;i<n;i++){
  uint64_t a=now();CHECK(mlkem_keypair_derand(s->pk,s->sk,s->seed)==0);uint64_t b=now();
  uint64_t rec=b-a;
  a=now();entropy(s->seed,64);CHECK(mlkem_keypair_derand(s->pk,s->sk,s->seed)==0);b=now();uint64_t kg=b-a;
  a=now();entropy(s->coins,32);CHECK(mlkem_enc_derand(s->ct,s->ss,s->pk,s->coins)==0);b=now();uint64_t enc=b-a;
  a=now();CHECK(mlkem_dec(s->out,s->ct,s->sk)==0);b=now();uint64_t dec=b-a;
  CHECK(memcmp(s->out,s->ss,32)==0);
  a=now();explicit_bzero(s->sk,2400);b=now();uint64_t clear=b-a;
  a=now();b=now();uint64_t timer=b-a;
  explicit_bzero(s->out,32);explicit_bzero(s->ss,32);explicit_bzero(s->coins,32);
  if(i>=0){uint64_t v[6]={rec,kg,enc,dec,clear,timer};memcpy(rows+6*i,v,sizeof(v));}
 }
 explicit_bzero(s,sizeof(*s));CHECK(munlock(s,sizeof(*s))==0&&munmap(s,sizeof(*s))==0);
 puts("session_id,iteration,reconstruction_ns,keygen_with_rng_ns,encaps_with_rng_ns,decaps_ns,zeroize_2400_ns,timer_pair_ns");
 for(int i=0;i<n;i++){printf("%s,%d",argv[1],i);for(int j=0;j<6;j++)printf(",%" PRIu64,rows[6*i+j]);putchar('\n');}
 free(rows);return 0;
}
