/* Controlled schedules; real ML-KEM-768 operation measurements on Linux ARM64.
 * This instrument runs matched real-cryptography cache experiments. */
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
#define CHECK(x) do { if(!(x)){fprintf(stderr,"check_failed:%s:%d errno=%d\n",#x,__LINE__,errno);exit(1);} }while(0)
#define MAXKEYS 256
#define MAXREQ 6000
#define MAXCACHE 128
typedef struct { unsigned char seed[64],pk[1184]; } Key;
typedef struct { unsigned char ct[1088],ss[32]; } RequestSecret;
typedef struct { Key keys[MAXKEYS]; unsigned char sk[2400],out[32],coins[32]; unsigned char cache[MAXCACHE][2400]; RequestSecret req[MAXREQ]; } Secrets;
typedef struct { int key; uint64_t due,stamp,rec,dec,service,cycles; double freq,temp; int success,hit,occupancy,evictions; uint64_t prediction,lookup,clear,copy,maintenance; } Event;
static uint64_t rng_state;
static uint64_t rnd(void){uint64_t x=rng_state;x^=x>>12;x^=x<<25;x^=x>>27;rng_state=x;return x*2685821657736338717ULL;}
static double uniform(void){return ((double)(rnd()>>11)+0.5)/9007199254740992.0;}
static uint64_t now(void){struct timespec t;CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0);return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;}
static void entropy(void*p,size_t n){unsigned char*b=p;while(n){ssize_t r=getrandom(b,n,0);if(r<0&&errno==EINTR)continue;CHECK(r>0);n-=(size_t)r;b+=r;}}
static double readnumber(const char*p,double scale){FILE*f=fopen(p,"r");if(!f)return NAN;double n=NAN;if(fscanf(f,"%lf",&n)!=1)n=NAN;fclose(f);return n/scale;}
static void wait_until(uint64_t target){struct timespec ts={(time_t)(target/1000000000ULL),(long)(target%1000000000ULL)};int r;do{r=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL);}while(r==EINTR);CHECK(r==0);}
static int choose_key(const char*kind,int i,int n,int k,double *gap){
    double u=uniform(); int v=0;
    if(!strcmp(kind,"uniform")||!strcmp(kind,"poisson"))v=(int)(u*k);
    else if(!strcmp(kind,"zipf")||!strcmp(kind,"nonstationary")){
        double total=0;for(int j=1;j<=k;j++)total+=1.0/pow(j,1.2);
        double target=u*total,acc=0;for(v=0;v<k-1;v++){acc+=1.0/pow(v+1,1.2);if(acc>=target)break;}
        if(!strcmp(kind,"nonstationary"))v=(v+i*k/n)%k;
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

/* All slot key material belongs to the locked secret arena. Metadata are public. */
typedef struct {int key,valid; uint64_t born,last,inserted; double score;} Slot;
static Slot slots[MAXCACHE];
static uint64_t max_life,total_life,zero_count,late_clear,max_lateness;
static uint64_t ttl_ns,guard_ns=200000ULL;
static int capacity;
static int occupied(void){int n=0;for(int j=0;j<capacity;j++)n+=slots[j].valid;return n;}
static uint64_t erase_slot(Secrets*s,int j){
    uint64_t begin=now();
    explicit_bzero(s->cache[j],2400);
    uint64_t end=now(),life=end-slots[j].born;
    if(life>max_life)max_life=life;
    if(life>ttl_ns){late_clear++;if(life-ttl_ns>max_lateness)max_lateness=life-ttl_ns;}
    total_life+=life;zero_count++;slots[j].valid=0;
    for(int x=0;x<2400;x++)CHECK(s->cache[j][x]==0);
    return now()-begin;
}
static uint64_t expire(Secrets*s,uint64_t t){
    uint64_t spent=0;
    for(int j=0;j<capacity;j++)if(slots[j].valid && t+guard_ns>=slots[j].born+ttl_ns)spent+=erase_slot(s,j);
    return spent;
}
static uint64_t wait_expiring(Secrets*s,uint64_t target){
    uint64_t overhead=0;
    while(1){
        uint64_t t=now(),b=t;(void)expire(s,t);overhead+=now()-b;
        if(t>=target)break;
        uint64_t wake=target;
        for(int j=0;j<capacity;j++)if(slots[j].valid){uint64_t d=slots[j].born+ttl_ns-guard_ns;if(d<wake)wake=d;}
        wait_until(wake);
    }
    return overhead;
}
static void feature_vector(const Event*events,int i,double*x){
    uint64_t t=events[i].due,prev=0;int have_previous=0;double mean_gap=0,m2=0;
    int ngap=0,g5=0,g50=0;
    memset(x,0,11*sizeof(double));x[4]=50;x[5]=50;
    int start=i;while(start>0 && events[i].due-events[start-1].due<=50000000ULL)start--;
    for(int j=start;j<=i;j++){
        uint64_t tj=events[j].due,age=t-tj;g50++;g5+=age<=5000000ULL;
        if(events[j].key!=events[i].key)continue;
        x[0]+=age<=5000000ULL;x[1]+=age<=10000000ULL;x[2]+=age<=20000000ULL;x[3]++;
        x[7]+=exp(-(double)age/10000000.0);
        if(have_previous){double d=(double)(tj-prev)/1e6;ngap++;double delta=d-mean_gap;mean_gap+=delta/ngap;m2+=delta*(d-mean_gap);x[4]=d;}
        prev=tj;have_previous=1;
    }
    if(ngap){x[5]=mean_gap;if(ngap>=2&&x[5]>0)x[6]=sqrt(fmax(0,m2/ngap))/x[5];}
    x[8]=fabs(x[0]/g5-(x[3]-x[0])/fmax(1,g50-g5));x[9]=g5/5.;x[10]=g50/50.;
}
#if __has_include("model_lr.h")
#include "model_lr.h"
#else
static double predict_lr(const double*x){(void)x;fprintf(stderr,"LR model missing\n");exit(3);}
#endif
int main(int argc,char**argv){
    if(argc==2&&!strcmp(argv[1],"features")){
        Event*e=calloc(MAXREQ,sizeof(Event));CHECK(e);int n=0;
        while(n<MAXREQ&&scanf("%" SCNu64 " %d",&e[n].due,&e[n].key)==2){
            double x[11];feature_vector(e,n,x);
            for(int j=0;j<11;j++)printf(j?",%.17g":"%.17g",x[j]);
            putchar('\n');n++;
        }
        free(e);return 0;
    }
    CHECK(argc==11);
    const char*session=argv[1],*kind=argv[2];uint64_t seed=strtoull(argv[3],NULL,10);
    int n=atoi(argv[4]),nk=atoi(argv[5]);double interval_us=atof(argv[6]);
    const char*split=argv[7],*policy=argv[8];capacity=atoi(argv[9]);ttl_ns=(uint64_t)(atof(argv[10])*1e6);
    CHECK(seed&&n>=100&&n<=MAXREQ&&nk>=32&&nk<=MAXKEYS&&interval_us>=50);
    CHECK(capacity>=0&&capacity<=MAXCACHE&&ttl_ns>=1000000);
    int seedonly=!strcmp(policy,"seed_only"),fixed=!strcmp(policy,"fixed_ttl"),lru=!strcmp(policy,"lru"),lfu=!strcmp(policy,"lfu");
    int frequency=!strcmp(policy,"frequency"),ewma=!strcmp(policy,"ewma"),lr=!strcmp(policy,"logistic");
    CHECK(seedonly||fixed||lru||lfu||frequency||ewma||lr);
    if(seedonly)capacity=0;else CHECK(capacity>0);
    rng_state=seed;struct rlimit lim={0,0};CHECK(setrlimit(RLIMIT_CORE,&lim)==0&&prctl(PR_SET_DUMPABLE,0)==0);
    size_t size=sizeof(Secrets)-sizeof(RequestSecret)*(MAXREQ-n);
    Secrets*s=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(s!=MAP_FAILED);
    CHECK(mlock(s,size)==0&&madvise(s,size,MADV_DONTDUMP)==0);
    Event*events=calloc((size_t)n,sizeof(Event));CHECK(events);
    uint64_t counts[MAXKEYS]={0};int permutation[MAXKEYS];
    for(int j=0;j<nk;j++)permutation[j]=j;
    for(int j=nk-1;j>0;j--){int q=(int)(rnd()%(uint64_t)(j+1));int tmp=permutation[j];permutation[j]=permutation[q];permutation[q]=tmp;}
    for(int j=0;j<nk;j++){entropy(s->keys[j].seed,64);CHECK(mlkem_keypair_derand(s->keys[j].pk,s->sk,s->keys[j].seed)==0);explicit_bzero(s->sk,2400);}
    uint64_t relative=0;
    for(int i=0;i<n;i++){
        double gap=interval_us;events[i].key=permutation[choose_key(kind,i,n,nk,&gap)];relative+=(uint64_t)(gap*1000);events[i].due=relative;
        entropy(s->coins,32);CHECK(mlkem_enc_derand(s->req[i].ct,s->req[i].ss,s->keys[events[i].key].pk,s->coins)==0);explicit_bzero(s->coins,32);
    }
    for(int i=0;i<100;i++){int id=events[0].key;CHECK(mlkem_keypair_derand(s->keys[id].pk,s->sk,s->keys[id].seed)==0);CHECK(mlkem_dec(s->out,s->req[0].ct,s->sk)==0);CHECK(!memcmp(s->out,s->req[0].ss,32));explicit_bzero(s->sk,2400);explicit_bzero(s->out,32);}
    struct perf_event_attr pe={0};pe.type=PERF_TYPE_HARDWARE;pe.size=sizeof(pe);pe.config=PERF_COUNT_HW_CPU_CYCLES;pe.exclude_kernel=1;pe.exclude_hv=1;
    int pfd=(int)syscall(SYS_perf_event_open,&pe,0,-1,-1,0);CHECK(pfd>=0);
    uint64_t start=now()+10000000ULL;double temp=NAN,freq=NAN;int rejected=0;
    for(int i=0;i<n;i++){
        Event*e=&events[i];uint64_t due=start+e->due;
        if(i%64==0){temp=readnumber("/sys/class/thermal/thermal_zone0/temp",1000);freq=readnumber("/sys/devices/system/cpu/cpu2/cpufreq/scaling_cur_freq",1000);}
        e->temp=temp;e->freq=freq;e->maintenance=wait_expiring(s,due);e->stamp=now();
        uint64_t cyc0,cyc1;CHECK(read(pfd,&cyc0,8)==8);
        uint64_t b=now();int slot=-1;
        for(int j=0;j<capacity;j++)if(slots[j].valid&&slots[j].key==e->key){slot=j;break;}
        e->lookup=now()-b;e->hit=slot>=0;counts[e->key]++;
        uint64_t born=now();
        if(slot<0){b=now();CHECK(mlkem_keypair_derand(s->keys[e->key].pk,s->sk,s->keys[e->key].seed)==0);e->rec=now()-b;}
        b=now();int ok=mlkem_dec(s->out,s->req[i].ct,slot<0?s->sk:s->cache[slot])==0;e->dec=now()-b;
        e->success=ok&&!memcmp(s->out,s->req[i].ss,32);CHECK(e->success);explicit_bzero(s->out,32);
        double score=1.0;
        if(frequency||ewma||lr){
            b=now();double x[11];feature_vector(events,i,x);
            score=frequency?1-exp(-10*fmax(0,x[3]-1)/50):ewma?1-exp(-fmax(0,x[7]-1)/(1-exp(-5))):predict_lr(x);
            e->prediction=now()-b;CHECK(isfinite(score)&&score>=0&&score<=1);
        }
        if(slot>=0){slots[slot].last=(uint64_t)i;slots[slot].score=score;}
        if(slot<0&&!seedonly){
            int target=-1;for(int j=0;j<capacity;j++)if(!slots[j].valid){target=j;break;}
            if(target<0){
                target=0;
                for(int j=1;j<capacity;j++){
                    int choose=fixed?slots[j].inserted<slots[target].inserted:lfu?(counts[slots[j].key]<counts[slots[target].key]||(counts[slots[j].key]==counts[slots[target].key]&&slots[j].last<slots[target].last)):slots[j].last<slots[target].last;
                    if(frequency||ewma||lr)choose=slots[j].score<slots[target].score;
                    if(choose)target=j;
                }
            }
            int admit=!(frequency||ewma||lr)||score>=.5;
            if((frequency||ewma||lr)&&slots[target].valid&&score<slots[target].score)admit=0;
            if(admit){
                if(slots[target].valid){e->clear+=erase_slot(s,target);e->evictions++;}
                b=now();memcpy(s->cache[target],s->sk,2400);e->copy=now()-b;
                slots[target]=(Slot){.key=e->key,.valid=1,.born=born,.last=(uint64_t)i,.inserted=(uint64_t)i,.score=score};
            }else rejected++;
        }
        b=now();explicit_bzero(s->sk,2400);e->clear+=now()-b;
        e->clear+=expire(s,now());e->occupancy=occupied();CHECK(e->occupancy<=capacity);
        CHECK(read(pfd,&cyc1,8)==8);e->cycles=cyc1-cyc0;e->service=now()-e->stamp;
    }
    for(int j=0;j<capacity;j++)if(slots[j].valid)erase_slot(s,j);
    struct rusage ru;CHECK(getrusage(RUSAGE_SELF,&ru)==0);
    fprintf(stderr,"session=%s policy=%s workload=%s seed=%" PRIu64 " requests=%d capacity=%d ttl_ns=%" PRIu64 " guard_ns=%" PRIu64 " max_residency_ns=%" PRIu64 " summed_residency_ns=%" PRIu64 " cache_zeroizations=%" PRIu64 " late_clear_count=%" PRIu64 " max_lateness_ns=%" PRIu64 " rejected_admissions=%d secrets_mlocked_bytes=%zu peak_rss_bytes=%ld cpu=%d\n",session,policy,kind,seed,n,capacity,ttl_ns,guard_ns,max_life,total_life,zero_count,late_clear,max_lateness,rejected,size,ru.ru_maxrss*1024,sched_getcpu());
    explicit_bzero(s,size);CHECK(munlock(s,size)==0&&munmap(s,size)==0);close(pfd);
    puts("session_id,split,workload_id,policy,request_id,key_id,schedule_ns,arrival_ns,service_ns,response_ns,reconstruction_ns,decapsulation_ns,cpu_cycles,cache_hit,cache_occupancy_bytes,evictions,prediction_ns,lookup_ns,copy_ns,clear_ns,idle_maintenance_ns,temperature_c,cpu_frequency_mhz,success");
    for(int i=0;i<n;i++){Event*e=&events[i];printf("%s,%s,%s,%s,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%d\n",session,split,kind,policy,i,e->key,e->due,e->stamp,e->service,e->stamp+e->service-start-e->due,e->rec,e->dec,e->cycles,e->hit,e->occupancy*2400,e->evictions,e->prediction,e->lookup,e->copy,e->clear,e->maintenance,e->temp,e->freq,e->success);}
    free(events);return 0;
}
