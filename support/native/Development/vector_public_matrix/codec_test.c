/* Public integer fixtures only: no keys, KEM or timing on the Mac. */
#include <stdio.h>
#include <string.h>
#include "pack12.h"
__attribute__((noinline)) static void encode(uint8_t *p,const int16_t *x){scar_pack12_poly(p,x);}
__attribute__((noinline)) static void decode(int16_t *x,const uint8_t *p){scar_unpack12_poly(x,p);}
int main(void){
 int16_t domain[256];unsigned domain_checks=0;
 for(int value=-32768;value<=32767;value++){
  for(unsigned i=0;i<256;i++)domain[i]=(int16_t)value;
  assert(scar_pack12_coefficients_valid(domain)==(value>=0&&value<3329));domain_checks++;
 }
 const int16_t bad[4]={-32768,-1,3329,32767};
 for(unsigned k=0;k<4;k++)for(unsigned lane=0;lane<256;lane++){
  memset(domain,0,sizeof domain);domain[lane]=bad[k];
  assert(!scar_pack12_coefficients_valid(domain));domain_checks++;
 }
 assert(domain_checks==66560);

 int16_t x[256],y[258];uint8_t guarded[386],ref[384];unsigned long pairs=0,blocks=0;
 for(unsigned a=0;a<3329;a++)for(unsigned first=0;first<3329;first+=128){
  memset(guarded,0xa5,sizeof guarded);y[0]=y[257]=12345;
  for(unsigned j=0;j<128;j++){x[2*j]=(int16_t)a;x[2*j+1]=(int16_t)((first+j)%3329);}
  encode(guarded+1,x);decode(y+1,guarded+1);
  assert(guarded[0]==0xa5&&guarded[385]==0xa5&&y[0]==12345&&y[257]==12345);
  assert(memcmp(x,y+1,sizeof x)==0);
  /* Independent bit-index encoder for edge/cross-byte fixtures. */
  if(a==0||a==3328||first==0){
   memset(ref,0,sizeof ref);
   for(unsigned k=0;k<256;k++)for(unsigned bit=0;bit<12;bit++)
    ref[(12*k+bit)/8]|=(uint8_t)(((unsigned)x[k]>>bit&1u)<<((12*k+bit)%8));
   assert(memcmp(ref,guarded+1,sizeof ref)==0);
  }
  pairs+=(3329-first<128?3329-first:128);blocks++;
 }
 assert(pairs==11082241ul);
 uint32_t state=0x6d237a1u;
 for(unsigned block=0;block<2000;block++){
  memset(guarded,0xa5,sizeof guarded);y[0]=y[257]=12345;memset(ref,0,sizeof ref);
  for(unsigned k=0;k<256;k++){
   state=state*1664525u+1013904223u;x[k]=(int16_t)(state%3329u);
   for(unsigned bit=0;bit<12;bit++)ref[(12*k+bit)/8]|=(uint8_t)(((unsigned)x[k]>>bit&1u)<<((12*k+bit)%8));
  }
  encode(guarded+1,x);decode(y+1,guarded+1);
  assert(!memcmp(x,y+1,sizeof x)&&!memcmp(ref,guarded+1,sizeof ref));
  assert(guarded[0]==0xa5&&guarded[385]==0xa5&&y[0]==12345&&y[257]==12345);
 }

 printf("codec_passed=1 canonical_pairs=%lu polynomial_blocks=%lu guarded_buffers=1 independent_bit_encoder=1 domain_checks=66560 mixed_polynomials=2000\n",pairs,blocks);
 return 0;
}
