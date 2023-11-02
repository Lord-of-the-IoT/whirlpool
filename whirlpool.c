#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "whirlpool.h"
//ported from whirlpool.cpp


whirlpool_instance *init_whirlpool_instance(void){
  whirlpool_instance *instance = malloc(sizeof(whirlpool_instance));
  //zeroes out all members
  instance->numblocks=0;
  memset(instance->CState, 0, 64);
  memset(instance->KState, 0, 64);
  memset(instance->HState, 0, 64);
  return instance;
}


whirlpool_instance *whirlpool_hash(char *digest){
  whirlpool_instance *instance = init_whirlpool_instance();
  whirlpool_pad_digest(instance, digest);
  return instance;
};


whirlpool_instance *whirlpool_block_cipher_w(whirlpool_instance *instance){
  int i=0;
  while (i<10){
    whirlpool_sub_bytes(instance);
    whirlpool_shift_collumns(instance);
    whirlpool_mix_rows(instance);
    whirlpool_add_round_constant(instance);
    whirlpool_add_key(instance);
    i++;
  }
  return instance;
};


whirlpool_instance *whirlpool_add_round_key(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_add_round_constant(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_add_key(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_sub_bytes(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_shift_collumns(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_mix_rows(whirlpool_instance *instance){
  return instance;
};


whirlpool_instance *whirlpool_pad_digest(whirlpool_instance *instance, char *digest){
  int dsize = 17; //strlen(instance->digest);
  int bits=dsize*8;

  printf("1 dsize = %i\n", dsize);
  printf("1 bits = %i\n\n", bits);
  if (!(bits%256) && !((bits/256)%2)){ //if bits are not an odd multiple of 256
    printf("1\n");
    bits+=512;
  }
  printf("2 bits = %i\n", bits);
  if (bits%256){ //if bytes are not an odd mutliple of 256
    printf("2\n");
    if (bits<256) bits=256; // if it is less than 256, bring to 256, the nearest block
    else bits+=256-bits%256; // else add the remainder to bring to closet 256
  }
  printf("3 bits = %i\n", bits);
  if (!(bits%256) || !((bits/256)%2)){ //if bytes are an odd mutliple of 256
    printf("3\n");
    bits+=256;
  }
  printf("4 bits = %i\n", bits);
  instance->numblocks = bits/256 + 1; //add one for final 256 bytes
  printf("4 numblocks = %i\n", instance->numblocks);
  instance->digest = malloc(bits+256);
  strcpy(instance->digest, digest);
  if((1<<((int8_t) log((double) (digest[dsize-1]&-digest[dsize-1])-1)>=1))){
    instance->digest[dsize-1] ^= 1<<((int8_t) log((double) (digest[dsize-1]&-digest[dsize-1])-1));
  }
  else{
    instance->digest[dsize] = (int8_t) 128;
  }
  int i=0;
  while (i<(bits+256)/8){
    printf("0x%x ", instance->digest[i]);
    i++;
  }
  return instance;
};


int8_t whirlpool_sbox(int8_t x){

};
