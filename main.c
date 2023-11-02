#include <stdio.h>
#include "whirlpool.c"

int main(void){
  char *message = "why hello how are you today";
  whirlpool_hash(message);
  return 0;
}
