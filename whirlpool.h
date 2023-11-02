int8_t ebox[16]={0x1,0xb,0x9,0xc,0xd,0x6,0xf,0x3,0xe,0x8,0x7,0x4,0xa,0x2,0x5,0x0}; //e mini box for mix rows
int8_t eboxinv[16]={0xf,0x0,0xd,0x7,0xb,0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4, 0x8, 0x6}; //e-1 mini box for mix rows
int8_t rbox[16]={0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0}; //r mini box for mix rows
int8_t TransformationMatrix[8][8] = {
  {1,1,4,1,8,5,2,9},
  {9,1,1,4,1,8,5,2},
  {2,9,1,1,4,1,8,5},
  {5,2,9,1,1,4,1,8},
  {8,5,2,9,1,1,4,1},
  {1,8,5,2,9,1,1,4},
  {4,1,8,5,2,9,1,1},
  {1,4,1,8,5,2,9,1}
}; //transformation matrix for mixrows

struct whirlpool_instance{
  int8_t *digest; //plaintext provided
  int8_t digest_section[64]; //digest of hash
  int8_t IV[16]; //initialisation vector
  int8_t CState[8][8];
  int8_t KState[8][8];
  int8_t HState[8][8];
  int numblocks;
};  //contains variables needed for hashing of digest

typedef struct whirlpool_instance whirlpool_instance; //allows for emmission of struct
whirlpool_instance *init_whirlpool_instance(void); //allocates and initialises a whirlpool_instance struct
whirlpool_instance *whirlpool_hash(char *digest); //main algorithm for hashing
whirlpool_instance *whirlpool_block_cipher_w(whirlpool_instance *instance);
whirlpool_instance *whirlpool_add_round_key(whirlpool_instance *instance);
whirlpool_instance *whirlpool_add_round_constant(whirlpool_instance *instance);
whirlpool_instance *whirlpool_add_key(whirlpool_instance *instance);
whirlpool_instance *whirlpool_sub_bytes(whirlpool_instance *instance);
whirlpool_instance *whirlpool_shift_collumns(whirlpool_instance *instance);
whirlpool_instance *whirlpool_mix_rows(whirlpool_instance *instance);
whirlpool_instance *whirlpool_pad_digest(whirlpool_instance *instance, char *digest);
int8_t whirlpool_sbox(int8_t x); //sbox algorithm for whirlpool_mix_rows
