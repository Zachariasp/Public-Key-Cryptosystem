/**
   Zacharias Shufflebarger
   CS 427
   Project 2
**/
#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h> //open mode constants

#define PRIME 1
#define COMPOSITE 0
#define _bit 0x1 //   a bit
#define _byte 0x8 //  8 bits
#define _block 0x4 // 4 bytes

// 2^31 = 2,147,483,648 - choose primes larger than this
#define MIN_PRIME 2147483648 
// largest int is 4,294,967,295 - choose primes smaller than this
// 2,147,483,648 < p < 4,294,967,295
#define MAX_INT 4294967295


const char* ptextin     = "ptext.txt";
const char* ptextout    = "ptext.out";
const char* ctextin     = "ctext.txt";
const char* ctextout    = "ctext.out";
const char* pubkeyfile  = "pubkey.txt";
const char* prikeyfile  = "prikey.txt";
// for testing purposes. These primes all have the high-bit set.
const int primes[12] = {2685457421,2576983867,2360739643,2149686127,
			3121238909,3669829403,3978735073,3449943869,
			4000846301,4111485199,4222234741,4293184081};

/**
   Using this function, I can select a new pseudorandom generator and it will
   propagate to all calls to the pseudorandom number generator.
 */
unsigned int p2_rand(){
  unsigned int a = (unsigned int) rand();
  return a;
}


/**
   returns a random number with the second highest bit set.
 */
unsigned int rand_31bit(){
  unsigned int a = p2_rand() | (0x1<<30);
  return a;
}


/**
   returns a random number with the high bit set. 
 */
unsigned int rand_32bit(){
  unsigned int a = p2_rand() | (0x1<<31);
  return a;
}


/**
   print_bits prints the binary representation of the given number a.
   Assumes a 32-bit unsigned int as input.
 */
void print_bits(unsigned int a){
  unsigned int b = 0x0;

  for(int i = 0; i < 32; i++){
    b = a & (_bit << (31 -i)); // isolate the ith bit from the MSB in a
    b >>= (31 - i); // shift whatever it is to the LSB.
    //                 This way b is only ever 1 or 0.
    printf("%u", b); 
  }
  printf("\n");
}


/**
   Load 4 characters into a 32-bit block from a buffer, 
   zero-fill if less than 4 characters are in the buffer.
   For use on reading the plaintext.
 */
void load_block(unsigned int *a, char* buff){
  *a <<= _byte;
  if(buff != NULL){
    *a |= buff[0];
  }
  *a <<= _byte;
  if(buff+1 != NULL){
    *a |= buff[1];
  }
  *a <<= _byte;
  if(buff+2 != NULL){
    *a |= buff[2];
  }
  *a <<= _byte;
  if(buff+3 != NULL){
    *a |= buff[3];
  }
}


/**
   This function takes four integer pointers which will be returned with the
   file descriptors for the plaintext, ciphertext, public key, and private key.
   Lastly, the mode flag will tell the function which files it needs to 
   (re)create. Encrypt = 1, Decrypt = 0, Generate Keys = -1.
   Returns 0 for success and -1 for flag failure.
*/
int openfiles(int* ptfd, int* ctfd, int* pubkeyfd, int* prikeyfd, int flag){
  int rflag = O_RDONLY;
  int wflag = O_WRONLY | O_CREAT | O_TRUNC;
  int mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
  if(flag == 0){ // decrypt
    *ptfd = open(ptextout, wflag, mode);
    *ctfd = open(ctextin, rflag, mode);
    *pubkeyfd = open(pubkeyfile, rflag, mode);
    *prikeyfd = open(prikeyfile, rflag, mode);
  } else if (flag == 1){ // encrypt
    *ptfd = open(ptextin, rflag, mode);
    *ctfd = open(ctextout, wflag, mode);
    *pubkeyfd = open(pubkeyfile, rflag, mode);
    *prikeyfd = open(prikeyfile, rflag, mode);
  } else if (flag == -1){ // generate
    *ptfd = open(ptextout, rflag, mode);
    *ctfd = open(ctextout, rflag, mode);
    *pubkeyfd = open(pubkeyfile, wflag, mode);
    *prikeyfd = open(prikeyfile, wflag, mode);
  } else { return -1; } // bad flag
  if(*ptfd < 0){ perror("Error openning ptext.txt"); exit(-1); }
  if(*ctfd < 0){ perror("Error openning ctext.txt"); exit(-1); }
  if(*pubkeyfd < 0){ perror("Error openning pubkey.txt"); exit(-1); }
  if(*prikeyfd < 0){ perror("Error openning prikey.txt"); exit(-1); }
  return 0;

}


/**
   Read 4 characters from the file plaintext file and place their binary 
   values into the block m.
 */
int read_bits(unsigned int *m, int fd){
  // alloc four 8 byte chars
  int n;
  unsigned char* buff = (unsigned char*)calloc(_block,sizeof(char)); 
  if( (n = read(fd, buff, _block)) < 0 ){
    perror("Reading File: ");
  }
  if( n == 0 ){ *m = 0; return n; } // don't append an empty block.
  load_block(m, buff);
  return n;
}


/**
   read ciphertext number pairs into the buffer.
 */
int read_numpairs(char* buffer, int fd){
  int c1_found = 0, c2_found = 0, n = 0;
  char* byte_buffer = (char*) calloc(2, sizeof(char));
  while( (n += read(fd, byte_buffer, 1)) ){ //until c1 and c2 are found...
    if(strcmp(byte_buffer, " ") == 0){
      if(c1_found){
	c2_found = 1;
	break;
      } else {
	c1_found = 1;
      }
    }
    // read will return 1 if it reads the null terminator, so decrement n.
    if( strlen(byte_buffer) == 0 ){ n--; break; } 
    strcat(buffer, byte_buffer);
    memset(byte_buffer,0,2);
  }
  return n;
}


/**
   get the generator e1, selected random e2, and the prime p 
   from the public key.
 */
void read_pubkey(unsigned int* e1, unsigned int* e2,
		unsigned int* p, int fd){
  
  char* buff = (char*) calloc(256, sizeof(char));
  if( read(fd, buff, 255) < 0 ){
    perror("Reading Public Key File: ");
  }
  sscanf(buff, "%u %u %u", e1, e2, p);
}


/**
   get the selected random d from the private key.
 */
void read_prikey(unsigned int* d, int fd){
  char* buff = (char*) calloc(256, sizeof(char));
  if( read(fd, buff, 255) < 0 ){
    perror("Reading Private Key File: ");
  }
  sscanf(buff, "%u", d);
}


/**
   straight up ripped from pseudocode found here: 
     https://en.wikipedia.org/wiki/Modular_exponentiation
     + changed int to unsigned int.
     + changed base to 64 bit long

   This is the Right-to-Left binary method of the modular exponentiation 
   algorithm. Given the base, exponent, and modulus. This function returns 
   the remainder of b^e mod m.
 */
unsigned int modular_pow(unsigned int b_ui, unsigned int exp, unsigned int mod){
  // base needs to be large enough to handle max_int^2,
  // so calculations use a 64-bit long to prevent overflow if b_ui is large
  unsigned long long base = b_ui; 
  if( mod == 1) return 0;
  unsigned long long rem = 1;
  base = base % mod;
  while( exp > 0 ){
    if ( exp % 2 == 1){
      rem = (rem * base) % mod;
    }
    exp >>= 1;
    base = (base * base) % mod;
  }
  return (unsigned int) rem;
}


/**
   find k and q for Miller-Rabin. 
 */
int find_kq(unsigned int prime, unsigned int* k, unsigned int* q){
  
  for(int i = 31; i >= 0; i--){
    unsigned int pow2 = 0x1 << i; //2^k
    *k = i;
    if( pow2 > prime ) continue;
    *q = (prime-1)/pow2;
    if( (*q)*pow2 == (prime-1) ) return 1;
  }
  return 0;
}


/**
   this is the actual Miller-Rabin test, but it is used in the MRPrimeTest.
 */
int test_helper( unsigned int a, unsigned int n ){
  unsigned int a_to_power, i, k, q;
  find_kq(n, &k, &q); 
  a_to_power = modular_pow(a, q, n);
  if (a_to_power == 1) return PRIME;
  if(k){
    for(i = 0; i < k-1; i++){
      if(a_to_power == n-1) return PRIME;
      a_to_power = modular_pow(a_to_power, 2, n);
    }
  }
  if (a_to_power == n-1) return PRIME;
  return COMPOSITE;
}


/**
   Adapted from http://en.literateprograms.org/Miller-Rabin_primality_test_(C)
   along with the test_helper function above.

   Miller-Rabin test for primality
   n = number to test for primality
   return 0 for composite, 1 for probably prime, -1 for error.
 */
int MRPrimeTest(unsigned int n){

  if (n <= 1) return 0;
  if (n == 2) return 1;
  
  // test that n mod 12 = 5 and that the Miller-Rabin test returns 'prime' for
  // a = 2, 7, and 61. These numbers from the alogrithm found online and are
  // cited there to deterministically prove a 32-bit number to be prime.
  if ((test_helper(2, n) == PRIME) &&
      (n <= 7  || test_helper(7, n) == PRIME) &&
      (n <= 61 || test_helper(61, n) == PRIME)){
    return PRIME;
  } else {
    return COMPOSITE;
  }

}


/**
   helper to safe_prime(), finds a 31-bit prime number.
 */
unsigned int rand_31bit_prime(){
  unsigned int isprime = 0,q;
  do{
    q = rand_31bit();
    if (modular_pow(q,1,12) != 5){continue;}
    isprime = MRPrimeTest(q);
  }while(isprime != PRIME);
  return q;  
}


/**
   find a safe 32-bit prime (from slides) for key generation.
 */
unsigned int safe_prime(){
  unsigned int isprime = 0,p,q;
  do{
    q = rand_31bit_prime();
    p = (2 * q) + 1;
    isprime = MRPrimeTest(p);
  }while(isprime != PRIME);
  return p;
}


/**
   encrypt a single block P.
 */
unsigned int* encrypt (unsigned int e1, unsigned int e2,
		       unsigned int p, unsigned int P){
  unsigned int r = p2_rand();
  unsigned int c1 = modular_pow(e1,r,p);
  // below: ab mod p = (a mop p * b mod p) mod p
  unsigned int rem1 = modular_pow(P,1,p);
  unsigned int rem2 = modular_pow(e2,r,p);
  // convert rems to longs to safely multiply
  long long place_holder = ((long long) rem1) * ((long long) rem2);
  unsigned int c2 = (place_holder) % p;
  unsigned int* C = (unsigned int*) calloc(2,sizeof(unsigned int));
  C[0] = c1; C[1] = c2;
  return C;
}

/**
   encrypt a message one block at a time.
 */

void encrypt_message(int plnfd, int cphrfd, int pubkfd, int prikfd){
  unsigned int m,e1,e2,p,d,readable = 1;
  read_pubkey(&e1,&e2,&p,pubkfd);
  read_prikey(&d, prikfd);
  while(readable){
    int n = read_bits(&m, plnfd);
    if (n < _block){ readable = 0; } // if last block was read, finish up.
    if (n == 0){ break; }
    unsigned int* C = encrypt(2,e2,p,m);
    // largest ciphers will be 10 digits.
    // 2 of them plus two spaces and a null term = 23 characters.
    char* cbuff = (char*) calloc(23,sizeof(char));
    sprintf(cbuff,"%u %u ", C[0], C[1]);
    write(cphrfd, cbuff, strlen(cbuff));
  }
}


/**
   convert block m into 4 8-bit characters.
 */
char* convert_m(unsigned int m){
  char* buffer = (char*) calloc(_block,sizeof(char)); //[_block];
  buffer[0] = (m & 0xff000000) >> 24;
  buffer[1] = (m & 0x00ff0000) >> 16;
  buffer[2] = (m & 0x0000ff00) >>  8;
  buffer[3] = (m & 0x000000ff);
  return buffer;
}


/**
   decrypt a ciphertext number pair.
 */
unsigned int decrypt(unsigned int C1, unsigned int C2,
	      unsigned int d, unsigned int p){
  
  unsigned int rem1 = modular_pow(C1,p-1-d,p);
  unsigned int rem2 = modular_pow(C2,1,p);
  long long place_holder = ((long long) rem1) * ((long long) rem2);
  unsigned int m = place_holder % p;
  return m;
}

/**
   decrypt an entire message one number pair at a time.
 */
void decrypt_message(int plnfd, int cphrfd, int pubkfd, int prikfd){
  unsigned int m,e1,e2,p,d,readable = 1;
  read_pubkey(&e1,&e2,&p,pubkfd);
  read_prikey(&d, prikfd);
  while(readable){
    char* buffer = (char*) calloc(256, sizeof(char));
    int n = read_numpairs(buffer, cphrfd);
    if(n == 0){
      readable = 0;
      break;
    }
    unsigned int C1, C2;
    sscanf(buffer, "%u %u", &C1, &C2);
    m = decrypt(C1, C2, d, p);
    char* mbuff = convert_m(m);
    write(plnfd, mbuff, strlen(mbuff));
    memset(buffer,0,strlen(buffer));
  }
}


/**
   Generate the public and private keys.
 */
void keygen(int pubkfd, int prikfd){
  unsigned int p = safe_prime();
  unsigned int d;
  while(1){
    d = p2_rand();
    if( d >= 1 && d <= p - 2){ break; }
  }
  unsigned int e1 = 2; //congruent with safe prime generator
  unsigned int e2 = modular_pow(e1,d,p);
  char* pubbuff = (char*) calloc(256,sizeof(char));
  char* pribuff = (char*) calloc(256,sizeof(char));
  sprintf(pubbuff, "%u %u %u",e1, e2, p);
  write(pubkfd,pubbuff,strlen(pubbuff));
  sprintf(pribuff, "%u",d);
  write(prikfd,pribuff,strlen(pribuff));
}


/**
   Call this program using one command line argument:
   -g selects the key generation, which writes to pubkey.txt and prikey.txt.
   -e selects encryption, which reads from the key files and ptext.txt,
        it writes to ctext.out
   -d selects decryption, which reads from the key files and ctext.txt,
        it writes to ptext.out.
 */
int main (int argc, char* argv[]){
  int plnfd, cphrfd, pubkfd, prikfd, mode;
  if(argc == 1){
    printf("Usage: Please supply a command line flag.\n");
    printf("-d  decrypt\n-e  encrypt\n-g  generate keys\n");
    return -1;
  }
  if(argc > 1){
    if( strcmp(argv[1],"-g") == 0 ){ mode = -1; }
    if( strcmp(argv[1],"-d") == 0 ){ mode =  0; }
    if( strcmp(argv[1],"-e") == 0 ){ mode =  1; }
  }
  if(openfiles(&plnfd, &cphrfd, &pubkfd, &prikfd, mode) < 0){
    printf("Usage: valid flags: -d, -e, -g\n");
  }
  srand(10);
  if(mode == -1){keygen(pubkfd,prikfd);}
  if(mode ==  0){decrypt_message(plnfd, cphrfd, pubkfd, prikfd);}
  if(mode ==  1){encrypt_message(plnfd, cphrfd, pubkfd, prikfd);}
  return 0;
}
