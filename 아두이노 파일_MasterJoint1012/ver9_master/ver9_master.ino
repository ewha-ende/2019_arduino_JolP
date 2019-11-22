#include <uECC.h>
#include <AES.h>
#include <stdarg.h>
#include <EEPROM.h>
AES aes ;
int mode = 1;

extern "C" {

int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently. 
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
    while (analogRead(0) == init) {
      ++count;
    }

    if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;

  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

} // extern "C"


void myprintf(char *fmt, ... ){
  char tmp[128]; // resulting string limited to 128 chars
  va_list args;
  va_start (args, fmt );
  vsnprintf(tmp, 128, fmt, args);
  va_end (args);
  Serial.print(tmp);
}

void dump(char *text, uint8_t *d, int leng) {
  int i;
  myprintf("%-20s", text);
  for (i = 0; i < leng; i++){
    if (i%16 == 0)
      Serial.print("\n\t");
    myprintf("%02x ", d[i]);
  }
  Serial.print("\n");
}

// AES

uint8_t my_iv[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
} ;


// generate a value between 0 <= x < n, thus there are n possible outputs
int rand_range(int n)
{
  int r, ul;
  ul = RAND_MAX - RAND_MAX % n;
  while ((r = random(RAND_MAX+1)) >= ul);
  //r = random(ul);
  return r % n;
}

void shuffle_swap(int index_a, int index_b, byte *array, int size)
{
  char *x, *y, tmp[size];

  if (index_a == index_b)
    return;

  x = (char*)array + index_a * size;
  y = (char*)array + index_b * size;

  memcpy(tmp, x, size);
  memcpy(x, y, size);
  memcpy(y, tmp, size);
}

// shuffle an array using fisher-yates method, O(n)
void shuffle(byte *array, int nmemb, int size, uint8_t seed)
{
  int r;
  // The index of sufffling seedNumber is predetermined
  // for the secret connection
  randomSeed((long)seed);
  Serial.print("shuffle seed : ");
  Serial.println ((long)seed,HEX) ;
  while (nmemb > 1) {
    r = rand_range(nmemb--);
    shuffle_swap(nmemb, r, array, size);
  }
}


void setup() {
  
  // Open serial communications and wait for port to open:
  uECC_set_rng(&RNG);
  Serial.begin(115200);
  
  // wait for serial port to connect. Needed for native USB port only
  while (!Serial) {
    ;
  }

  Serial.print("[ENDE]");
  Serial.print(" enter : mode keysize blocksize");
  Serial.println(" (ex: 1 24 16)");
  Serial.println("[mode : 0 => no padding, normal mode]");
  Serial.println("[mode : 1 => padding mode]\n");
  Serial.println("[keysize : 24 => secret key length : 192bits]");
  Serial.println("[keysize : 32 => secret key length : 256bits]\n");
  Serial.println("[blocksize : n => plain length : n*16 bytes]");
  Serial.println("[blocksize : 16, 32, 64]");
}

void loop() {

  if (Serial.available()) {
    
    // loop시작 알리기
    String start = Serial.readString();
    Serial.println(start);
    char cTempData[4];
    start.substring(0,1).toCharArray(cTempData,4);
    mode = atoi(cTempData);
    //Serial.println(mode);
    
    start.substring(2,4).toCharArray(cTempData,4);
    int KEY_SIZE = atoi(cTempData);
    //Serial.println(KEY_SIZE);
    
    start.substring(5,7).toCharArray(cTempData,4);
    int BLOCK_COUNT = atoi(cTempData);
    //int BLOCK_COUNT = 16;
    //Serial.println(BLOCK_COUNT);
    
    // select key size and block count
   // int KEY_SIZE = 24, BLOCK_COUNT = 2;
    const struct uECC_Curve_t * curve;
    if (KEY_SIZE == 24) {
      // select 192 bits key size (24 bytes)
      curve = uECC_secp192r1();
    }
    else {
      // select 256 bits key size (32 bytes)
      curve = uECC_secp256r1();
    }
    uint8_t private1[KEY_SIZE], private2[KEY_SIZE];
    uint8_t public1[KEY_SIZE*2], public2[KEY_SIZE*2];
    uint8_t secret1[KEY_SIZE], secret2[KEY_SIZE];
    
    
    Serial.println("=========================================================");
    Serial.print("<== Starting the ECDH key generation ==>\n");
    Serial.println("=========================================================");

    unsigned long a, b, c, d;
    int puleng, prleng, seleng, r1, r2;
    
    // public1, private1 생성
    a = micros();
    uECC_make_key(public1, private1, curve);
    b = micros();
    
    // public2, private2 생성
    c = micros();
    uECC_make_key(public2, private2, curve);
    d = micros();
    
    puleng = sizeof(public1) / sizeof(public1[0]);
    prleng = sizeof(private1) / sizeof(private1[0]);

    // 소요시간 출력
    Serial.print("ECDH generated key 1 in ");
    Serial.print(b-a); Serial.println(" uSec");
    Serial.print("ECDH generated key 2 in ");
    Serial.print(d-c); Serial.println(" uSec");

    // 키 출력
    Serial.println("=========================================================");
    Serial.print("<ECDH public key 1>");
    dump("", public1, puleng);
    Serial.print("<ECDH private key 2>");
    dump("", private1, prleng);
    Serial.println();
    Serial.print("<ECDH public key 1>");
    dump("", public2, puleng);
    Serial.print("<ECDH private key 2>");
    dump("", private2, prleng);
    Serial.println("=========================================================");

    // 공유 비밀키 생성 (master)
    a = micros();
    r1 = uECC_shared_secret(public2, private1, secret1, curve);
    b = micros();

    // 공유 비밀키 생성 (slave)
    c = micros();
    r2 = uECC_shared_secret(public1, private2, secret2, curve);
    d = micros();
    
    seleng = sizeof(secret1) / sizeof(secret1[0]);
    
    // 소요시간 출력
    Serial.print("ECDH Shared secret key 1 in ");
    Serial.print(b-a); Serial.println(" uSec");
    Serial.print("ECDH Shared secret key 2 in ");
    Serial.print(d-c); Serial.println(" uSec");

    if (!r1 || !r2) {
      Serial.print("shared_secret() failed (1)\n");
      return;
    }

    Serial.println("=========================================================");
    Serial.print("<ECDH shared secret key 1>");
    dump("", secret1, seleng);
    Serial.println();
    Serial.print("<ECDH shared secret key 2>");
    dump("", secret2, seleng);
    Serial.println("=========================================================");

    // EEPROM에 키 저장 (~4096 bytes)
    for(byte i = 0; i < 24; i++){
      EEPROM.write(i, secret1[i]);
    }
    Serial.println("Completed saving the secret key to EEPROM.");

    if(mode == 1)
      prekey(KEY_SIZE*8,BLOCK_COUNT);
    else
      prekey(256,BLOCK_COUNT);
    //prekey(192,1);
    //prekey(192,2);
    //prekey(192,8);
  }
  
}

void prekey (int bits, int blocks)
{
  uint8_t plain[blocks*N_BLOCK], check[blocks*N_BLOCK];
  uint8_t cipher [blocks*N_BLOCK];
  uint8_t key[bits/8], shuffled_key[bits/8];
  uint8_t shuffle_seed1[blocks*N_BLOCK], shuffle_seed2[blocks*N_BLOCK];
  byte iv [N_BLOCK];
  unsigned long t0, t1, t2, t3;
  int keyleng = sizeof(key) / sizeof(key[0]);
  int pleng = sizeof(plain) / sizeof(plain[0]);
  int chkleng = sizeof(check) / sizeof(check[0]);
  int cleng = sizeof(cipher) / sizeof(cipher[0]);
  int seedleng = sizeof(shuffle_seed1) / sizeof(shuffle_seed1[0]);

  // shuffle seed 설정
  for (byte i = 0; i < 7; i++) {
    shuffle_seed1[i] = 65 + i;
  }

  for (byte i = 0 ; i < keyleng ; i++) {
    key[i]=EEPROM.read(i);
  }

  Serial.println("\n\n");
  Serial.print("* Block Count : ");
  Serial.println(blocks);
  Serial.println("=========================================================");
  Serial.println("<==== AES with ECDH shared key ====>");
  t0 = micros() ;
  byte succ = aes.set_key (key, bits) ; //key bit length
  t1 = micros();
  Serial.println("=========================================================");
  Serial.print("<AES key from ECDH shared key>");
  dump("", key, keyleng);

  Serial.print("  > set_key "); Serial.print(bits);
  Serial.print(" -> ") ; Serial.print((int) succ==0?"Done":"Fail") ;
  Serial.print(" time "); Serial.print(t1-t0); Serial.println(" uSec");
  Serial.println("=========================================================");

  // seed 암호화
  t0 = micros () ;
  if (blocks == 1)
    succ = aes.encrypt (shuffle_seed1, cipher) ;
  else {
    for (byte i = 0; i < 16; i++) {
      iv[i] = my_iv[i] ;
    }
    succ = aes.cbc_encrypt (shuffle_seed1, cipher, blocks, iv) ;
  }
  t1 = micros () ;

  Serial.print("\n<plain (shuffle seed1)>");
  dump("", shuffle_seed1, seedleng);
  Serial.println();
  Serial.print("  > Encryption "); Serial.print((int) succ == 0? "Done":"Fail");
  Serial.print(" time "); Serial.print(t1-t0); Serial.println(" uSec");
  Serial.println();
  Serial.print("\n<cipher (shuffle seed1)>");
  dump("", cipher, 16);

  // seed 복호화
  t2 = micros () ;
  if (blocks == 1)
    succ = aes.decrypt (cipher, shuffle_seed2) ;
  else {
    for (byte i = 0; i < 16; i++){
      iv[i] = my_iv[i] ;
    }
    succ = aes.cbc_decrypt (cipher, shuffle_seed2, blocks, iv) ;
  }
  t3 = micros () ;
  
  Serial.println();
  Serial.print("  > Decryption "); Serial.print((int) succ == 0? "Done":"Fail");
  Serial.print(" time "); Serial.print(t3-t2); Serial.println (" uSec");
  Serial.println();
  Serial.print("\n<check (shuffle seed2)>");
  dump("", shuffle_seed2, seedleng);
  Serial.println("=========================================================");

if(mode == 2){
  //조작시작
  randomSeed((long)shuffle_seed1[1]);
  
  for(int i =0; i<8; i++) {
    key[i+24] = rand_range(256);
    EEPROM.write(i+24, key[i+24]);
  }
  
} 


  // ========================== AES Key Shuffling =========================
  for(int mm=0; mm <4; mm++){
    shuffle(key, keyleng, sizeof(byte), shuffle_seed2[mm]);
    //Serial.print("    AES key After Shuffling");
    //dump("", key, keyleng);
    //Serial.println();

    for (byte i = 0 ; i < keyleng; i++) {
      EEPROM.write(i+mm*keyleng, key[i]);
    }
  }
  
  double sum1 = 0, sum2 = 0;
  // 평문 암/복호화
  for(int mmm=0;mmm<4;mmm++) {

    // 키 설정
    for(int i=0;i< keyleng; i++) {
      shuffled_key[i] = EEPROM.read(i+(mmm%4)*keyleng);
    }

    // 메세지 설정
    for(int i=0; i<pleng; i++){
      int arduino_a0_value=analogRead(A0);
      plain[i] = map(arduino_a0_value,0,1023,0,255); // data reading from analog port A0
      plain[i] = (plain[i] + rand_range(255))*2/5;
    }


    Serial.println("\n=========================================================");
    myprintf("<==%2d ==> Message Encryption with shuffled AES key \n", mmm);
    Serial.println("=========================================================");
    Serial.print("<Shuffled AES key>");
    dump("", shuffled_key,keyleng);
    t0 = micros () ;
    byte succ_shuffle = aes.set_key (shuffled_key, bits) ;
    t1 = micros() ;
    Serial.print("  > set_key "); Serial.print(bits); Serial.print(" -> ");
    Serial.print((int) succ_shuffle == 0? "Done":"Fail");
    Serial.print(" time "); Serial.print(t1-t0); Serial.println(" uSec");
    Serial.println("=========================================================");

    
    // 암호화
    t0 = micros () ;
    if (blocks == 1)
      succ = aes.encrypt (plain, cipher) ;
    else {
      for (byte i = 0; i < 16; i++) {
        iv[i] = my_iv[i] ;
      }
      succ = aes.cbc_encrypt (plain, cipher, blocks, iv) ;
    }
    t1 = micros () ;

    sum1 = sum1 + t1 - t0;
    
    Serial.print("\n<plain (message)>");
    dump("", plain, pleng);
    Serial.println();
    Serial.print("  > Encryption "); Serial.print((int) succ == 0? "Done":"Fail");
    Serial.print(" time "); Serial.print(t1-t0); Serial.println(" uSec");
    Serial.println();
    Serial.print("\n<cipher (message)>");
    dump("", cipher, cleng);
    

    // 복호화
    t2 = micros () ;
    if (blocks == 1)
      succ = aes.decrypt (cipher, check) ;
    else {
      for (byte i = 0; i < 16; i++) {
        iv[i] = my_iv[i] ;
      }
      succ = aes.cbc_decrypt (cipher, check, blocks, iv) ;
    }
    t3 = micros () ;

    sum2 = sum2 + t3 - t2;
    
    Serial.println();
    Serial.print("  > Decryption "); Serial.print((int) succ == 0? "Done":"Fail");
    Serial.print(" time "); Serial.print(t3-t2); Serial.println (" uSec");
    Serial.println();
    Serial.print("\n<check (message)>");
    dump("", check, chkleng);
    Serial.println("=========================================================");
    
    Serial.print("<");
    Serial.print(mmm);
    Serial.println("번째>");
    Serial.print("plain : ");
    
    for(int i=0; i<pleng; i++){
      if(i%32 == 0 && i != 0)
        Serial.print("\n\t");
      else
        Serial.print(" ");
      Serial.print((char) plain[i]);
    }

    Serial.print("\ncheck : ");
    for(int i=0; i<chkleng; i++){
      if(i%32 == 0 && i != 0)
        Serial.print("\n\t");
      else
        Serial.print(" ");
      Serial.print((char) plain[i]);
    }
    

  }
  Serial.println("\n=========================================================");
  Serial.print("total time (EN, Plain ");
  Serial.print(blocks * 16);
  Serial.print("bytes) : ");
  Serial.println(sum1/4);
  Serial.print("total time (DE, Plain ");
  Serial.print(blocks * 16);
  Serial.print("bytes) : ");
  Serial.print(sum2/4);
  Serial.println("\n=========================================================");
}
