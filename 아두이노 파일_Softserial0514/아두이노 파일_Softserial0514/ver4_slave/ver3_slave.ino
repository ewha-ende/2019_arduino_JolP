#include <uECC.h>
#include <AES.h>
#include <stdarg.h>
#include <EEPROM.h>
#define NUM_ECC_DIGITS 24
AES aes ;

#include <SoftwareSerial.h>

SoftwareSerial mySerial(10, 11); // RX, TX

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
  for (i = 0; i < leng; ++i){
    myprintf("%02x ", d[i]);
    if (i != 0 && i%24 == 0)
      Serial.print("\n\t\t");
  }
  Serial.print("\n");
}

// AES
uint8_t key[24] =
{
0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} ;

uint8_t shuffled_key[24] =
{
0x80, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} ;

uint8_t plain[] =
{
0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba, 0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2, 0x73, 0xe6,
0x00, 0x00, 0x00, 0x00, 0x3c, 0xc6, 0x27, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xC0, 0x3c, 0xc6, 0x27, 0xba, 0x00, 0x00, 0x3c, 0xc6, 0x27, 0xba, 0x3c, 0xc6, 0x27, 0xba, 0xe6,
0xE0, 0x00, 0x00, 0x00, 0x00, 0x3c, 0xc6, 0x27, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0xc6, 0x27, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00,
} ;
uint8_t shuffle_seed[] =
{
0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};
uint8_t my_iv[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
} ;

uint8_t cipher [4*N_BLOCK] ;
uint8_t check [4*N_BLOCK] ;

uint8_t private2[24];

uint8_t public1[48], public2[48];

uint8_t secret2[24];


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
void shuffle(byte *array, int nmemb, int size)
{
  int r;
  // The index of sufffling seedNumber is predetermined
  // for the secret connection
  randomSeed((long)shuffle_seed[5]);
  Serial.print("shuffle seed : ");
  Serial.println ((long)shuffle_seed[5],HEX) ;
  while (nmemb > 1) {
    r = rand_range(nmemb--);
    shuffle_swap(nmemb, r, array, size);
  }
}


void setup() {
// Open serial communications and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  Serial.println("Goodnight moon!");

  // set the data rate for the SoftwareSerial port
  mySerial.begin(9600);
//  mySerial.println("Hello, world?");
  
  uECC_set_rng(&RNG);
  Serial.print("public key length : ");
  Serial.println(sizeof(public2) / sizeof(public2[0]));
  int ivleng = (sizeof(my_iv) / sizeof(my_iv[0]));
  Serial.print("iv length : ");
  Serial.println(ivleng);
  dump("my iv : ", my_iv, ivleng);
}

void loop() {

  Serial.flush();
  mySerial.flush();

  if (Serial.available()) {
    
    // loop시작 알리기
    String s = Serial.readString();
    Serial.println(s);
Serial.println("=====================================================================================================");
Serial.println("=====================================================================================================");
Serial.print("<== Starting the ECDH key generation ==>\n");
Serial.println("=====================================================================================================");

const struct uECC_Curve_t * curve = uECC_secp192r1(); // select 192 bits key size (24 bytes)
unsigned long a = micros();
uECC_make_key(public2, private2, curve);
unsigned long b = micros();
int puleng = sizeof(public2) / sizeof(public2[0]);
int prleng = sizeof(private2) / sizeof(private2[0]);

Serial.print("ECDH generated key 2 in ");
Serial.print(b-a);Serial.println(" uSec");
dump("ECDH public key 2=>", public2, puleng);
dump("ECDH private key 2=>", private2, prleng);

// 통신 : public2를 보내고 public1을 받아야 함.
  //mySerial.flush();
  for (int i = 0; i < puleng; i++){ 
    mySerial.write(public2[i]);
  }
  while(mySerial.available()<puleng){
    // wait
  }

mySerial.readBytes(public1, puleng);

a = micros();
int r = uECC_shared_secret(public1, private2, secret2, curve);
b = micros();
int seleng = sizeof(secret2) / sizeof(secret2[0]);
Serial.println("=====================================================================================================");
Serial.print("ECDH Shared secret key 2 in "); Serial.print(b-a);Serial.println(" uSec");
if (!r) {
Serial.print("shared_secret() failed (2)\n");
return;
}

Serial.println("=====================================================================================================");
dump("ECDH public key 1=>", public1, puleng);
dump("ECDH public key 2=>", public2, puleng);
dump("ECDH shared secret key 2=> ", secret2, seleng);
Serial.println("=====================================================================================================");

//
Serial.print("buf : +");
Serial.println(mySerial.available());

for(byte i=0;i<24;i++) key[i]=secret2[i];
//prekey(192,1);
prekey(192,2);
//prekey(192,3);
  }
}

void prekey (int bits, int blocks)
{
byte iv [N_BLOCK] ;
int myivleng = sizeof(my_iv) / sizeof(my_iv[0]);

Serial.println("\n<==== AES with ECDH shared key ====>");
unsigned long t0 = micros() ;
byte succ = aes.set_key (key, bits) ; //key bit length
unsigned long t1 = micros();
int keyleng = sizeof(key) / sizeof(key[0]);
Serial.println("=====================================================================================================");
dump("AES key from ECDH shared key ", key, keyleng);
Serial.println("=====================================================================================================");

Serial.print ("set_key ") ; Serial.print (bits) ;
Serial.print (" ->") ; Serial.print ((int) succ==0?"Done":"Fail") ;
Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;

// seed 받기
  mySerial.flush();
  int cleng = sizeof(cipher) / sizeof(cipher[0]);
  int seedleng = sizeof(shuffle_seed) / sizeof(shuffle_seed[0]);
  Serial.print("cipher length : ");
  Serial.println(cleng);
  Serial.print("seed length : ");
  Serial.println(seedleng);
  while(mySerial.available()<cleng/2){
    // wait
  }

mySerial.readBytes(cipher, cleng);

// seed 복호화
t0 = micros () ;
if (blocks == 1)
  succ = aes.decrypt (cipher, shuffle_seed) ;
else {
  for (byte i = 0 ; i < 16 ; i++)
    iv[i] = my_iv[i] ;
  succ = aes.cbc_decrypt (cipher, shuffle_seed, blocks, iv) ;
}
t1 = micros () ;
Serial.print ("Decryption ") ; Serial.print ((int) succ==0?"Done":"Fail") ;
Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;

//
Serial.print("buf : +");
Serial.println(mySerial.available());

dump("cipher : ", cipher, cleng);
dump("shuffle_seed : ", shuffle_seed, seedleng);
dump("iv : ", iv, 16);


//======================== AES Key Shuffling ======================

dump("AES key Before Shuffling\n", key , keyleng);
shuffle(key, 24, sizeof(byte));
dump("AES key After Shuffling\n", key, keyleng);


for (byte i = 0 ; i < 24 ; i++) {
  shuffled_key[i] = key[i] ;
  EEPROM.write(i, shuffled_key[i]);
}

byte e;
Serial.print("EEPROM : ");
for (byte i = 0; i < 24; i++){
  e = EEPROM.read(i);
  Serial.print(e, HEX);
  Serial.print(" ");
}
Serial.println();

for(int mmm=0;mmm<3;mmm++) {
  // 뭐하는 코드지? 평문 채우는 거같은데,,, 잘모르겠어
  for(int i=0;i< 24; i++) {
    int arduino_a0_value=analogRead(A0);
    plain[i]=map(arduino_a0_value,0,1023,0,255); // data reading from analog port A0
  }
  myprintf("\n <==%2d ==> Message Decryption with shuffled AES key \n", mmm);
  Serial.println("=====================================================================================================");
  dump("Shuffled AES key=>", shuffled_key,keyleng);
  Serial.println("=====================================================================================================");
  t0 = micros () ;
  byte succ_shuffle = aes.set_key (shuffled_key, bits) ;
  t1 = micros() ;
  Serial.print ("set_key ") ; Serial.print (bits) ; Serial.print (" ->") ; Serial.print ((int) succ_shuffle==0?"Done":"Fail");
  Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;

  // ciper 수신
  //int cleng = 32;
  mySerial.flush();
  Serial.print("cipher length : ");
  Serial.println(cleng);
  while(mySerial.available()<cleng/2){
    // wait
  }
  mySerial.readBytes(cipher, cleng);

  t0 = micros () ;
  if (blocks == 1)
    succ = aes.decrypt (cipher, plain) ;
  else {
    for (byte i = 0 ; i < 16 ; i++)
      iv[i] = my_iv[i] ;
    succ = aes.cbc_decrypt (cipher, plain, blocks, iv) ;
  }
  t1 = micros () ;

Serial.print ("decrypt ") ; Serial.print ((int) succ==0?"Done":"Fail") ;
Serial.print (" took ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;
    
  int pleng = sizeof(plain) / sizeof(plain[0]);
  dump("cipher : ", cipher, cleng);
  dump("plain : ", plain, pleng);
    /*
        for (byte ph = 0 ; ph < (blocks == 1 ? 3 : 4) ; ph++) {
          for (byte i = 0 ; i < (ph < 3 ? blocks*N_BLOCK : N_BLOCK) ; i++) {
            byte val = ph == 0 ? plain[i] : ph == 1 ? cipher[i] : ph == 2 ? check[i] : iv[i] ;
            Serial.print (val>>4, HEX) ; Serial.print (val&15, HEX) ; Serial.print (" ") ;
          }
        Serial.println () ;
      }
*/
}

}
