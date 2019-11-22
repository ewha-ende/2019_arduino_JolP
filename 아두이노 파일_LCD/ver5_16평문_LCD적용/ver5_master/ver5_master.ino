#include <uECC.h>
#include <AES.h>
#include <stdarg.h>
#include <EEPROM.h>
#define NUM_ECC_DIGITS 24
AES aes ;
#include <Wire.h> 
#include <LiquidCrystal_I2C.h>
#include <SoftwareSerial.h>

SoftwareSerial mySerial(10, 11); // RX, TX
LiquidCrystal_I2C lcd(0x27,16,2);  // set the LCD address to 0x27 for a 16 chars and 2 line display

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

uint8_t plain[] =
{
0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba, 0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2, 0x73, 0xe6,


} ;
uint8_t shuffle_seed[] =
{
0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};
uint8_t my_iv[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
} ;

uint8_t cipher [1*N_BLOCK] ;
uint8_t check [1*N_BLOCK] ;




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
void shuffle(byte *array, int nmemb, int size, int seedIndex)
{
  int r;
  // The index of sufffling seedNumber is predetermined
  // for the secret connection
  randomSeed((long)shuffle_seed[seedIndex]);
  Serial.print("shuffle seed : ");
  Serial.println ((long)shuffle_seed[seedIndex],HEX) ;
  while (nmemb > 1) {
    r = rand_range(nmemb--);
    shuffle_swap(nmemb, r, array, size);
  }
}


void setup() {
// Open serial communications and wait for port to open:
  Serial.begin(57600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  Serial.println("[ENDE]");

  // set the data rate for the SoftwareSerial port
  mySerial.begin(57600);
//  mySerial.println("Hello, world?");
  
  uECC_set_rng(&RNG);

  // initialize the lcd 
  lcd.init();                      
  lcd.clear();
  // Print a message to the LCD.
  lcd.backlight();
  lcd.setCursor(0,0);
  lcd.print("Arduino Project");
  lcd.setCursor(0,1);
  lcd.print("> ENDE");

}

void loop() {
  

   Serial.flush();
  mySerial.flush();

  if (Serial.available()) {
    uint8_t private1[24];

    uint8_t public1[48], public2[48];

    uint8_t secret1[24];
    
    // loop시작 알리기
    String s = Serial.readString();
    Serial.println(s);
    mySerial.write(1);
    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Key 192bits");
    lcd.setCursor(0,1);
    lcd.print("> START MASTER");
Serial.println("=====================================================================================================");
Serial.println("=====================================================================================================");
Serial.print("<== Starting the ECDH key generation ==>\n");
Serial.println("=====================================================================================================");

    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Key Generation!");
    lcd.setCursor(0,1);
    lcd.print("> Public&Private");
const struct uECC_Curve_t * curve = uECC_secp192r1(); // select 192 bits key size (24 bytes)
unsigned long a = micros();
uECC_make_key(public1, private1, curve);
unsigned long b = micros();
int puleng = sizeof(public1) / sizeof(public1[0]);
int prleng = sizeof(private1) / sizeof(private1[0]);

Serial.print("ECDH generated key 1 in ");
Serial.print(b-a); Serial.println(" uSec");
dump("ECDH public key 1=>", public1, puleng);
dump("ECDH private key 1=>", private1, prleng);

// 통신 : public1을 보내고 public2를 받아야 함.
  //mySerial.flush();
  for (int i = 0; i < puleng; i++){ 
    mySerial.write(public1[i]);
  }
  while(mySerial.available()<puleng){
    // wait
  }

mySerial.readBytes(public2, puleng);

a = micros();
int r = uECC_shared_secret(public2, private1, secret1, curve);
b = micros();
    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Key Generation!");
    lcd.setCursor(0,1);
    lcd.print(">Shared ECDH Key");
int seleng = sizeof(secret1) / sizeof(secret1[0]);
Serial.println("=====================================================================================================");
Serial.print("ECDH Shared secret key 1 in "); Serial.print(b-a);Serial.println(" uSec");
if (!r) {
      // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Key Generation!");
    lcd.setCursor(0,1);
    lcd.print("> Fail");
Serial.print("shared_secret() failed (1)\n");
return;
}

Serial.println("=====================================================================================================");
dump("ECDH public key 1=>", public1, puleng);
dump("ECDH public key 2=>", public2, puleng);
dump("ECDH shared secret key 1=> ", secret1, seleng);
Serial.println("=====================================================================================================");

//
Serial.print("buf : +");
Serial.println(mySerial.available());

for(byte i=0;i<24;i++)
 EEPROM.write(i, secret1[i]);
prekey(192,1);
//prekey(192,2);
//prekey(192,8);
  }
}

void prekey (int bits, int blocks)
{
   uint8_t shuffled_key[24];
  uint8_t key[24];
byte iv [N_BLOCK];

for (byte i = 0 ; i < 24 ; i++) {
    key[i]=EEPROM.read(i);
  }
  
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

// seed 암호화
t0 = micros () ;
if (blocks == 1)
  succ = aes.encrypt (shuffle_seed, cipher) ;
else {
  for (byte i = 0 ; i < 16 ; i++) iv[i] = my_iv[i] ;
    succ = aes.cbc_encrypt (shuffle_seed, cipher, blocks, iv) ;
}
t1 = micros () ;
Serial.print ("Encryption ") ; Serial.print ((int) succ==0?"Done":"Fail") ;
Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;
    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Shuffle Seed");
    lcd.setCursor(0,1);
    lcd.print("> Encryption");

// seed 전송
  mySerial.flush();
  int cleng = sizeof(cipher) / sizeof(cipher[0]);
  int seedleng = sizeof(shuffle_seed) / sizeof(shuffle_seed[0]);
  Serial.print("cipher length : ");
  Serial.println(cleng);
  Serial.print("seed length : ");
  Serial.println(seedleng);
  for (int i = 0; i < cleng; i++){ 
    mySerial.write(cipher[i]);
  }

//
Serial.print("buf : +");
Serial.println(mySerial.available());

dump("cipher : ", cipher, cleng);
dump("shuffle_seed : ", shuffle_seed, seedleng);
dump("iv : ", iv, 16);


/*
for (byte ph = 0 ; ph < (blocks == 1 ? 2 : 3) ; ph++) {
for (byte i = 0 ; i < (ph < 3 ? blocks*N_BLOCK : N_BLOCK) ; i++) {
byte val = ph == 0 ? shuffle_seed[i] : ph == 1 ? cipher[i] : iv[i] ;
Serial.print(val, HEX); Serial.print(" ");
Serial.print (val>>4, HEX) ; Serial.print (val&15, HEX) ; Serial.print (" ") ;
}
Serial.println () ;
}
*/


//======================== AES Key Shuffling ======================
for(int mm=1; mm <5; mm++){
  //dump("AES key Before Shuffling\n", key , keyleng);
  shuffle(key, 24, sizeof(byte), mm);
  dump("AES key After Shuffling\n", key, keyleng);


  for (byte i = 0 ; i < 24 ; i++) {
    EEPROM.write(i+mm*24, key[i]);
  }
}
    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Key Shuffling");
    lcd.setCursor(0,1);
    lcd.print("> key 1 -> 4");

double sum =0;
for(int mmm=0;mmm<1;mmm++) {
  Serial.print("i : ");
 Serial.println(mmm);
  for(int i=0;i< 24; i++) {
    shuffled_key[i] = EEPROM.read(i+(mmm%4 + 1)*24);
   
  }

    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Master Plain");
    String tempPlain = "JihyunSeyeonHana";
   for(int i=0; i<16; i++){
    int arduino_a0_value=analogRead(A0) + i*2;
    plain[i]=map(arduino_a0_value,0,1023,0,255); // data reading from analog port A0
    lcd.setCursor(i,1);
    lcd.print((char)plain[i]);
    }
  
 // myprintf("\n <==%2d ==> Message Encryption with shuffled AES key \n", mmm);
 // Serial.println("=====================================================================================================");
 // dump("Shuffled AES key=>", shuffled_key,keyleng);
 // Serial.println("=====================================================================================================");
  t0 = micros () ;
  byte succ_shuffle = aes.set_key (shuffled_key, bits) ;
  t1 = micros() ;
 // Serial.print ("set_key ") ; Serial.print (bits) ; Serial.print (" ->") ; Serial.print ((int) succ_shuffle==0?"Done":"Fail");
 // Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;
  t0 = micros () ;
  if (blocks == 1)
    succ = aes.encrypt (plain, cipher) ;
  else {
    for (byte i = 0 ; i < 16 ; i++)
      iv[i] = my_iv[i] ;
    succ = aes.cbc_encrypt (plain, cipher, blocks, iv) ;
  }
  t1 = micros () ;
    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Plain (16bits)");
    lcd.setCursor(0,1);
    lcd.print("> Encrytion");
 sum = sum+t1-t0;
//Serial.print ("Encryption ") ; Serial.print ((int) succ_shuffle==0?"Done":"Fail") ;
//Serial.print (" time ") ; Serial.print (t1-t0) ; Serial.println (" uSec") ;

  // cipher 송신
  mySerial.flush();
  Serial.print("cipher length : ");
 Serial.println(cleng);
  for (int i = 0; i < cleng; i++){ 
    mySerial.write(cipher[i]);
  }



int pleng = sizeof(plain) / sizeof(plain[0]);
  //dump("cipher : ", cipher, cleng);
  dump("plain : ", plain, pleng);
  for(int i=0; i<pleng; i++){
    Serial.print((char)plain[i]);
    }
    Serial.println();
  Serial.print("buf : +");
Serial.println(mySerial.available());

    // 화면 띄우기
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.print("Master Plain");
    for(int i=0; i<pleng; i++){
       lcd.setCursor(i,1);
       lcd.print((char)plain[i]);
    }
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
Serial.print("total time (EN, Plain 16bytes) : ");
Serial.print(sum/4);
}
