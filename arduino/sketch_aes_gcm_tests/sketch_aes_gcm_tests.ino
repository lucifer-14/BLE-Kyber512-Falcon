#include "mbedtls/gcm.h"

extern "C" {
#include "randombytes.h"
}

void hex_print(const char* label, const uint8_t* data, size_t len){
  Serial.print(label);
  Serial.print(": ");
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print('0');
    Serial.print(data[i], HEX);
    Serial.print(' ');
  }
  Serial.println();
}


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial.println("Hi");
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  uint8_t key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  };
  uint8_t iv[12];
  randombytes(iv, sizeof(iv));
  uint8_t plaintext[] = "hello";
  size_t ciphertext_len = sizeof(plaintext);
  uint8_t ciphertext[ciphertext_len];
  size_t decrypted_len = sizeof(ciphertext);
  uint8_t decryptedtext[decrypted_len];
  uint8_t tag[16];

  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext),
                            iv, sizeof(iv), NULL, 0,
                            plaintext, ciphertext, sizeof(tag), tag);


  hex_print("IV: ", iv, sizeof(iv));              
  hex_print("Plaintext: ", plaintext, sizeof(plaintext));
  hex_print("Ciphertext: ", ciphertext, sizeof(ciphertext));
  hex_print("Tag:", tag, sizeof(tag));

  int ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(ciphertext),
                                     iv, sizeof(iv),
                                     NULL, 0,  // No AAD
                                     tag, sizeof(tag),
                                     ciphertext, decryptedtext);

  if (ret == 0){
    hex_print("Decrypted: ", decryptedtext, sizeof(decryptedtext));
    Serial.print("Decrypted text: ");
    Serial.println((char*)decryptedtext);
  } else {
    Serial.println("Decryption failed! Tag mismatch.");
  }
  mbedtls_gcm_free(&gcm);
}

void loop() {
  // put your main code here, to run repeatedly:
  int a = 10;
  Serial.println(a);
  delay(1000);

}
