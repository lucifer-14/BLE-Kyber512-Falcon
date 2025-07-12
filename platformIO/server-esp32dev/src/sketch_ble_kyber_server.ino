#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <Arduino.h>
#include <Preferences.h>

#include "freertos/semphr.h"
#include "mbedtls/gcm.h"

#include <pqcrypto.h>

Preferences prefs;

//
uint8_t sPk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sSk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t client_sPK[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
static size_t clientSPK_offset = 0;

// const uint8_t message[] = "Hello PQClean Falcon512!";
uint8_t signature_c[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
uint8_t signature_s[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
uint8_t signature_to_send_buf[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES+2];
uint8_t signature_to_receive_buf[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES+2];
static size_t sig_offset = 0;
size_t sig_len_s;
size_t sig_len_c;


uint8_t gcm_key[32];
static size_t data_offset = 0;



//
// #define STACK_SIZE (8 * 1024)
#define bleServerName "ESP32_Server2"

#define serverPubSignKey "sthsth"    // preconfigured server's sign pub key

bool deviceConnected = false;
bool handshakePerformed = false;

bool readySignal = false;
bool wasFalconGenerated = false;
bool hasClientSignKey = false;
bool fullSigReceived = false;

static uint8_t pk[KYBER_PUBLICKEYBYTES];  //800
static uint8_t sk[KYBER_SECRETKEYBYTES];  //1632
static uint8_t ct[KYBER_CIPHERTEXTBYTES]; // 768
static uint8_t ss[KYBER_SSBYTES]; // 32
static size_t ct_offset = 0;
// uint8_t* ct = (uint8_t*) malloc(KYBER_CIPHERTEXTBYTES);

SemaphoreHandle_t doneSemaphoreKEM;
SemaphoreHandle_t doneSemaphoreFalcon;
SemaphoreHandle_t doneSemaphoreSigGen;

#define EXCHANGE_SERVICE_UUID "2be35291-37fc-4772-9dc0-7a3636205ded"
#define FALCON_SERVICE_UUID "73a8ff7f-2638-4845-8d97-0909b4bcd151"
#define FALCON_SIG_SERVICE_UUID "2c7d41f1-05cf-4686-9371-55b13aefe341"
#define DATA_EXCHANGE_SERVICE_UUID "9df2eb52-9b45-4a6a-af86-4ca47bac1ead"

BLECharacteristic clientIndicateCharacteristics("65a50320-e6fb-45f7-9a6b-806e0baddc64", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverWriteCharacteristics("16a00f2b-49f5-4a64-8e4e-9621ed7549c2", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverWriteDescriptor(BLEUUID((uint16_t)0x2901));

BLECharacteristic readyWriteCharacteristics("65101b02-932d-4d0d-b05a-db945a870e60", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor readyWriteDescriptor(BLEUUID((uint16_t)0x2901));

BLECharacteristic clientFalconIndicateCharacteristics("d8abbaaf-0cf3-4118-a96b-cd1a30e76772", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientFalconIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverFalconWriteCharacteristics("8e53157c-79b2-4901-8690-e2e454c7de99", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverFalconWriteDescriptor(BLEUUID((uint16_t)0x2901));

BLECharacteristic clientFalconSigIndicateCharacteristics("fcc20e75-c787-4831-8b77-b1681ab5fdf6", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientFalconSigIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverFalconSigWriteCharacteristics("130ee706-0b27-4a49-9cc4-f10ffc368360", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverFalconSigWriteDescriptor(BLEUUID((uint16_t)0x2901));

BLECharacteristic clientDataIndicateCharacteristics("75e48616-472b-4bd8-9507-0a83f1166ece", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientDataIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverDataWriteCharacteristics("76c2cc6c-ad4f-4eb1-9691-2b2ed024cb86", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverDataWriteDescriptor(BLEUUID((uint16_t)0x2901));

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

void sig_gen_task(void *pvParameters){
  PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature_s, &sig_len_s, pk, sizeof(pk), sSk);
  
  signature_to_send_buf[0] = (sig_len_s >> 8) & 0xFF;  // high byte of length
  signature_to_send_buf[1] = sig_len_s & 0xFF;
  memcpy(signature_to_send_buf + 2, signature_s, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);

  xSemaphoreGive(doneSemaphoreSigGen);
  vTaskDelete(NULL);
}

void mlkem_task(void *pvParameters) {
  doneSemaphoreSigGen = xSemaphoreCreateBinary();
  Serial.print("started the kem process already.");
  while (!readySignal){
    Serial.println("100 ms delayed.");
    delay(100);
  }

  static uint8_t tmp_sPk1[448];
  static uint8_t tmp_sPk2[449];
  memcpy(tmp_sPk1, sPk, 448);
  memcpy(tmp_sPk2, sPk + 448, 449);

  clientFalconIndicateCharacteristics.setValue(tmp_sPk1, 448);
  clientFalconIndicateCharacteristics.indicate();
  clientFalconIndicateCharacteristics.setValue(tmp_sPk2, 449);
  clientFalconIndicateCharacteristics.indicate();
  
  PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
  static uint8_t tmp_pk1[400];
  static uint8_t tmp_pk2[400];
  memcpy(tmp_pk1, pk, 400);
  memcpy(tmp_pk2, pk + 400, 400);
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.println("KEM Key gen done.");
  Serial.print("Generated PK: ");
  for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
    // Serial.print(pk[i]);
    // Serial.print(" ");
  }
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.println("done pk. Helllooooooooooooooo!");
  clientIndicateCharacteristics.setValue(tmp_pk1, 400);
  clientIndicateCharacteristics.indicate();
  clientIndicateCharacteristics.setValue(tmp_pk2, 400);
  clientIndicateCharacteristics.indicate();

  const uint32_t stackSizeWords = 65536;
  BaseType_t taskCreated = xTaskCreate(
    sig_gen_task,
    "SignatureGenerate_Task",
    stackSizeWords,
    NULL,
    1,
    NULL
  );
  if (xSemaphoreTake(doneSemaphoreSigGen, portMAX_DELAY) == pdTRUE) {
    Serial.println("End");
    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
    Serial.println("Sig gen done! Time to send sig.");
    // Use pk, sk safely here or call a function that uses them
  }

  static uint8_t tmp_sig1[377];
  static uint8_t tmp_sig2[377];
  memcpy(tmp_sig1, signature_to_send_buf, 377);
  memcpy(tmp_sig2, signature_to_send_buf + 377, 377);

  clientFalconSigIndicateCharacteristics.setValue(tmp_sig1, 377);
  clientFalconSigIndicateCharacteristics.indicate();
  clientFalconSigIndicateCharacteristics.setValue(tmp_sig2, 377);
  clientFalconSigIndicateCharacteristics.indicate();

  // Serial.println(tmp_pk1[0]);
  // Serial.println(tmp_pk2[0]);
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.print("sent pk already, where my client?.");

  uint8_t zero_ct[100] = {0};
  bool is_ct_empty = true;

  while (is_ct_empty){
    Serial.println("CT Delayed 100 ms");
    delay(100);
    is_ct_empty = !memcmp(ct + 668, zero_ct, 100);
  }
  // PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
  // Serial.println("Encap done!");
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.print("CT: ");
  for (int i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
    // Serial.print(ct[i]);
    // Serial.print(" ");
  }

  while(!fullSigReceived){
    Serial.println("CT SIG Delayed 100 ms");
    delay(100);
  }
  bool sig_check = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature_c, sig_len_c, ct, sizeof(ct), client_sPK);
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  if (sig_check == 0){
    Serial.println("Correct Signature. Proceeding....");
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
    Serial.println("Decap done");

    Serial.print("\nGenerated SS: ");
    for (int i = 0; i < KYBER_SSBYTES; i++) {
      Serial.print(ss[i]);
      Serial.print(" ");
    }
    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
    Serial.println("\nDONE.");

    // bool match = true;
    // for (int i = 0; i < KYBER_SSBYTES; i++) {
    //   if (ss1[i] != ss2[i]) { match = false; break; }
    // }
    // Serial.print("Shared secret match: ");
    // Serial.println(match ? "YES" : "NO");
    
    Serial.println("Key Exchange done!");
    handshakePerformed = true;
  } else{
    Serial.println("INCorrect Signature. Somehow stop.");
    memset(signature_c, 0, sizeof(signature_c));    // didn't reset pk and sk cuz they
    memset(ct, 0, sizeof(ct));    // will be resetted anyway when the key is regenerated
    Serial.println("Resetted ct and signature_c.");  
    handshakePerformed = false;
    readySignal = false;
  }

  
  xSemaphoreGive(doneSemaphoreKEM);
  vTaskDelete(NULL);
}

class MyServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
  };
  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
  }
  void onMTUChanged(BLEServer* pServer, esp_ble_gatts_cb_param_t *param) {
    Serial.print("MTU changed: ");
    Serial.println(param->mtu.mtu);
  }
};

class serverWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    uint8_t* data = pCharacteristic->getData();
    size_t length = pCharacteristic->getLength();
    if (ct_offset + length <= KYBER_CIPHERTEXTBYTES) {
      memcpy(ct + ct_offset, data, length);
      ct_offset += length;
      Serial.print("Received chunk. Offset now: ");
      Serial.println(ct_offset);
    } else {
      Serial.println("Error: Received too much data.");
    }

    if (ct_offset == KYBER_CIPHERTEXTBYTES) {
      Serial.print("[");
      Serial.print(millis());
      Serial.print(" ms] ");
      Serial.println("Full ciphertext received!");
      ct_offset = 0; // Reset for next round
      // You can now use `ct`
    }
    // uint8_t* data = pCharacteristic->getData();
    // size_t len = pCharacteristic->getLength();
    // memcpy(ct, data, len);
    
    Serial.println("Got Ct.");
  }
};

class serverFalconWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    if (!hasClientSignKey) {
      uint8_t* data = pCharacteristic->getData();
      size_t length = pCharacteristic->getLength();
      if (clientSPK_offset + length <= PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        memcpy(client_sPK + clientSPK_offset, data, length);
        clientSPK_offset+= length;
        Serial.print("Received chunk. Offset now: ");
        Serial.println(clientSPK_offset);
      } else {
        Serial.println("Error: Received too much data.");
      }

      if (clientSPK_offset == PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        Serial.println("Full client sign pub key received!");
        clientSPK_offset= 0; // Reset for next round

        prefs.begin("falcon", false);  // read-write

        prefs.putBytes("client_sign_pub", client_sPK, sizeof(client_sPK));

        prefs.end();
        hasClientSignKey = true;
        // You can now use `client_sPK`
      }
      // uint8_t* data = pCharacteristic->getData();
      // size_t len = pCharacteristic->getLength();
      // memcpy(ct, data, len);
      Serial.println("Got client_sPK.");
    } else {
      Serial.println("Already got client's sign key, can't overwrite.");
    }

  }
};

class serverFalconSigWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    uint8_t* data = pCharacteristic->getData();
    size_t length = pCharacteristic->getLength();
    if (sig_offset + length <= PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES + 2) {
      memcpy(signature_to_receive_buf + sig_offset, data, length);
      sig_offset += length;
      Serial.print("Received chunk. Offset now: ");
      Serial.println(sig_offset);
    } else {
      Serial.println("Error: Received too much data.");
    }

    if (sig_offset == PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES + 2) {
      Serial.print("[");
      Serial.print(millis());
      Serial.print(" ms] ");
      Serial.println("Full signature received from client!");
      sig_offset = 0; // Reset for next round
      sig_len_c = ((size_t)signature_to_receive_buf[0] << 8) | (size_t)signature_to_receive_buf[1];
      Serial.print("****Received Size: ");
      Serial.println(sig_len_c);
      memcpy(signature_c, signature_to_receive_buf + 2, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
      fullSigReceived = true;

      // You can now use `ct`
    }
    // uint8_t* data = pCharacteristic->getData();
    // size_t len = pCharacteristic->getLength();
    // memcpy(ct, data, len);
    Serial.println("Got Sig from client.");
  }
};

class serverDataWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    // this is easy callback, cannot handle messages longer than 400 bytes
    uint8_t* data = pCharacteristic->getData();
    size_t length = pCharacteristic->getLength();

    uint8_t zero_gcm[32] = {0};
    bool is_gcm_empty = !memcmp(gcm_key, zero_gcm, 32);

    while (is_gcm_empty){
      Serial.println("GCM Key or SS Delayed 100 ms");
      delay(100);
      is_gcm_empty = !memcmp(gcm_key, zero_gcm, 32);
    }
    
    uint8_t data_to_receive[length];
    memcpy(data_to_receive, data, length);

    uint8_t iv[12];
    size_t ciphertext_len = length - (12 + 16);
    uint8_t ciphertext[ciphertext_len];
    uint8_t tag[16];
    memcpy(iv, data_to_receive, sizeof(iv));
    memcpy(tag, data_to_receive+sizeof(iv), sizeof(tag));
    memcpy(ciphertext, data_to_receive+sizeof(iv)+sizeof(tag), ciphertext_len);

    uint8_t decryptedtext[ciphertext_len];
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, gcm_key, 256);
    int ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
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
};

class readyWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic){
    readySignal = true;
    Serial.println("Ready signal received.");
  }
};


void generateFalconKeys(void *pvParameters){
  
  prefs.begin("falcon", false);  // read-write

  PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(sPk, sSk);
  prefs.putBytes("my_sign_pub", sPk, sizeof(sPk));
  prefs.putBytes("my_sign_secret", sSk, sizeof(sSk));

  prefs.end();
  wasFalconGenerated = true;
  xSemaphoreGive(doneSemaphoreFalcon);
  vTaskDelete(NULL);
}

void loadFalconKeys(){
  prefs.begin("falcon", true);
  prefs.getBytes("my_sign_pub", sPk, sizeof(sPk));
  prefs.getBytes("my_sign_secret", sSk, sizeof(sSk));
  if (hasClientSignKey){
    prefs.getBytes("client_sign_pub", client_sPK, sizeof(client_sPK));
  }
  Serial.print("FalconPK from saved: ");
  for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
    // Serial.print(sPk[i]);
    // Serial.print(" ");
  }
  Serial.print("\nFalconsK from saved: ");
  for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES; i++) {
    // Serial.print(sSk[i]);
    // Serial.print(" ");
  }
  prefs.end();

  Serial.println("Loaded");

}

bool falconKeysExist(){

  prefs.begin("falcon", false);  // read-write

  bool isPkExist = prefs.isKey("my_sign_pub");
  bool isSkExist = prefs.isKey("my_sign_secret");
  bool isCPKExist = prefs.isKey("client_sign_pub");
  
  prefs.end();

  if (isCPKExist){
    hasClientSignKey = true;
  }

  wasFalconGenerated = false;
  return isPkExist && isSkExist;
}

void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  doneSemaphoreKEM = xSemaphoreCreateBinary();
  doneSemaphoreFalcon = xSemaphoreCreateBinary();

  Serial.println("sample delay");
  delay(5000);
  Serial.println("delay done");

  if (falconKeysExist()) {
    Serial.println("Got my keys already.");
    loadFalconKeys();

  } else{
    Serial.println("Generating my own keys.");
    const uint32_t stackSizeWords = 32768;
    BaseType_t taskCreated = xTaskCreate(
      generateFalconKeys,
      "GenerateFalconKeys_Task",
      stackSizeWords,
      NULL,
      1,
      NULL
    );
    if (xSemaphoreTake(doneSemaphoreFalcon, portMAX_DELAY) == pdTRUE) {
      Serial.println("End");
      Serial.println("Falcon Key gen done! Safe to use sPk and sSk now.");
      // Use pk, sk safely here or call a function that uses them
    }
  }

  // prefs.begin("falcon", false);
  // prefs.remove("my_sign_pub");  // Deletes "message"
  // prefs.remove("my_sign_secret");  // Deletes "message"
  // prefs.end();

  //
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(sPk, sSk);
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature, &sig_len, message, sizeof(message)-1, sSk);
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, sig_len, message, sizeof(message)-1, sPk);
  //

  BLEDevice::init(bleServerName);
  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *handshakeService = pServer->createService(EXCHANGE_SERVICE_UUID);
  handshakeService->addCharacteristic(&clientIndicateCharacteristics);
  clientIndicateDescriptor.setValue("Send Pub Key Data to Client");
  clientIndicateCharacteristics.addDescriptor(&clientIndicateDescriptor);

  handshakeService->addCharacteristic(&serverWriteCharacteristics);
  serverWriteDescriptor.setValue("Receive Ciphertext back from client");
  serverWriteCharacteristics.addDescriptor(&serverWriteDescriptor);
  serverWriteCharacteristics.setCallbacks(new serverWriteCallbacks());

  handshakeService->addCharacteristic(&readyWriteCharacteristics);
  readyWriteDescriptor.setValue("Send Ready signal to server.");
  readyWriteCharacteristics.addDescriptor(&readyWriteDescriptor);
  readyWriteCharacteristics.setCallbacks(new readyWriteCallbacks());

  BLEService *falconService = pServer->createService(FALCON_SERVICE_UUID);

  falconService->addCharacteristic(&clientFalconIndicateCharacteristics);
  clientFalconIndicateDescriptor.setValue("Send Sign Pub Key Data to Client");
  clientFalconIndicateCharacteristics.addDescriptor(&clientFalconIndicateDescriptor);

  falconService->addCharacteristic(&serverFalconWriteCharacteristics);
  serverFalconWriteDescriptor.setValue("Receive Sign Pub Key back from Client");
  serverFalconWriteCharacteristics.addDescriptor(&serverFalconWriteDescriptor);
  serverFalconWriteCharacteristics.setCallbacks(new serverFalconWriteCallbacks());

  BLEService *falconSigService = pServer->createService(FALCON_SIG_SERVICE_UUID);

  falconSigService->addCharacteristic(&clientFalconSigIndicateCharacteristics);
  clientFalconSigIndicateDescriptor.setValue("Send Signature to Client");
  clientFalconSigIndicateCharacteristics.addDescriptor(&clientFalconSigIndicateDescriptor);

  falconSigService->addCharacteristic(&serverFalconSigWriteCharacteristics);
  serverFalconSigWriteDescriptor.setValue("Receive Signature back from Client");
  serverFalconSigWriteCharacteristics.addDescriptor(&serverFalconSigWriteDescriptor);
  serverFalconSigWriteCharacteristics.setCallbacks(new serverFalconSigWriteCallbacks());

  BLEService *dataExchangeService = pServer->createService(DATA_EXCHANGE_SERVICE_UUID);

  dataExchangeService->addCharacteristic(&clientDataIndicateCharacteristics);
  clientDataIndicateDescriptor.setValue("Send Data to Client");
  clientDataIndicateCharacteristics.addDescriptor(&clientDataIndicateDescriptor);

  dataExchangeService->addCharacteristic(&serverDataWriteCharacteristics);
  serverDataWriteDescriptor.setValue("Receive Data back from Client");
  serverDataWriteCharacteristics.addDescriptor(&serverDataWriteDescriptor);
  serverDataWriteCharacteristics.setCallbacks(new serverDataWriteCallbacks());
  
  handshakeService->start();
  falconService->start();
  falconSigService->start();
  dataExchangeService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(EXCHANGE_SERVICE_UUID);
  pAdvertising->addServiceUUID(FALCON_SERVICE_UUID);
  pAdvertising->addServiceUUID(FALCON_SIG_SERVICE_UUID);
  pAdvertising->addServiceUUID(DATA_EXCHANGE_SERVICE_UUID);
  pServer->getAdvertising()->start();
  Serial.println("Waiting a client connection...");

}

void loop() {
  // put your main code here, to run repeatedly:
  if (deviceConnected)
  {
    Serial.println("Device Connected.");
    if (!handshakePerformed){
      Serial.println("Starting handshake ...");
      const uint32_t stackSizeWords = 16384;
      BaseType_t taskCreated = xTaskCreate(
        mlkem_task,
        "MLKEM_Task",
        stackSizeWords,
        NULL,
        1,
        NULL
      );
      if (xSemaphoreTake(doneSemaphoreKEM, portMAX_DELAY) == pdTRUE) {
        Serial.println("End");
        Serial.println("Key exchange done! Safe to use shared ss now.");
      }
    } else{
      delay(1000);
      Serial.println("Encryption Established!!");
      Serial.print("My pub key: ");
      for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
      // Serial.print(sPk[i]);
      // Serial.print(" ");
      }
      Serial.println("Client pub key: ");
      for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
      // Serial.print(client_sPK[i]);
      // Serial.print(" ");
      }
      prefs.begin("falcon", false);
      
      // prefs.remove("client_sign_pub");  // Deletes "message"
      // prefs.remove("my_sign_pub");
      // prefs.remove("my_sign_secret");
      prefs.end();

      // start of data exchange here....
      uint8_t iv[12];
      randombytes(iv, sizeof(iv));
      uint8_t plaintext[] = "hello";
      size_t ciphertext_len = sizeof(plaintext);
      uint8_t ciphertext[ciphertext_len];
      uint8_t tag[16];
      // uint8_t decryptedtext[400];
      uint8_t data_to_send[ciphertext_len + 12 + 16]; // ciphertext + iv + tag len
      // uint8_t data_to_receive[428];

      Serial.print("Ciphertext_len (should say 6): ");
      Serial.print(ciphertext_len);
      // ciphertext[ciphertext_len];
      memcpy(gcm_key, ss, sizeof(gcm_key));

      mbedtls_gcm_context gcm;
      mbedtls_gcm_init(&gcm);

      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, gcm_key, 256);
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext),
                            iv, sizeof(iv), NULL, 0,
                            plaintext, ciphertext, sizeof(tag), tag);

      mbedtls_gcm_free(&gcm);
      // data_to_send[ciphertext_len + 12 + 16]; // ciphertext + iv + tag len
      memcpy(data_to_send, iv, sizeof(iv));
      memcpy(data_to_send+sizeof(iv), tag, sizeof(tag));
      memcpy(data_to_send+sizeof(iv)+sizeof(tag), ciphertext, ciphertext_len);
      clientDataIndicateCharacteristics.setValue(data_to_send, sizeof(data_to_send));
      clientDataIndicateCharacteristics.indicate();

      delay(5000);
    }
    

  }

  delay(1000); // Delay a second between loops.

}
