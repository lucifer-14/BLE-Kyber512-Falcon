#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <Arduino.h>
#include "freertos/semphr.h"

#include <pqcrypto.h>

//
uint8_t sPk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t sSk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];

const uint8_t message[] = "Hello PQClean Falcon512!";
uint8_t signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
size_t sig_len;

//
// #define STACK_SIZE (8 * 1024)
#define bleServerName "ESP32_Server2"

#define serverPubSignKey "sthsth"    // preconfigured server's sign pub key

bool deviceConnected = false;
bool handshakePerformed = false;

bool readySignal = false;

static uint8_t pk[KYBER_PUBLICKEYBYTES];  //800
static uint8_t sk[KYBER_SECRETKEYBYTES];  //1632
static uint8_t ct[KYBER_CIPHERTEXTBYTES]; // 768
static uint8_t ss[KYBER_SSBYTES]; // 32
static size_t ct_offset = 0;
// uint8_t* ct = (uint8_t*) malloc(KYBER_CIPHERTEXTBYTES);

SemaphoreHandle_t doneSemaphore;

#define EXCHANGE_SERVICE_UUID "2be35291-37fc-4772-9dc0-7a3636205ded"

BLECharacteristic clientIndicateCharacteristics("65a50320-e6fb-45f7-9a6b-806e0baddc64", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverWriteCharacteristics("16a00f2b-49f5-4a64-8e4e-9621ed7549c2", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverWriteDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic readyWriteCharacteristics("65101b02-932d-4d0d-b05a-db945a870e60", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor readyWriteDescriptor(BLEUUID((uint16_t)0x2902));

void mlkem_task(void *pvParameters) {
  Serial.print("started the kem process already.");
  while (!readySignal){
    Serial.println("100 mili delayed.");
    delay(100);
  }
  PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
  static uint8_t tmp_pk1[400];
  static uint8_t tmp_pk2[400];
  memcpy(tmp_pk1, pk, 400);
  memcpy(tmp_pk2, pk + 400, 400);
  Serial.println("Key gen done.");
  Serial.print("Generated PK: ");
  for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
    // Serial.print(pk[i]);
    // Serial.print(" ");
  }
  Serial.println("done pk. Helllooooooooooooooo!");
  clientIndicateCharacteristics.setValue(tmp_pk1, 400);
  clientIndicateCharacteristics.indicate();
  clientIndicateCharacteristics.setValue(tmp_pk2, 400);
  clientIndicateCharacteristics.indicate();
  Serial.println(tmp_pk1[0]);
  Serial.println(tmp_pk2[0]);
  Serial.print("sent pk already, where my client?.");

  uint8_t zero_ct[100] = {0};
  bool is_ct_empty = true;

  while (is_ct_empty){
    Serial.println("CT Delayed 1s");
    delay(1000);
    is_ct_empty = !memcmp(ct + 668, zero_ct, 100);
  }
  // PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
  // Serial.println("Encap done!");
  Serial.print("CT: ");
  for (int i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
    // Serial.print(ct[i]);
    // Serial.print(" ");
  }

  PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
  Serial.println("Decap done");

  Serial.print("\nGenerated SS: ");
  for (int i = 0; i < KYBER_SSBYTES; i++) {
    Serial.print(ss[i]);
    Serial.print(" ");
  }
  Serial.println("\nDONE.");

  // bool match = true;
  // for (int i = 0; i < KYBER_SSBYTES; i++) {
  //   if (ss1[i] != ss2[i]) { match = false; break; }
  // }
  // Serial.print("Shared secret match: ");
  // Serial.println(match ? "YES" : "NO");
  
  Serial.println("Key Exchange done!");
  handshakePerformed = true;
  xSemaphoreGive(doneSemaphore);
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

class MyMTUCallbacks : public BLEServerCallbacks {
  
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

class readyWriteCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic){
    readySignal = true;
    Serial.println("Ready signal received.");
  }
};

void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  doneSemaphore = xSemaphoreCreateBinary();

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
  serverWriteDescriptor.setValue("Send Ciphertext back to Server");
  serverWriteCharacteristics.addDescriptor(&serverWriteDescriptor);
  serverWriteCharacteristics.setCallbacks(new serverWriteCallbacks());

  handshakeService->addCharacteristic(&readyWriteCharacteristics);
  readyWriteDescriptor.setValue("Send Ready signal to server.");
  readyWriteCharacteristics.addDescriptor(&readyWriteDescriptor);
  readyWriteCharacteristics.setCallbacks(new readyWriteCallbacks());
  
  // esp_ble_gatt_set_local_mtu(97);
  handshakeService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(EXCHANGE_SERVICE_UUID);
  pServer->getAdvertising()->start();
  Serial.println("Waiting a client connection...");

}

void loop() {
  // put your main code here, to run repeatedly:
  if (deviceConnected)
  {
    Serial.println("Device Connected.");
    if (!handshakePerformed){

      const uint32_t stackSizeWords = 16384;
      BaseType_t taskCreated = xTaskCreate(
        mlkem_task,
        "MLKEM_Task",
        stackSizeWords,
        NULL,
        1,
        NULL
      );
      if (xSemaphoreTake(doneSemaphore, portMAX_DELAY) == pdTRUE) {
        Serial.println("End");
        Serial.println("Key generation done! Safe to use pk and sk now.");
        // Use pk, sk safely here or call a function that uses them
      }
      // PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
      // Serial.println("Keypair generated");

      // clientIndicateCharacteristics.setValue(pk, KYBER_PUBLICKEYBYTES);
      // clientIndicateCharacteristics.indicate();

      // PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
      // Serial.println("Obtained ciphertext from the other side.");

      // PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
      // Serial.println("Decapsulation done");

      // Serial.println("Key Exchange done!");
      // handshakePerformed = true;
      // delay(10000);
    }
    delay(1000);
    Serial.println("Encryption Established!!");

  }

  delay(1000); // Delay a second between loops.

}
