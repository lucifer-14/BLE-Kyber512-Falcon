#include <BLEDevice.h>
#include <Arduino.h>
#include "freertos/semphr.h"

#include "pqcrypto.h"

//
uint8_t sPk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t sSk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];

const uint8_t message[] = "Hello PQClean Falcon512!";
uint8_t signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
size_t sig_len;

//

#define bleServerName "ESP32_Server2"

bool deviceConnected = false;
bool handshakePerformed = false;

static BLEUUID exchangeServiceUUID("2be35291-37fc-4772-9dc0-7a3636205ded");

static BLEUUID clientIndicateCharacteristicsUUID("65a50320-e6fb-45f7-9a6b-806e0baddc64");

static BLEUUID serverWriteCharacteristicsUUID("16a00f2b-49f5-4a64-8e4e-9621ed7549c2");

static BLEUUID readyWriteCharacteristicsUUID("65101b02-932d-4d0d-b05a-db945a870e60");

static bool doConnect = false;

uint8_t pk[KYBER_PUBLICKEYBYTES];
uint8_t sk[KYBER_SECRETKEYBYTES];
uint8_t ct[KYBER_CIPHERTEXTBYTES];
uint8_t ss[KYBER_SSBYTES];
static size_t pk_offset = 0;

SemaphoreHandle_t doneSemaphore;

static BLEAddress *pServerAddress;

BLERemoteCharacteristic* pRemoteClientIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerWriteChar = nullptr;
BLERemoteCharacteristic* pRemoteReadyWriteChar = nullptr;

static uint8_t indicationOn[] = {0x02, 0x00};

void mlkem_task(void *pvParameters) {
  Serial.println("Started KEM, did my server sent already?");
  uint8_t readySignal = {1};
  pRemoteReadyWriteChar->writeValue(readySignal, 1);
  
  uint16_t mtu = BLEDevice::getMTU();
  Serial.printf("Current MTU: %d\n", mtu);
  uint8_t zero_pk[100] = {0};
  
  bool is_pk_empty = true;

  while (is_pk_empty){
    Serial.println("PK Delayed 1s");
    delay(1000);
    is_pk_empty = !memcmp(pk + 700, zero_pk, 100);
    Serial.print(pk[0]);
  }
  Serial.print("PK: ");
  for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
    // Serial.print(pk[i]);
    // Serial.print(" ");
  }
  
  PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
  static uint8_t tmp_ct1[384];
  static uint8_t tmp_ct2[384];
  memcpy(tmp_ct1, ct, 384);
  memcpy(tmp_ct2, ct + 384, 384);
  Serial.print("\nGenerated CT: ");
  for (int i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
    // Serial.print(ct[i]);
    // Serial.print(" ");
  }
  Serial.println("Encap done");

  pRemoteServerWriteChar->writeValue(tmp_ct1, 384, true);
  pRemoteServerWriteChar->writeValue(tmp_ct2, 384, true);

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

bool connectToServer(BLEAddress pAddress) {
  BLEClient* pClient = BLEDevice::createClient();
  
 
  // Connect to the remove BLE Server.
  pClient->connect(pAddress);
  Serial.println(" - Connected to server");

  pClient->setMTU(403);
 
  // Obtain a reference to the service we are after in the remote BLE server.
  BLERemoteService* pRemoteService = pClient->getService(exchangeServiceUUID);
  if (pRemoteService == nullptr) {
    Serial.print("Failed to find our service UUID: ");
    Serial.println(exchangeServiceUUID.toString().c_str());
    return (false);
  }
 
  // Obtain a reference to the characteristics in the service of the remote BLE server.
  pRemoteClientIndicateChar = pRemoteService->getCharacteristic(clientIndicateCharacteristicsUUID);
  pRemoteServerWriteChar = pRemoteService->getCharacteristic(serverWriteCharacteristicsUUID);
  pRemoteReadyWriteChar = pRemoteService->getCharacteristic(readyWriteCharacteristicsUUID);

  if (pRemoteClientIndicateChar == nullptr || pRemoteServerWriteChar == nullptr || pRemoteReadyWriteChar == nullptr) {
    Serial.print("Failed to find our characteristic UUID");
    return false;
  }
  Serial.println(" - Found our characteristics");
 
  //Assign callback functions for the Characteristics
  pRemoteClientIndicateChar->registerForNotify(clientIndicateCallback, true);
  pRemoteClientIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
  return true;
}

//Callback function that gets called, when another device's advertisement has been received
class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    if (advertisedDevice.getName() == bleServerName) { //Check if the name of the advertiser matches
      advertisedDevice.getScan()->stop(); //Scan can be stopped, we found what we are looking for
      pServerAddress = new BLEAddress(advertisedDevice.getAddress()); //Address of advertiser is the one we need
      doConnect = true; //Set indicator, stating that we are ready to connect
      Serial.println("Device found. Connecting!");
    }
  }
};

static void clientIndicateCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic, 
                                        uint8_t* pData, size_t length, bool isNotify) {

  if (pk_offset + length <= KYBER_PUBLICKEYBYTES) {
    memcpy(pk + pk_offset, pData, length);
    pk_offset += length;
    Serial.print("Received chunk. Offset now: ");
    Serial.println(pk_offset);
  } else {
    Serial.println("Error: Received too much data.");
  }

  if (pk_offset == KYBER_PUBLICKEYBYTES) {
    Serial.println("Full public key received!");
    pk_offset = 0; // Reset for next round
    // You can now use `pk`
  }
  // Serial.println(length);
  // Serial.println(KYBER_PUBLICKEYBYTES);
  // size_t copyLen = length < KYBER_PUBLICKEYBYTES ? length : KYBER_PUBLICKEYBYTES;
  // memcpy(pk, pData, copyLen);
  Serial.println("Got pk.");
}

void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  doneSemaphore = xSemaphoreCreateBinary();

  //
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(sPk, sSk);
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature, &sig_len, message, sizeof(message)-1, sSk);
  // PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, sig_len, message, sizeof(message)-1, sPk);
  //

  Serial.println("Starting Arduino BLE Client application...");
  BLEDevice::init("ESP32_Client");
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(30);
}

void loop() {
  // put your main code here, to run repeatedly:
  if (!deviceConnected){
    if (doConnect) {
      if (connectToServer(*pServerAddress)) {
        Serial.println("We are now connected to the BLE Server.");
        //Activate the Notify property of each Characteristic
        // pRemoteClientIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);

        deviceConnected = true;
      } else {
        Serial.println("We have failed to connect to the server; Restart your device to scan for nearby BLE server again.");
        doConnect = false;
      }
    } 
  } else {
    if(!handshakePerformed){

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
      
      
      // PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
      // Serial.println("Encapsulation done");

      // pRemoteServerWriteChar->writeValue("hello", true);  // true = Write With Response

      // Serial.println("Key Exchange done!");
      // handshakePerformed = true;
    }
    Serial.println("Encryption Established!!");

  }
  delay(1000); // Delay a second between loops.

}
