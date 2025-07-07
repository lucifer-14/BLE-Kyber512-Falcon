#include <BLEDevice.h>
#include <Arduino.h>
#include <Preferences.h>
#include "freertos/semphr.h"
#include "mbedtls/gcm.h"

#include "pqcrypto.h"

Preferences prefs;

//
uint8_t sPk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sSk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t server_sPK[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
static size_t serverSPK_offset = 0;

const uint8_t message[] = "Hello PQClean Falcon512!";
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

#define bleServerName "ESP32_Server2"

bool deviceConnected = false;
bool handshakePerformed = false;

bool wasFalconGenerated = false;
bool hasServerSignKey = false;

bool fullSigReceived = false;

static BLEUUID exchangeServiceUUID("2be35291-37fc-4772-9dc0-7a3636205ded");
static BLEUUID falconServiceUUID("73a8ff7f-2638-4845-8d97-0909b4bcd151");
static BLEUUID falconSigServiceUUID("2c7d41f1-05cf-4686-9371-55b13aefe341");
static BLEUUID dataExchangeServiceUUID("9df2eb52-9b45-4a6a-af86-4ca47bac1ead");

static BLEUUID clientIndicateCharacteristicsUUID("65a50320-e6fb-45f7-9a6b-806e0baddc64");

static BLEUUID serverWriteCharacteristicsUUID("16a00f2b-49f5-4a64-8e4e-9621ed7549c2");

static BLEUUID readyWriteCharacteristicsUUID("65101b02-932d-4d0d-b05a-db945a870e60");

static BLEUUID clientFalconIndicateCharacteristicsUUID("d8abbaaf-0cf3-4118-a96b-cd1a30e76772");

static BLEUUID serverFalconWriteCharacteristicsUUID("8e53157c-79b2-4901-8690-e2e454c7de99");

static BLEUUID clientFalconSigIndicateCharacteristicsUUID("fcc20e75-c787-4831-8b77-b1681ab5fdf6");

static BLEUUID serverFalconSigWriteCharacteristicsUUID("130ee706-0b27-4a49-9cc4-f10ffc368360");

static BLEUUID clientDataIndicateCharacteristicsUUID("75e48616-472b-4bd8-9507-0a83f1166ece");

static BLEUUID serverDataWriteCharacteristicsUUID("76c2cc6c-ad4f-4eb1-9691-2b2ed024cb86");

static bool doConnect = false;

uint8_t pk[KYBER_PUBLICKEYBYTES];
uint8_t sk[KYBER_SECRETKEYBYTES];
uint8_t ct[KYBER_CIPHERTEXTBYTES];
uint8_t ss[KYBER_SSBYTES];
static size_t pk_offset = 0;

SemaphoreHandle_t doneSemaphoreKEM;
SemaphoreHandle_t doneSemaphoreFalcon;
SemaphoreHandle_t doneSemaphoreSigGen;

static BLEAddress *pServerAddress;

BLERemoteCharacteristic* pRemoteClientIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerWriteChar = nullptr;
BLERemoteCharacteristic* pRemoteReadyWriteChar = nullptr;
BLERemoteCharacteristic* pRemoteClientFalconIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerFalconWriteChar = nullptr;
BLERemoteCharacteristic* pRemoteClientFalconSigIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerFalconSigWriteChar = nullptr;
BLERemoteCharacteristic* pRemoteClientDataIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerDataWriteChar = nullptr;

static uint8_t indicationOn[] = {0x02, 0x00};

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
  Serial.println("Generting sig for ct ...");
  PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature_c, &sig_len_c, ct, sizeof(ct), sSk);
  // uint16_t len_to_send = (uint16_t)sig_len_c;
  
  signature_to_send_buf[0] = (sig_len_c >> 8) & 0xFF;  // high byte of length
  signature_to_send_buf[1] = sig_len_c & 0xFF;
  memcpy(signature_to_send_buf + 2, signature_c, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);

  Serial.println("Generting sig for ct done ...");

  xSemaphoreGive(doneSemaphoreSigGen);
  vTaskDelete(NULL);
}

void mlkem_task(void *pvParameters) {
  doneSemaphoreSigGen = xSemaphoreCreateBinary();
  Serial.println("Started KEM, did my server sent already?");
  // uint8_t readySignal = {1};
  // pRemoteReadyWriteChar->writeValue(readySignal, 1);

  static uint8_t tmp_sPk1[448];
  static uint8_t tmp_sPk2[449];
  
  memcpy(tmp_sPk1, sPk, 448);
  memcpy(tmp_sPk2, sPk + 448, 449);
  pRemoteServerFalconWriteChar->writeValue(tmp_sPk1, 448, true);
  pRemoteServerFalconWriteChar->writeValue(tmp_sPk2, 449, true);
  
  // uint16_t mtu = BLEDevice::getMTU();
  // Serial.printf("Current MTU: %d\n", mtu);
  uint8_t zero_pk[100] = {0};
  
  bool is_pk_empty = true;

  while (is_pk_empty){
    Serial.println("PK Delayed 100 ms");
    delay(100);
    is_pk_empty = !memcmp(pk + 700, zero_pk, 100);
    Serial.print(pk[0]);
  }
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.print("PK: ");
  for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
    // Serial.print(pk[i]);
    // Serial.print(" ");
  }
  while(!fullSigReceived){
    Serial.println("PK SIG Delayed 100 ms");
    delay(100);
  }
  bool sig_check = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature_s, sig_len_s, pk, sizeof(pk), server_sPK);
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  if (sig_check == 0){
    Serial.println("Correct Signature. Proceeding....");

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
    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
    Serial.println("Encap done");

    pRemoteServerWriteChar->writeValue(tmp_ct1, 384, true);
    pRemoteServerWriteChar->writeValue(tmp_ct2, 384, true);

    Serial.println("Sent tmpct.");

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

    pRemoteServerFalconSigWriteChar->writeValue(tmp_sig1, 377, true);
    pRemoteServerFalconSigWriteChar->writeValue(tmp_sig2, 377, true);

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

    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
    Serial.println("Key Exchange done!");
    handshakePerformed = true;
  } else{
    Serial.println("INCorrect Signature. Somehow stop.");
    memset(signature_s, 0, sizeof(signature_s));
    memset(pk, 0, sizeof(pk));
    Serial.println("Resetted pk and signature_s.");
    handshakePerformed == false;
  }

  // check signature with server pub. only after that use enc and send cipher text.
  
  

  xSemaphoreGive(doneSemaphoreKEM);
  vTaskDelete(NULL);
}

bool connectToServer(BLEAddress pAddress) {
  BLEClient* pClient = BLEDevice::createClient();
  
 
  // Connect to the remove BLE Server.
  pClient->connect(pAddress);
  Serial.println(" - Connected to server");

  pClient->setMTU(453);
 
  // Obtain a reference to the service we are after in the remote BLE server.
  BLERemoteService* pRemoteService = pClient->getService(exchangeServiceUUID);
  if (pRemoteService == nullptr) {
    Serial.print("Failed to find our service UUID: ");
    Serial.println(exchangeServiceUUID.toString().c_str());
    return (false);
  }

  BLERemoteService* pRemoteFalconService = pClient->getService(falconServiceUUID);
  if (pRemoteFalconService == nullptr) {
    Serial.print("Failed to find our falcon service UUID: ");
    Serial.println(falconServiceUUID.toString().c_str());
    return (false);
  }

  BLERemoteService* pRemoteFalconSigService = pClient->getService(falconSigServiceUUID);
  if (pRemoteFalconSigService == nullptr) {
    Serial.print("Failed to find our falcon service UUID: ");
    Serial.println(falconSigServiceUUID.toString().c_str());
    return (false);
  }

  BLERemoteService* pRemoteDataExchangeService = pClient->getService(dataExchangeServiceUUID);
  if (pRemoteDataExchangeService == nullptr) {
    Serial.print("Failed to find our falcon service UUID: ");
    Serial.println(dataExchangeServiceUUID.toString().c_str());
    return (false);
  }
 
  // Obtain a reference to the characteristics in the service of the remote BLE server.
  pRemoteClientIndicateChar = pRemoteService->getCharacteristic(clientIndicateCharacteristicsUUID);
  pRemoteServerWriteChar = pRemoteService->getCharacteristic(serverWriteCharacteristicsUUID);
  pRemoteReadyWriteChar = pRemoteService->getCharacteristic(readyWriteCharacteristicsUUID);
  pRemoteClientFalconIndicateChar = pRemoteFalconService->getCharacteristic(clientFalconIndicateCharacteristicsUUID);
  pRemoteServerFalconWriteChar = pRemoteFalconService->getCharacteristic(serverFalconWriteCharacteristicsUUID);
  pRemoteClientFalconSigIndicateChar = pRemoteFalconSigService->getCharacteristic(clientFalconSigIndicateCharacteristicsUUID);
  pRemoteServerFalconSigWriteChar = pRemoteFalconSigService->getCharacteristic(serverFalconSigWriteCharacteristicsUUID);
  pRemoteClientDataIndicateChar = pRemoteDataExchangeService->getCharacteristic(clientDataIndicateCharacteristicsUUID);
  pRemoteServerDataWriteChar = pRemoteDataExchangeService->getCharacteristic(serverDataWriteCharacteristicsUUID);

  if (pRemoteClientIndicateChar == nullptr || pRemoteServerWriteChar == nullptr || pRemoteReadyWriteChar == nullptr
  || pRemoteServerFalconWriteChar == nullptr || pRemoteClientFalconIndicateChar == nullptr
  || pRemoteServerFalconSigWriteChar == nullptr || pRemoteClientFalconSigIndicateChar == nullptr
  || pRemoteServerDataWriteChar == nullptr || pRemoteClientDataIndicateChar == nullptr) {
    Serial.print("Failed to find our characteristic UUID");
    return false;
  }
  Serial.println(" - Found our characteristics");
  Serial.println("hmm2...");
  //Assign callback functions for the Characteristics
  pRemoteClientIndicateChar->registerForNotify(clientIndicateCallback, true);
  pRemoteClientIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
  Serial.println("hmm3...");
  pRemoteClientFalconIndicateChar->registerForNotify(clientFalconIndicateCallback, true);
  pRemoteClientFalconIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
  Serial.println("hmm ...");
  pRemoteClientFalconSigIndicateChar->registerForNotify(clientFalconSigIndicateCallback, true);
  pRemoteClientFalconSigIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
   Serial.println("hmm4 ...");
  pRemoteClientDataIndicateChar->registerForNotify(clientDataIndicateCallback, true);
  pRemoteClientDataIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
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
    Serial.print("[");
    Serial.print(millis());
    Serial.print(" ms] ");
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

static void clientFalconIndicateCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic, 
                                        uint8_t* pData, size_t length, bool isNotify) {
  if (!hasServerSignKey) {
    if (serverSPK_offset + length <= PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
      memcpy(server_sPK + serverSPK_offset, pData, length);
      serverSPK_offset += length;
      Serial.print("Received chunk. Offset now: ");
      Serial.println(serverSPK_offset);
    } else {
      Serial.println("Error: Received too much data.");
    }

    if (serverSPK_offset == PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
      Serial.println("Server sign public key received!");

      serverSPK_offset = 0; // Reset for next round
      prefs.begin("falcon", false);  // read-write

      prefs.putBytes("server_sign_pub", server_sPK, sizeof(server_sPK));

      prefs.end();
      hasServerSignKey = true;
      // You can now use `server_sPk`
    }
    // Serial.println(length);
    // Serial.println(KYBER_PUBLICKEYBYTES);
    // size_t copyLen = length < KYBER_PUBLICKEYBYTES ? length : KYBER_PUBLICKEYBYTES;
    // memcpy(pk, pData, copyLen);
    Serial.println("Got server_sPK.");
  } else{
    Serial.println("Already got server's sign key, can't overwrite.");
  }
}

static void clientFalconSigIndicateCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic,
                                          uint8_t* pData, size_t length, bool isNotify){

  if (sig_offset + length <= PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES + 2) {
    memcpy(signature_to_receive_buf + sig_offset, pData, length);
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
    Serial.println("Full signature received from server!");
    sig_offset = 0; // Reset for next round
    sig_len_s = ((size_t)signature_to_receive_buf[0] << 8) | (size_t)signature_to_receive_buf[1];
    Serial.print("****Received Size: ");
    Serial.println(sig_len_s);
    memcpy(signature_s, signature_to_receive_buf + 2, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
    fullSigReceived = true;

    // You can now use `ct`
  }
  // uint8_t* data = pCharacteristic->getData();
  // size_t len = pCharacteristic->getLength();
  // memcpy(ct, data, len);
  Serial.println("Got Sig from server.");
}

static void clientDataIndicateCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic,
                                          uint8_t* pData, size_t length, bool isNotify){
    
    uint8_t data_to_receive[length];
    memcpy(data_to_receive, pData, length);

    uint8_t zero_gcm[32] = {0};
    bool is_gcm_empty = !memcmp(gcm_key, zero_gcm, 32);

    while (is_gcm_empty){
      Serial.println("GCM Key or SS Delayed 100 ms");
      delay(100);
      is_gcm_empty = !memcmp(gcm_key, zero_gcm, 32);
    } // normally no gcm delay due to it generating ss first than server.

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
  Serial.println("OK");
  if (hasServerSignKey){
    Serial.println("Hello");
    prefs.getBytes("server_sign_pub", server_sPK, sizeof(server_sPK));
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
  bool isSPKExist = prefs.isKey("server_sign_pub");

  prefs.end();
  if (isSPKExist){
    hasServerSignKey = true;
  }

  wasFalconGenerated = false;
  return isPkExist && isSkExist;
}


void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  doneSemaphoreKEM = xSemaphoreCreateBinary();
  doneSemaphoreFalcon = xSemaphoreCreateBinary();

  Serial.println("sample client delay");
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
      Serial.println("Starting handshake ...");
      uint8_t readySignal = {1};
      pRemoteReadyWriteChar->writeValue(readySignal, 1);
      

      while (!hasServerSignKey){
        Serial.println("Waiting for server sign key.... 100 ms");
        delay(100);
      }
      const uint32_t stackSizeWords = 32768; //16384
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
        Serial.println("Key excahnge done! Safe to shared ss now.");
        // Use pk, sk safely here or call a function that uses them
      }
      
      
      // PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
      // Serial.println("Encapsulation done");

      // pRemoteServerWriteChar->writeValue("hello", true);  // true = Write With Response

      // Serial.println("Key Exchange done!");
      // handshakePerformed = true;
    } else {
      Serial.println("Encryption Established!!");
      Serial.print("My pub key: ");
      for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
      // Serial.print(sPk[i]);
      // Serial.print(" ");
      }
      Serial.println("server pub key: ");
      for (int i = 0; i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
      // Serial.print(server_sPK[i]);
      // Serial.print(" ");
      }

      prefs.begin("falcon", false);
      // prefs.remove("server_sign_pub");  // Deletes "message"
      // prefs.remove("my_sign_pub");
      // prefs.remove("my_sign_secret");
      prefs.end();

      // start of data exchange here....
      uint8_t iv[12];
      randombytes(iv, sizeof(iv));
      uint8_t plaintext[] = "hi from client";
      size_t ciphertext_len = sizeof(plaintext);
      uint8_t ciphertext[ciphertext_len];
      uint8_t tag[16];
      // uint8_t decryptedtext[400];
      uint8_t data_to_send[ciphertext_len + 12 + 16]; // ciphertext + iv + tag len
      // uint8_t data_to_receive[428];

      Serial.print("Ciphertext_len (should say 15): ");
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
      pRemoteServerDataWriteChar->writeValue(data_to_send, sizeof(data_to_send), true);
      Serial.println("Data sent.");

      delay(100000);
    }

  }
  delay(1000); // Delay a second between loops.

}
