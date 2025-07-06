#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// #include "kyber.h"

#define bleServerName "ESP32_Server"

#define serverPubSignKey "sthsth"    // preconfigured server's sign pub key

bool deviceConnected = false;
// uint8_t pk[KYBER_PUBLICKEYBYTES];
// uint8_t sk[KYBER_SECRETKEYBYTES];
// uint8_t ct[KYBER_CIPHERTEXTBYTES];
// uint8_t ss[KYBER_SSBYTES];

#define EXCHANGE_SERVICE_UUID "2be35291-37fc-4772-9dc0-7a3636205ded"

BLECharacteristic clientIndicateCharacteristics("65a50320-e6fb-45f7-9a6b-806e0baddc64", BLECharacteristic::PROPERTY_INDICATE);
BLEDescriptor clientIndicateDescriptor(BLEUUID((uint16_t)0x2902));

BLECharacteristic serverWriteCharacteristics("16a00f2b-49f5-4a64-8e4e-9621ed7549c2", BLECharacteristic::PROPERTY_WRITE);
BLEDescriptor serverWriteDescriptor(BLEUUID((uint16_t)0x2902));

class MyServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
  };
  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
  }
};

class MyCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    uint8_t* data = pCharacteristic->getData();
    size_t len = pCharacteristic->getLength();
    // memcpy(ct, data, len);
  }
};
void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);

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
  serverWriteCharacteristics.setCallbacks(new MyCallbacks());
  
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
    /*
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    Serial.println("Keypair generated");

    clientIndicateCharacteristics.setValue(pk, KYBER_PUBLICKEYBYTES);
    clientIndicateCharacteristics.indicate();

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
    Serial.println("Decapsulation done");

    Serial.println("Key Exchange done!");
    */
    delay(1000);
    Serial.println("Dev connected");

  }

  delay(1000); // Delay a second between loops.

}
