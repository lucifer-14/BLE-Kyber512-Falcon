#include <BLEDevice.h>

#include "kyber.h"

#define bleServerName "ESP32_Server"

bool deviceConnected = false;

static BLEUUID exchangeServiceUUID("2be35291-37fc-4772-9dc0-7a3636205ded");

static BLEUUID clientIndicateCharacteristicsUUID("65a50320-e6fb-45f7-9a6b-806e0baddc64");

static BLEUUID serverWriteCharacteristicsUUID("16a00f2b-49f5-4a64-8e4e-9621ed7549c2");

static boolean doConnect = false;

uint8_t pk[KYBER_PUBLICKEYBYTES];
uint8_t sk[KYBER_SECRETKEYBYTES];
uint8_t ct[KYBER_CIPHERTEXTBYTES];
uint8_t ss[KYBER_SSBYTES];

static BLEAddress *pServerAddress;

BLERemoteCharacteristic* pRemoteClientIndicateChar = nullptr;
BLERemoteCharacteristic* pRemoteServerWriteChar = nullptr;

static uint8_t indicationOn[] = {0x02, 0x00};


bool connectToServer(BLEAddress pAddress) {
   BLEClient* pClient = BLEDevice::createClient();
 
  // Connect to the remove BLE Server.
  pClient->connect(pAddress);
  Serial.println(" - Connected to server");
 
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

  if (pRemoteClientIndicateChar == nullptr || pRemoteServerWriteChar == nullptr) {
    Serial.print("Failed to find our characteristic UUID");
    return false;
  }
  Serial.println(" - Found our characteristics");
 
  //Assign callback functions for the Characteristics
  pRemoteClientIndicateChar->registerForNotify(clientIndicateCallback, true);
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
  Serial.println(length);
  Serial.println(KYBER_PUBLICKEYBYTES);
  size_t copyLen = length < KYBER_PUBLICKEYBYTES ? length : KYBER_PUBLICKEYBYTES;
  memcpy(pk, pData, copyLen);
}

void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  Serial.println("Starting Arduino BLE Client application...");
  BLEDevice::init("ESP32_Client");
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(30);
}

void loop() {
  // put your main code here, to run repeatedly:
  if (doConnect) {
    if (connectToServer(*pServerAddress)) {
      Serial.println("We are now connected to the BLE Server.");
      //Activate the Notify property of each Characteristic
      pRemoteClientIndicateChar->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t*)indicationOn, 2, true);
      
      PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
      Serial.println("Encapsulation done");

      pRemoteServerWriteChar->writeValue(ct, true);  // true = Write With Response

      Serial.println("Key Exchange done!");

    } else {
      Serial.println("We have failed to connect to the server; Restart your device to scan for nearby BLE server again.");
      doConnect = false;
    }
  }
  delay(1000); // Delay a second between loops.

}
