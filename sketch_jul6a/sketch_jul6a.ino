#include <Preferences.h>

Preferences prefs;

void setup() {
  Serial.begin(115200);

  // ==== Store "hello" ====
  // prefs.begin("test", false);               // Namespace = "test", RW mode
  // prefs.putString("message", "hello");      // Save string under key "message"
  // prefs.end();

  // Serial.println("Message saved.");

  // ==== Load "hello" ====
  prefs.begin("test", true);                // Read-only mode
  String msg = prefs.getString("message", "default");
  prefs.end();

  Serial.print("Loaded message: ");
  Serial.println(msg);
}

void loop() {
  // Nothing here
}