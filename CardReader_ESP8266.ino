#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN     5   // SPI Reset Pin (D1  Ausgang)
#define RELAIS_PIN  16  // Relais (D0  Ausgang) [LOW Aktiv] - Auch interne LED nahe USB Port
#define SS_PIN      15  // SPI Slave Select Pin

#define RGBLED_R    2   // Rot (D4  Ausgang) 
#define RGBLED_G    0   // Grün (D3  Ausgang) - Auch interne LED auf dem ESP Modul
#define RGBLED_B    4   // Blau (D2  Ausgang)

#define LED_BUILTIN 16
#define PIN_WIRE_SDA 4 
#define PIN_WIRE_SCL 5 

 
MFRC522 mfrc522(SS_PIN, RST_PIN);   // Instanz des MFRC522 erzeugen
MFRC522::MIFARE_Key key;

byte myValidCardUID[4] = {0x06,0x1C,0xDF,0x01}; // Hier die per serielle Schnittstelle gelesene
                                                // UID eintragen, für die der Lesevorgang zukünfig
                                                // gültig sein soll, und das Relais geschaltet werden 
                                                // soll.
void setup() {
  pinMode(RST_PIN,OUTPUT);
  pinMode(RELAIS_PIN,OUTPUT);
  pinMode(RGBLED_R,OUTPUT);
  pinMode(RGBLED_G,OUTPUT);
  pinMode(RGBLED_B,OUTPUT);
  digitalWrite(RELAIS_PIN,HIGH);    // Relais inaktiv
  digitalWrite(RST_PIN,HIGH);
  digitalWrite(RGBLED_R,LOW);       //Led AUS
  digitalWrite(RGBLED_G,LOW);
  digitalWrite(RGBLED_B,LOW);
  Serial.begin(9600);               // Serielle Kommunikation mit dem PC initialisieren
  Serial.println("Ser. Komm. OK."); 
  SPI.begin();                      // Initialisiere SPI Kommunikation
  digitalWrite(RST_PIN,LOW);
  delay(300);
  digitalWrite(RST_PIN,HIGH);
  mfrc522.PCD_Reset();
  mfrc522.PCD_Init();               // Initialisiere MFRC522 Lesemodul
  mfrc522.PCD_AntennaOn();
  yield();
   
  digitalWrite(RGBLED_R,HIGH);     //Led Farbe Lila Initalisierung abgeschlossen
  digitalWrite(RGBLED_G,LOW);
  digitalWrite(RGBLED_B,HIGH);
  
}
 
void loop()  // Diese Funktion wird in Endlosschleife ausgeführt
{

  // Nur wenn eine Karte gefunden wird und gelesen werden konnte, wird der Inhalt von IF ausgeführt

  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial() )   // PICC = proximity integrated circuit card = kontaktlose Chipkarte
  {

    Serial.print("PICC UID:");
    for (byte i = 0; i < mfrc522.uid.size; i++) 
    {
      // Abstand zwischen HEX-Zahlen und führende Null bei Byte < 16
      Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
      Serial.print(mfrc522.uid.uidByte[i], HEX);
 
    } 
 bool IsValid = true;
   for (byte i = 0; i < sizeof(myValidCardUID); i++) 
    {
    if (mfrc522.uid.uidByte[i] != myValidCardUID[i]) { IsValid = false; }
      
    }
   if (IsValid)
   {
      bool PinState= digitalRead(RELAIS_PIN);
      PinState = !PinState;
      digitalWrite(RELAIS_PIN, PinState);     
      digitalWrite(RGBLED_R,LOW);     //Led Grün
      digitalWrite(RGBLED_G,HIGH);
      digitalWrite(RGBLED_B,LOW);
      Serial.print("  gültig.");
      delay(2000);
      digitalWrite(RGBLED_R,LOW);     //Led Farbe Blau Leser ist in Grundzustand
      digitalWrite(RGBLED_G,LOW);
      digitalWrite(RGBLED_B,HIGH); 
   } else
   { 
      digitalWrite(RGBLED_R,HIGH);     //Led Rot - Letzte Karte war ungültig
      digitalWrite(RGBLED_G,LOW);
      digitalWrite(RGBLED_B,LOW);
      Serial.print(" ungültig.");
      delay(2000);   
   }
 

    
    Serial.println(); 
 
    // Versetzt die gelesene Karte in einen Ruhemodus, um nach anderen Karten suchen zu können.
    mfrc522.PICC_HaltA();
    delay(1000);
  }
 
  yield(); // interne ESP8266 Funktionen aufrufen
}


