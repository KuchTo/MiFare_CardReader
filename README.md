# MiFare_CardReader
ESP8266 based MiFare Classic Card Reader / Card Writer with embedded Webserver

Viele Card Reader- Projekte, mit dem MF522 Chipsatz als Basis uns dem Arduino die ich persönlich schon gesehen habe, nutzen leider weder in Sicherheitstechnisch noch in Möglichkeiten das aus, was uns die Mifare- Classic Karte an Funktionen bietet.
Diese Projekte beschränken sich darauf, die frei für jeden Kartenleser und Handys lesbare Unique ID (UUID) der Karte zu lesen und diese gegen eine Liste von erlaubten UUID's gegen zu prüfen. Ist diese in der Liste enthalten, wird die Karte als gültig angesehen. 
Dieses Projekt nutzt die integrierten Datenbereiche der MiFare Classic Kate und legt Daten dort ab.
Dazu sind vom Hersteller bereits auf der Karte 16 Sektoren (0-15) mit je 4 * 16 Bytes vorhanden bei denen, mit Ausnahme des Sektors 0 , 3 * 16 Byte frei beschrieben werden können. 16 Bytes eines jeden Sektors werden Sektor Trailer genannt und zur Ablage der 2 Sektorenschlüssel und zur Zugriffsmatrixdefinition genutzt.
Die 16 Bytes eines Sektor Trailer sind wie folgt aufgeteilt:
	6 Bytes - erster Sektorenschlüssel
	6 Bytes - zweiter Sektorenschlüssel
	4 Bytes - Zugriffsberechtigungsdefinition

Das Projekt arebitet mit einem Expressif ESP8266 Modul als Basis und einem RC522 PCD. Die Programmierung erfolgt über die Arduino IDE.
Dem Repository liegt die Quelldateien im .ino Sketch Format bei.

