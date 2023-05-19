# RSA-Verschlüsselung Java-Programm

Dieses Java-Programm führt die Generierung von RSA-Schlüsselpaaren, Verschlüsselung und Entschlüsselung von Textdateien durch.

## Anleitung

- Datei entschlüsseln: Methoden `generateKeyPair()` und `encryptFile(...)` auskommentieren, da sonst die Key-Paare überschrieben werden. Main-Methode ausführen.
- Datei verschüsseln: Methoden `generateKeyPair()` und `encryptFile(...)` *nicht* auskommentieren, da sonst die Key-Paare überschrieben werden. Main-Methode ausführen.

## Ablauf

1. Generierung eines RSA-Schlüsselpaars (1024 Bit)
2. Verschlüsselung einer Textdatei (ASCII) namens `text.txt` mit dem öffentlichen Schlüssel aus der Datei `pk.txt`
3. Entschlüsselung einer Datei namens `chiffre.txt` mit dem privaten Schlüssel aus der Datei `sk.txt`
4. Ausgabe des entschlüsselten Textes in der Datei `text-d.txt`

## Dateien

- `sk.txt`: Speichert den privaten Schlüssel (n, d) in Dezimaldarstellung
- `pk.txt`: Speichert den öffentlichen Schlüssel (n, e) in Dezimaldarstellung
- `text.txt`: Enthält den zu verschlüsselnden Text im ASCII-Format
- `chiffre.txt`: Enthält den verschlüsselten Text in Dezimaldarstellung, wobei die einzelnen Verschlüsselungen durch Kommas getrennt sind
- `text-d.txt`: Enthält den entschlüsselten Text nach der Verarbeitung von `chiffre.txt`

## Arbeitsgruppe

Tugce Nur Tas | Saskia Bosshard | Laurin Scheuber

## Verschlüsselter Lösungstext

"Das haben Sie gut gemacht!"
