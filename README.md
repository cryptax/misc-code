# Miscellaenous code

## Android/Flubot v3.6/v3.7 reverse engineering

- `./flubot/CryptaxRocks.java`: string de-obfuscation
- `./flubot/flubot.js`: Frida hook to display plaintext communication with C&C
- `./frida-hook/michaelrocks.js`: Frida hook to display de-obfuscated strings
- `./flubot/DGA.java`: standalone implementation of Flubot's DGA algorithm 

## Android/Ztorg reverse engineering

- string-decode.py: standalone Python script to de-obfuscate Ztorg strings
- DeobfuscateZtorg.py: JEB2 script to de-obfuscate Ztorg strings
- r2ztorg.py : Radare2 r2pipe script to de-obfuscated Android/Ztorg strings

## Android/MysteryBot reverse engineering

- ReplaceAllatori.py: replace the ALLATORIxDEMO obfuscated string
- JEBAllatori.py: de-obfuscation but not replacing

## c1dd9c26671fddc83c9923493236d210d7461b29dd066f743bd4794c1d647549 (malicious Tous Anti Covid)

- tous_anti.py: decrypt selected Base64+encrypted strings and put the result as comment

## Android/Alien reverse engineering

- aka Bankbot
- sha256: `ec3a10b4f38b45b7551807ba4342b111772c712c198e6a1a971dd043020f39a2`
- De-obfuscate strings: `AlienBankbotDecrypt.py`. Script for JEB4.

## Android reverse engineering (general)

- b64script.py: decode selected Base64 strings and put the result as comment

## NFC Glucose sensor tools

See ./glucose-tools directory

## Android/SpyAgent reverse engineering

- spyserv.py: Dummy server to display uncompressed messages for Android malware for malware sha256: `885d07d1532dcce08ae8e0751793ec30ed0152eee3c1321e2d051b2f0e3fa3d7`
## Android/Oji.G!worm

- `grab-oji.py`: Script to automatically grab fresh samples. This can be used to upload the samples to your favorite malware database for detection. Works as of May 7, 2021.

## Android/MoqHao

Malware sha256: `aad80d2ad20fe318f19b6197b76937bf7177dbb1746b7849dd7f05aab84e6724`

- `MoqHaoUnpacker.java`: program to unpack the sample. Provide as argument the encrypted asset. e.g. `efl15a`
