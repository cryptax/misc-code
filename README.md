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

## Android/Bahamut

Malware sha256: `fd1aac87399ad22234c503d8adb2ae9f0d950b6edf4456b1515a30100b5656a7`

- `bahamutDecrypt.py`: decrypts files or strings encrypted by the malware


## Android/BianLian

Malware sha256: `5b9049c392eaf83b12b98419f14ece1b00042592b003a17e4e6f0fb466281368`

- [UnpackJwi.java](https://github.com/cryptax/misc-code/blob/master/bianlian/UnpackJwi.java): unpacks the encrypted asset file
- [fakebianserver](https://github.com/cryptax/misc-code/blob/master/bianlian/fakebianserver.py): fake C&C template

## JsonPacker

- [jsondecrypt.py](https://github.com/cryptax/misc-code/blob/master/bianlian/jsondecrypt.py): unpacked JsonPacked asset file, provided you know the short key.
- Same, but Java implementation

## Android/Joker

Malware sha256: `afeb6efad25ed7bf1bc183c19ab5b59ccf799d46e620a5d1257d32669bedff6f`

- `JokerDecryptPBE.java`

## KangaPack

- Unpacker: `kangaunpack.py`
- Malware sha256: `2c05efa757744cb01346fe6b39e9ef8ea2582d27481a441eb885c5c4dcd2b65b`

## Flutter

- Radare 2 plugin to process byte arrays
- Python script to parse Flutter AOT headers
- Python script to search for Dart object uses in Object Pool of flutter libapp.so Aarch64
