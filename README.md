# Miscellaenous code

## Android/Flubot reverse engineering

- `CryptaxRocks.java`: string de-obfuscation

## Android/Ztorg reverse engineering

- string-decode.py: standalone Python script to de-obfuscate Ztorg strings
- DeobfuscateZtorg.py: JEB2 script to de-obfuscate Ztorg strings
- r2ztorg.py : Radare2 r2pipe script to de-obfuscated Android/Ztorg strings

## Android/MysteryBot reverse engineering

- ReplaceAllatori.py: replace the ALLATORIxDEMO obfuscated string
- JEBAllatori.py: de-obfuscation but not replacing

## c1dd9c26671fddc83c9923493236d210d7461b29dd066f743bd4794c1d647549 (malicious Tous Anti Covid)

- tous_anti.py: decrypt selected Base64+encrypted strings and put the result as comment

## Android reverse engineering (general)

- b64script.py: decode selected Base64 strings and put the result as comment

## NFC Glucose sensor tools

See ./glucose-tools directory

## Android/SpyAgent reverse engineering

- spyserv.py: Dummy server to display uncompressed messages for Android malware for malware sha256: `885d07d1532dcce08ae8e0751793ec30ed0152eee3c1321e2d051b2f0e3fa3d7`
