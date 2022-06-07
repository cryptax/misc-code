#!/usr/bin/env python3

# de-obfuscates strings in payload of malicious sample b2398fea148fbcab0beb8072abf47114f7dbbccd589f88ace6e33e2935d1c582
# Cryptax - May 31, 2022

KEY = "sorry!need8money[for`food"

'''
private static boolean safeChar(char c) {
        return c <= 0x20 || c > 0x7E;
    }
'''
def safeChar(c):
    if ord(c) <= 0x20 or ord(c) > 0x7E:
        return True
    return False

'''
public String wrapConstant(String input) {
        char[] wrap_key = {SdkUtilsImpl.key(5), SdkUtilsImpl.key(10), SdkUtilsImpl.key(16), SdkUtilsImpl.key(20)};
        StringBuilder output = new StringBuilder();
        int i;
        for(i = 0; i < input.length(); ++i) {
            int input_char = input.charAt(i);
            if(SdkUtilsImpl.safeChar(((char)input_char))) {
                output.append(((char)input_char));
            }
            else {
                char result = (char)(wrap_key[i % wrap_key.length] ^ input_char);
                if(SdkUtilsImpl.safeChar(result)) {
                    output.append(((char)input_char));
                }
                else {
                    output.append(result);
                }
            }
        }

        return output.toString();
    }
'''
def wrapConstant(input_msg):
    wrap_key = KEY[5]+KEY[10]+KEY[16]+KEY[20]
    output = ''
    for i in range(0, len(input_msg)):
        c = input_msg[i]
        if safeChar(c):
            output = output + c
        else:
            result = chr(ord(wrap_key[i % len(wrap_key)]) ^ ord(c))
            if safeChar(result):
                output = output + c
            else:
                output = output + result

    return output

if __name__ == '__main__':
    obfuscated = [ "@H+?MQ(t", "E]-iB]", "HV1eBL>d`H+s", "OW/iGQ8aUQ4n", \
        "GQ7e:/tO@V?rNQ??@K(eU/", "IL/p:/tiQ-:pH.8oL/1sNV", "QM(h~L4kDV", "BW.nUJ\"", "E]-iB]tsLK", "@H0s", \
            "@V?rNQ?NHV/eOLuaBL2oO.B/nl_#nuP,dlE$", "IL/p:/tiQ-:pH.8oL/1sNV" ]
    for o in obfuscated:
        print(f"obfuscated={o:30} --> {wrapConstant(o)}")
    