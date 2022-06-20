import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * @cryptax, June 20, 2022
 * Decrypts strings in sample Android/Joker
 * afeb6efad25ed7bf1bc183c19ab5b59ccf799d46e620a5d1257d32669bedff6f
 */

public class JokerDecryptPBE {
    private static final int ITERATION = 100;
    private static final String ALGO = "PBEWithMD5AndDES";

    public String decryptPBE_Base64(String encrypted, String arg3, String b64_salt) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        return new String(this.decryptPBE(Base64.getDecoder().decode(encrypted), arg3, this.decodeB64(b64_salt)), "utf-8");
    }

    public byte[] decodeB64(String arg2) {
        return Base64.getDecoder().decode(arg2);
    }

    public byte[] decryptPBE(byte[] arg3, String arg4, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(arg3, this.makeKey(arg4), new PBEParameterSpec(salt, ITERATION));
    }

    private Key makeKey(String arg3) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PBEKeySpec pbekeyspec = new PBEKeySpec(arg3.toCharArray());
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGO);
        return skf.generateSecret(pbekeyspec);
    }

    private byte[] decrypt(byte[] arg3, Key arg4, AlgorithmParameterSpec arg5) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(2, arg4, arg5);
        return cipher.doFinal(arg3);
    }

    public static void main(String [] args) {
        try {
            DecryptPBE d = new JokerDecryptPBE();
            String [] encrypted = { "txxloNzRiCUGAlLCRVepAvPIOFmo4TVqlrn1EKbQpfRyVMidoBwD9FSqkFGsFz70pKXdvinmsF+iAJelVl++tw==",
            "XDpCJSIAbOiSvwxnJIKLvg==",
            "PLwnie6KHT1I2RAniSACNg==",
            "/dv+M33CuEo=",
            "1D8uwEsOqUY=" };
            String keydata = "nuff";
            String salt = "Xu7PDSGzGRs=";

            for (int i=0; i<encrypted.length; i++) {
                String decrypted = d.decryptPBE_Base64(encrypted[i], keydata, salt);
                System.out.println("Decrypted="+decrypted);
            }

        }
        catch(Exception exp){
            System.out.println("Exception: "+exp.toString());
        }
    }

}