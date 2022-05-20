import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;

public class ErmacDecrypt {
    public static final String KEY = "sosi_sosison____";
    public byte [] key = null;
    
    public ErmacDecrypt() throws UnsupportedEncodingException {
	this.key = KEY.getBytes("UTF-8");
    }

    public String decrypt(String input) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException {
	byte [] decoded = Base64.getDecoder().decode(input);
	String decoded_str = new String(decoded);
	String [] data_iv = decoded_str.split("::", 2);
	byte [] ciphertext = Base64.getDecoder().decode(data_iv[0]);
	byte [] iv = Base64.getDecoder().decode(data_iv[1]);
	
	SecretKeySpec sks = new SecretKeySpec(this.key, "AES");
	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	cipher.init(2, sks, new IvParameterSpec(iv));
	byte [] decrypted = cipher.doFinal(ciphertext);
	return new String(decrypted, "UTF-8");
    }

    public static void main(String [] args) {
	try {
	    ErmacDecrypt ermac = new ErmacDecrypt();
	    System.out.println(ermac.decrypt("N093Zm5qYnhxWjFLUUZ2TVVvL04zZz09OjpGL2dlaTZPOTZ3anp0M25qZGJxMjB3PT0="));
	}
	catch(Exception exp) {
	    System.out.println("Exception: "+exp.toString());
	}
	
    }
}
