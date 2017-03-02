/** 
 * Quick ugly code to decrypt files downloaded by Dba.jar
 * Mimicks b.b.b.a.b
 * Input: file to decrypt
 * Output: a file with '.decrypted' appended to the name is created
 *
 * Example: 
 * $ java DbaXor bx
 * Decrypting downloaded file bx
 * 
 * A. Apvrille
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;

public class DbaXor {
    public static void copyAndXor(String input, String output) {
        int i;
        byte[] decrypted;
        byte[] encrypted;
        byte[] inputbuf;
        try {
            FileInputStream v2 = new FileInputStream(input);
            int inputlen = v2.available();
            if(inputlen < 30) {
		System.out.println("Input file is too short");
                v2.close();
            }

            inputbuf = new byte[inputlen];
            v2.read(inputbuf);
            v2.close();
            byte[] v2_1 = new byte[5];
            byte[] v4 = new byte[5];
            encrypted = new byte[5];
            decrypted = new byte[5];
            System.arraycopy(inputbuf, 0, v2_1, 0, 5);
            System.arraycopy(inputbuf, 5, v4, 0, 5);
            System.arraycopy(inputbuf, inputbuf.length - 5, encrypted, 0, 5);
            System.arraycopy(inputbuf, inputbuf.length - 10, decrypted, 0, 5);
	    
	    FileOutputStream fos = new FileOutputStream(output);
	    encrypted = new byte[10];
	    System.arraycopy(inputbuf, 10, encrypted, 0, 10);
	    decrypted = new byte[inputbuf.length - 30];
	    System.arraycopy(inputbuf, 20, decrypted, 0, decrypted.length);
	    for(i = 0; i < decrypted.length; ++i) {
		decrypted[i] = ((byte)(encrypted[i % 10] ^ decrypted[i]));
	    }

	    fos.write(decrypted);
	    fos.close();
	}
	catch(Exception v1) {
            v1.printStackTrace();
        }
    }

    public static void main(String args[]) {
	// Supply filename to decrypt as argument
	// Yes, this is quick and ugly - no input check
	System.out.println("Decrypting downloaded file " +args[0]);
	String output_name = args[0] + ".decrypted";
	DbaXor.copyAndXor(args[0],output_name);
    }
}
