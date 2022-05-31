import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

/**
 * This program unpacks malicious sample 
 * SHA256: 5b9049c392eaf83b12b98419f14ece1b00042592b003a17e4e6f0fb466281368
 *
 * In this sample, a packed DEX is included in ./assets/7G8Uwty/G9ugwFtIG1.jwi
 * in an "encrypted" format
 * 
 * Get the jwi file and put it in the same dir as this program (or customize the program :)
 * run and retrieve the unpacked DEX for analysis :)
 *
 * NB. This is crappy Java code, with some parts copied from disassembly. Sorry.
 *
 * December 16, 2021
 * @cryptax
 * Kudos to @U039b and @0xabc0
 *
 * How to use:
 *
 * javac UnpackJwi.java
 * cp ./assets/7G8Uwty/G9ugwFtIG1.jwi .
 * java UnpackJwi
 * unzip unpacked.zip
 *
 * Then analyze classes.dex
 */


public class UnpackJwi {
    

    /**
     * Decrypts the input stream
     * key is the "encryption/decryption"  key
     * input stream containing the encrypted data
     * output stream containing the decrypted data (the DEX!)
     */
    public static void decrypt(String key, InputStream is, OutputStream os) throws IOException {
        char[] keychars = key.toCharArray();
        char v2 = keychars[0];
        char v3 = keychars[1];
        char v4 = keychars[2];
        char v5 = keychars[3];
        char v6 = keychars[4];
        char v7 = keychars[5];
        char v8 = keychars[6];
        char v9 = keychars[7];
        char v10 = keychars[8];
        char v11 = keychars[9];
        char v12 = keychars[10];
        char v13 = keychars[11];

	/* see com.brazzers.naughty.k.a() -- remove junk code */

	byte[] buf = new byte[0x2000];
	int pos = 0;
	int i = pos;
	for (pos = 0; true; pos = i) {
	    int len = is.read(buf);
	    if (len<0) {
		System.out.println("decode(): finished reading");
		return;
	    }
	    System.out.println("decode(): processing "+len+" bytes...");

	    /* home-made algorithm */
	    int index = 0;
	    i = pos;
	    while(i < pos + len) {
		buf[index] = (byte)(((byte)(new int[]{v11 << 16 | v10, v13 << 16 | v12}[i % 8 / 4] >> (i % 4 << 3))) ^ buf[index]);
		++i;
		++index;
	    }

	    /* write the "decrypted" buffer */
	    os.write(buf, 0, len);
	}
    }

    public static void unpack_asset(String key, String packed_asset, String output_zipname) throws FileNotFoundException, IOException {
	ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output_zipname)));
	System.out.println("[+] Initialized ZIP file "+output_zipname);
	
	ZipEntry classes_entry = new ZipEntry("classes.dex");
	zos.putNextEntry(classes_entry);
	System.out.println("[+] Creating classes.dex in ZIP file");
	
	FileInputStream fis = new FileInputStream(packed_asset);
	InflaterInputStream iis = new InflaterInputStream(fis);
	System.out.println("[+] Uncompressing data in the *deflate* compression format");
	
	InflaterOutputStream ios = new InflaterOutputStream(zos);
	decrypt(key, iis, ios);
	System.out.println("[+] Decrypted");
	ios.close();
	iis.close();
	zos.close();
    }
    
    public static void main(String args[]) {
	System.out.println("-----==== UnpackJwi ====-----");
	
	try {
	    String key = "GIUh9JHGUIGIUHGokfewrofij58YV6UhYUF7gjhgv";
	    String asset = "7pjwG78hg1.6t8";
	    String output_name = "unpacked.zip";
	    
	    UnpackJwi.unpack_asset(key, asset, output_name);
	}
	catch (Exception exp){
	    System.out.println("main(): Exception occurred: "+ exp.toString());
	    exp.printStackTrace(System.out);
	}
	System.out.println("-------------------------------------------");
    }
}
