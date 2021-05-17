import java.io.*;
import java.util.zip.InflaterInputStream;

/*
  Sample aad80d2ad20fe318f19b6197b76937bf7177dbb1746b7849dd7f05aab84e6724
  uses a packer that XORs + Unzips assets.
  The unzipping is performed natively in the malicious sample.
  This standalone Java program "decrypts" the asset
  
  @cryptax - May 17, 2021

  java MoqHaoUnpacker ./efl15a
  
*/
 

public class MoqHaoUnpacker {
    public static void unzip(OutputStream output, byte[] buf, InputStream input) throws IOException {
        InputStream is = new InflaterInputStream(input);
        while(true) {
            int len = is.read(buf);
            if(len == -1) {
                break;
            }

            output.write(buf, 0, len);
        }

        is.close();
    }
    
    public static void xor_and_unzip(ByteArrayOutputStream output, InputStream input, int len, int xorkey) throws IOException {
        ByteArrayOutputStream bytearray = new ByteArrayOutputStream();
        byte[] buf = new byte[0x1000];
	System.out.println("xor_and_unzip(): len="+len+ " xorkey="+xorkey);
        while(true) {
            int v2 = input.read(buf, 0, Math.min(len, 0x1000));
            if(v2 == -1 || v2 == 0) {
                break;
            }

            len -= v2;
            int v4;
            for(v4 = 0; v4 < v2; ++v4) {
                buf[v4] = (byte)(buf[v4] ^ xorkey);
            }

            bytearray.write(buf, 0, v2);
        }

        MoqHaoUnpacker.unzip(output, buf, ((InputStream)new ByteArrayInputStream(bytearray.toByteArray())));
    }
    
    public static void main(String args[]) {
	System.out.println("Decrypting asset: "+args[0]);
	try {
	    ByteArrayOutputStream output = new ByteArrayOutputStream();
	    InputStream fis = new FileInputStream(args[0]);
	    byte[] v0 = new byte[11];
	    fis.read(v0);
	    MoqHaoUnpacker.xor_and_unzip(output, fis, (v0[9] & 0xFF) << 8 | (v0[8] & 0xFF) << 16 | v0[10] & 0xFF, fis.read());
	    System.out.println("Dumping to file...");
	    byte[] v0_1 = output.toByteArray();
	    FileOutputStream v2_1 = new FileOutputStream(args[0]+".decrypted");
	    v2_1.write(v0_1);
	    v2_1.close();
	    
	} catch(Exception exp) {
	    System.out.println("ERROR. Something weird occurred: "+exp.getMessage());
	}
    }
}

