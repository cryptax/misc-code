import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/* Unpacks malware 2877b27f1b6c7db466351618dda4f05d6a15e9a26028f3fc064fa144ec3a1850 
 * @cryptax - June 24, 2022
 * For other sample, you need to adapt the key... and possibly more ;)
*/

public class UnpackJson {
    public String key = "Ianj";

    public UnpackJson(String key) {
        this.key = key;
    }

    private void swap(int a, int b, int[] array) {
        int tmp = array[a];
        array[a]=array[b];
        array[b]=tmp;
    }
    
    private int[] convert_key(byte[] key) {
        int[] convertedkey = new int[0x100];
        int i;
        for(i = 0; i < 256; ++i) {
            convertedkey[i] = i;  // init
        }
        int j = 0;
        int k = 0;
        while(j < 0x100) {
            int cv = convertedkey[j];
            k = (k+cv+key[j%key.length]+0x100) %  0x100;
            swap(j, k, convertedkey);  // swap values
            ++j;
        }
        return convertedkey;
    }

    public byte [] decrypt(byte [] encrypted, int len) {
        byte [] key = this.key.getBytes();
        int [] ckey = convert_key(key);
        byte [] decrypted = new byte[len];
        int i, counter, other_counter;
        for (i=0, counter=0, other_counter=0; i<len; i++) {
            counter = (counter+1) % 0x100;
            other_counter = (other_counter + ckey[counter]) % 0x100;
            swap(counter, other_counter, ckey);
            decrypted[i] = (byte) (ckey[(ckey[counter] + ckey[other_counter]) % 0x100] ^ encrypted[i]); 
        }
        return decrypted;
    }

    public static void main(String [] args) {
        try {
            String in_filename = args[0];
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(in_filename));
            System.out.println("Reading file="+in_filename);

            int MAXSIZE = 0x300000;
            byte [] encrypted = new byte[MAXSIZE];
            int nbread = bis.read(encrypted);
            bis.close();
            System.out.println("Read "+nbread+" bytes");

            UnpackJson unpack = new UnpackJson("Ianj");
            System.out.println("Decrypting...");
            byte [] decrypted = unpack.decrypt(encrypted, nbread);

            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(in_filename+".decrypted"));
            bos.write(decrypted);
            bos.close();
            System.out.println("Decrypted file wrote in "+in_filename+".decrypted");
        }
        catch(Exception exp){
            System.out.println("Exception caught: "+exp.toString());
        }
    }
}