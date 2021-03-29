import java.util.ArrayList;
import java.util.Calendar;
import java.util.Random;

public class DGA {
    private static final int MAX_HOSTS = 5000;
    private static long seed;

    public static void FindHost() {
        String v7_1;
            DGA.GetSeed();
            Random v3 = new Random(DGA.seed);
            ArrayList v4 = new ArrayList();
            int v6;
            for(v6 = 0; v6 < MAX_HOSTS; ++v6) {
                String space = " ";
                int v8;
                for(v8 = 0; v8 < 15; ++v8) {
                    space = space + ((char)(v3.nextInt(25) + 97));
                }

                if(v6 % 3 == 0) {
                    // .ru
                    v7_1 = space + ".ru";
                }
                else {
                    v7_1 = v6 % 2 == 0 ? space + ".com" : space + ".cn";
                }

                v4.add(v7_1);
            }

	    for (int i=0; i<v4.size(); i++) {
		System.out.println(v4.get(i));
	    }
	    System.out.println("Size: "+v4.size());
	    
	}

    private static void GetSeed() {
        int v0 = Calendar.getInstance().get(1);
        int v1 = Calendar.getInstance().get(2);
        long v4 = (long)(v0 ^ v1 ^ 0);
        DGA.seed = v4;
        long v4_1 = v4 * 2L;
        DGA.seed = v4_1;
        long v4_2 = v4_1 * (((long)v0) ^ v4_1);
        DGA.seed = v4_2;
        long v4_3 = v4_2 * (((long)v1) ^ v4_2);
        DGA.seed = v4_3;
        long v4_4 = v4_3 * (0L ^ v4_3);
        DGA.seed = v4_4;
        DGA.seed = v4_4 + 0x799L;
    }

    public static void main(String args[]) {
	DGA.FindHost();
    }
}

