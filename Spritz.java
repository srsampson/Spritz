/*
 * Spritz.java
 *
 * A spongy RC4-like stream cipher and hash function
 *
 * Ronald L. Rivest
 * Jacob C. N. Schuldt
 *
 * Programmers: Steve Sampson, 2014
 */

public final class Spritz {

    private static final int N = 256;
    //
    private short i_register;     // size short for unsigned byte
    private short j_register;
    private short k_register;
    private short z_register;
    private short a_register;
    private short w_register;
    //
    private byte[] S_BOX;
    //
    private short i_register_p;
    private short j_register_p;
    private short k_register_p;
    private short z_register_p;
    private short a_register_p;
    private short w_register_p;
    //
    private byte[] S_BOX_P;

    public Spritz() {
        S_BOX = new byte[N];
    }

    public void initialize() {
        i_register = 0;
        j_register = 0;
        k_register = 0;
        z_register = 0;
        a_register = 0;
        w_register = 1;

        for (int loop = 0; loop < N; loop++) {
            S_BOX[loop] = (byte) loop;
        }
    }

    /*
     * The prime s-box stores the keyed s-box, so we don't have to do this
     * multiple times with a different IV.
     */
    public void setPrime() {
        i_register_p = i_register;
        j_register_p = j_register;
        k_register_p = k_register;
        z_register_p = z_register;
        a_register_p = a_register;
        w_register_p = w_register;
        
        S_BOX_P = S_BOX.clone();
    }

    /*
     * When starting a new frame with the same key, we preload the s-box with
     * the keyed s-box from initialization. At this point we can add in the IV.
     */
    public void getPrime() {
        i_register = i_register_p;
        j_register = j_register_p;
        k_register = k_register_p;
        z_register = z_register_p;
        a_register = a_register_p;
        w_register = w_register_p;
        
        S_BOX = S_BOX_P.clone();
    }

    private int low(int val1) {
        return val1 & 0x0F;
    }

    private int high(int val1) {
        return (val1 >>> 4) & 0xF;
    }

    private void swap(int val1, int val2) {
        byte temp = S_BOX[val1];
        S_BOX[val1] = S_BOX[val2];
        S_BOX[val2] = temp;
    }

    private void update() {
        // simulate unsigned

        int temp1 = (i_register + w_register) & 0xFF;
        i_register = (short) temp1;

        int temp2 = S_BOX[i_register];
        temp2 = (j_register + (temp2 < 0 ? N + temp2 : temp2)) & 0xFF;

        int temp3 = S_BOX[temp2];
        temp3 = k_register + (temp3 < 0 ? N + temp3 : temp3);
        j_register = (short) (temp3 & 0xFF);

        int temp4 = S_BOX[j_register];
        temp4 = temp4 < 0 ? N + temp4 : temp4;

        int temp5 = (i_register + k_register) & 0xFF;
        k_register = (short) ((temp5 + temp4) & 0xFF);

        swap(i_register, j_register);
    }

    private void whip() {
        for (int loop = 0; loop < (N * 2); loop++) {
            update();
        }

        w_register = (short) ((w_register + 2) & 0xFF);
    }

    private void crush() {
        for (int loop = 0; loop < N / 2; loop++) {
            int temp = ((N - 1) - loop) & 0xFF;

            int c1 = (S_BOX[loop] < 0 ? N + S_BOX[loop] : S_BOX[loop]);
            int c2 = (S_BOX[temp] < 0 ? N + S_BOX[temp] : S_BOX[temp]);

            if (c1 > c2) {
                swap(loop, temp);
            }
        }
    }

    private void shuffle() {
        whip();
        crush();
        whip();
        crush();
        whip();
        
        a_register = 0;
    }

    private void squeeze(byte[] array) {
        if (a_register > 0) {
            shuffle();
        }

        for (int loop = 0; loop < array.length; loop++) {
            array[loop] = (byte) drip();
        }
    }

    private void absorbNibble(int val1) {
        if (a_register == N / 2) {
            shuffle();
        }

        swap(a_register, (N / 2 + val1) & 0xFF);
        
        a_register = (short) ((a_register + 1) & 0xFF);
    }

    private void absorbByte(int val1) {
        absorbNibble(low(val1));
        absorbNibble(high(val1));
    }

    public void absorb(byte[] array) {
        for (int loop = 0; loop < array.length; loop++) {
            absorbByte((array[loop] < 0 ? N + array[loop] : array[loop]));
        }
    }

    public void absorbStop() {
        if (a_register == N / 2) {
            shuffle();
        }

        a_register = (short) ((a_register + 1) & 0xFF);
    }

    public int drip() {
        if (a_register > 0) {
            shuffle();
        }

        update();

        // simulate unsigned
        int temp1 = (z_register + k_register) & 0xFF;

        int temp2 = S_BOX[temp1];
        temp2 = (i_register + (temp2 < 0 ? N + temp2 : temp2)) & 0xFF;

        int temp3 = S_BOX[temp2];
        temp3 = (j_register + (temp3 < 0 ? N + temp3 : temp3)) & 0xFF;

        int temp4 = S_BOX[temp3];
        temp4 = temp4 < 0 ? N + temp4 : temp4;

        z_register = (short) temp4;

        return temp4;
    }

    /**
     * Compute a Hash value for the given message array.
     * 
     * @param array 8-bit unsigned bytes - (N - 1) bytes maximum
     * @param length Number of bytes in array
     * @return Hash of length N bytes maximum
     */
    public byte[] hash(byte[] array, int length) {
        initialize();       // init the S Box

        /*
         * Leave room for the hashlen byte
         * i.e., hash array is N bytes max
         */
        int hashlen = (length > (N - 1)) ? (N - 1) : length;
        byte[] output = new byte[hashlen];

        /*
         * Note, we don't key the S-Box
         */
        absorb(array);
        absorbStop();
        absorbByte(hashlen);
        squeeze(output);

        return output;
    }

    /**
     * Compute a MAC value for the given message array.
     * 
     * @param key 8-bit unsigned bytes cipher key - (N / 8) bytes maximum
     * @param array 8-bit unsigned bytes - (N - 1) bytes maximum
     * @param length Number of bytes in message array
     * @return MAC of length N bytes maximum
     */
    public byte[] mac(byte[] key, byte[] array, int length) {
        initialize();       // init the S Box

        int keylen = (key.length > (N / 8)) ? (N / 8) : key.length;
        byte[] keyp = new byte[keylen];
        
        for (int loop = 0; loop < keylen; loop++) {
            keyp[loop] = key[loop];
        }

        /*
         * Leave room for the hashlen byte
         * i.e., hash array is N bytes max
         */
        int hashlen = (length > (N - 1)) ? (N - 1) : length;
        byte[] output = new byte[hashlen];


        absorb(keyp);
        absorbStop();
        absorb(array);
        absorbStop();
        absorbByte(hashlen);
        squeeze(output);

        return output;
    }
}
