/*
 * Spritz
 * A spongy RC4-like stream cipher and hash function
 *
 * Public Domain (P) October, 2014
 *
 * Ronald L. Rivest
 * Jacob C. N. Schuldt
 *
 * Translated to Java, Steve Sampson, November 2014
 */
package spritz;

public final class Spritz {

    private static final int N = 256;
    //
    private short i_register;     // size short for unsigned byte
    private short j_register;
    private short k_register;
    private short z_register;
    private short a_register;
    private short w_register;
    private byte[] S_BOX;
    //
    private short i_register_p;
    private short j_register_p;
    private short k_register_p;
    private short z_register_p;
    private short a_register_p;
    private short w_register_p;
    private byte[] S_BOX_P;

    public Spritz() {
        this.S_BOX = new byte[N];
    }

    public void initialize() {
        this.i_register = 0;
        this.j_register = 0;
        this.k_register = 0;
        this.z_register = 0;
        this.a_register = 0;
        this.w_register = 1;

        for (int loop = 0; loop < N; loop++) {
            this.S_BOX[loop] = (byte) loop;
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
        this.S_BOX_P = this.S_BOX.clone();
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
        this.S_BOX = this.S_BOX_P.clone();
    }

    private int low(int val1) {
        return val1 & 0x0F;
    }

    private int high(int val1) {
        return (val1 >>> 4) & 0xF;
    }

    private void swap(int val1, int val2) {
        byte temp = this.S_BOX[val1];
        this.S_BOX[val1] = this.S_BOX[val2];
        this.S_BOX[val2] = temp;
    }

    private void update() {
        // simulate unsigned

        int temp1 = (this.i_register + this.w_register) & 0xFF;
        this.i_register = (short) temp1;

        int temp2 = this.S_BOX[this.i_register];
        temp2 = (this.j_register + (temp2 < 0 ? 256 + temp2 : temp2)) & 0xFF;

        int temp3 = this.S_BOX[temp2];
        temp3 = this.k_register + (temp3 < 0 ? 256 + temp3 : temp3);
        this.j_register = (short) (temp3 & 0xFF);

        int temp4 = this.S_BOX[this.j_register];
        temp4 = temp4 < 0 ? 256 + temp4 : temp4;

        int temp5 = (this.i_register + this.k_register) & 0xFF;
        this.k_register = (short) ((temp5 + temp4) & 0xFF);

        swap(this.i_register, this.j_register);
    }

    private void whip() {
        for (int loop = 0; loop < N * 2; loop++) {
            update();
        }

        this.w_register = (short) ((this.w_register + 2) & 0xFF);
    }

    private void crush() {
        for (int loop = 0; loop < N / 2; loop++) {
            int temp = ((N - 1) - loop) & 0xFF;

            int c1 = (this.S_BOX[loop] < 0 ? 256 + this.S_BOX[loop] : this.S_BOX[loop]);
            int c2 = (this.S_BOX[temp] < 0 ? 256 + this.S_BOX[temp] : this.S_BOX[temp]);

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
        this.a_register = 0;
    }

    private void squeeze(byte[] array) {
        if (this.a_register > 0) {
            shuffle();
        }

        for (int loop = 0; loop < array.length; loop++) {
            array[loop] = (byte) drip();
        }
    }

    private void absorbNibble(int val1) {
        if (this.a_register == N / 2) {
            shuffle();
        }

        swap(this.a_register, (N / 2 + val1) & 0xFF);
        this.a_register = (short) ((this.a_register + 1) & 0xFF);
    }

    private void absorbByte(int val1) {
        absorbNibble(low(val1));
        absorbNibble(high(val1));
    }

    public void absorb(byte[] array) {
        for (int loop = 0; loop < array.length; loop++) {
            absorbByte((array[loop] < 0 ? 256 + array[loop] : array[loop]));
        }
    }

    public void absorbStop() {
        if (this.a_register == N / 2) {
            shuffle();
        }

        this.a_register = (short) ((this.a_register + 1) & 0xFF);
    }

    public int drip() {
        if (this.a_register > 0) {
            shuffle();
        }

        update();

        // simulate unsigned
        int temp1 = (this.z_register + this.k_register) & 0xFF;

        int temp2 = this.S_BOX[temp1];
        temp2 = (this.i_register + (temp2 < 0 ? 256 + temp2 : temp2)) & 0xFF;

        int temp3 = this.S_BOX[temp2];
        temp3 = (this.j_register + (temp3 < 0 ? 256 + temp3 : temp3)) & 0xFF;

        int temp4 = this.S_BOX[temp3];
        temp4 = temp4 < 0 ? 256 + temp4 : temp4;

        this.z_register = (short) temp4;

        return temp4;
    }

    public byte[] hash(byte[] array, int length) {
        initialize();

        int hashlen = (length > 255) ? 255 : length;
        byte[] output = new byte[hashlen];

        absorb(array);
        absorbStop();
        absorbByte(hashlen);
        squeeze(output);

        return output;
    }
}
