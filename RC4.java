/*
 * RC4.java
 *
 * Modified 56-bit key RC4 crypto algorithm
 *
 */

import java.security.InvalidKeyException;
import java.security.SecureRandom;

public final class RC4 {

    private final SecureRandom random;
    private byte[] S;
    private byte[] S_PRIMED;
    private int SN;              // sequence number  (0000..FFFF)
    private int RC;              // rollover counter (00..FF)

    public RC4() {
        random = new SecureRandom();
        random.generateSeed(16);
        S = new byte[256];
        S_PRIMED = S.clone();
        SN = random.nextInt(65536); // The counters should be completely random
        RC = random.nextInt(256);   // although this is only a requirement for encryption
    }

    public void setKey(byte[] key) throws InvalidKeyException {
        byte[] tmpi = new byte[1536];    // RFC-4345 requires first 1536 keystream bytes
        byte[] tmpo = new byte[1536];    // to be discarded.
        byte temp;
        int i;

        if (key.length != 7) {
            throw new InvalidKeyException("Fatal: Key length must be 56 bits");
        }

        for (i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }

        // Now Scramble the S-Box with the key
        // the Key is repeated as necessary to fill the array
        int j = 0;

        for (i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.length]) & 0xFF;
            temp = S[i];    // swap values at indexes
            S[i] = S[j];
            S[j] = temp;
        }

        // Burn some S-Box values to get rid of known keystream weakness
        scramble(tmpi, tmpo);   // this is only important for encryption

        S_PRIMED = S.clone();   // used to restore S-Box for each packet
    }

    /**
     * Method called when starting a new transmit session
     */
    public void newSequenceNumber() {
        SN = random.nextInt(65536); // The counters should be completely random
        RC = random.nextInt(256);   // this is a requirement for encryption
    }

    /**
     * Method to increment the sequence number and rollover counter
     *
     * @param sequence a pointer to an integer to receive the value
     * @param rollover a pointer to an integer to receive the value
     */
    public void newSendPacket(int[] sequence, int[] rollover) {
        S = S_PRIMED.clone();  // reset S-Box

        // increment sequence counter
        SN = (SN + 1) % 65536;

        // if it rolls over then increment rollover counter
        if (SN == 0) {
            RC = (RC + 1) % 256;
        }

        sequence[0] = SN;
        rollover[0] = RC;
    }

    /**
     * Method to set the sequence number and rollover counter
     *
     * @param sequence a pointer to an integer that has the new value
     * @param rollover a pointer to an integer that has the new value
     */
    public void newReceivePacket(int[] sequence, int[] rollover) {
        S = S_PRIMED.clone();  // reset S-Box

        SN = sequence[0];
        RC = rollover[0];
    }

    /**
     * Method used for both encryption and decryption<br>
     * A viable source of pseudo-random numbers
     *
     * @param src an array of bytes to be operated on
     * @param dest an array of bytes that result from the operation
     */
    public void scramble(byte[] src, byte[] dest) {
        int j = (SN >>> 8) & 0xFF;
        int i = ((SN & 0xFF) ^ S[j]) & 0xFF;
        int k = 0;

        for (int n = 0; n < src.length; n++) {
            i = (i + k) & 0xFF;
            j = (j + S[i] + S[RC]) & 0xFF;
            byte rand = S[(S[i] + S[j]) & 0xFF];
            dest[n] = (byte) (rand ^ src[n]);
            k++;
        }
    }
}
