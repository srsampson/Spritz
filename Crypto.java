/*
 * Public Domain (P) 2014 Steve Sampson
 *
 * No rights reserved
 */
package dv;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import spritz.Spritz;

public final class Crypto {

    private final SecureRandom random; // only used to generate seed
    private int SN;                    // sequence number  (000000..FFFFFF)
    private final Spritz spritz;       // cipher engine
    private final byte[] iv;

    public Crypto() {
        spritz = new Spritz();
        iv = new byte[3];
        random = new SecureRandom();
        random.generateSeed(16);
    }

    public void setKey(byte[] key) throws InvalidKeyException {
        if (key.length != 16) {
            throw new InvalidKeyException("Fatal: Key length must be 128 bits");
        }
        
        spritz.initialize();
        spritz.absorb(key);
        spritz.absorbStop();
        spritz.setPrime();
    }

    /**
     * Method called when starting a new transmit session
     */
    public void newSequenceNumber() {
        SN = random.nextInt(16777216);          // 2^24

        iv[0] = (byte) ((SN >>> 16) & 0xFF);    // msb
        iv[1] = (byte) ((SN >>> 8) & 0xFF);
        iv[2] = (byte) (SN & 0xFF);             // lsb

        spritz.getPrime();
        spritz.absorb(iv);
    }

    /**
     * Method to increment the 24-bit sequence number
     * 
     * @return 24 bit sequence number
     */
    public int newSendPacket() {
        // increment sequence number
        SN = ((SN + 1) % 16777216) & 0xFFFFFF;  // 24 bits

        iv[0] = (byte) ((SN >>> 16) & 0xFF);    // msb
        iv[1] = (byte) ((SN >>> 8) & 0xFF);
        iv[2] = (byte) (SN & 0xFF);             // lsb
        
        spritz.getPrime();
        spritz.absorb(iv);
        
        return SN;
    }

    /**
     * Method to set the sequence number
     *
     * @param sequence new value
     */
    public void newReceivePacket(int sequence) {
        SN = sequence;

        iv[0] = (byte) ((SN >>> 16) & 0xFF);
        iv[1] = (byte) ((SN >>> 8) & 0xFF);
        iv[2] = (byte) (SN & 0xFF);
        
        spritz.getPrime();
        spritz.absorb(iv);
    }

    /**
     * Method used for encryption
     *
     * @param src an array of bytes to be operated on
     * @param dest an array of bytes that result from the operation
     */
    public void encrypt(byte[] src, byte[] dest) {
        for (int loop = 0; loop < src.length; loop++) {
            dest[loop] = (byte) ((src[loop] + spritz.drip()) & 0xFF);
        }
    }

    /**
     * Method used for decryption
     *
     * @param src an array of bytes to be operated on
     * @param dest an array of bytes that result from the operation
     */
    public void decrypt(byte[] src, byte[] dest) {
        for (int loop = 0; loop < src.length; loop++) {
            dest[loop] = (byte) ((src[loop] - spritz.drip()) & 0xFF);
        }
    }
}
