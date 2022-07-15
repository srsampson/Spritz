/*
 * Public Domain (P) 2014 Steve Sampson
 *
 * No rights reserved
 * 
 * 16 bit nonce version
 */

import java.security.InvalidKeyException;
import java.security.SecureRandom;

public final class Crypto {

    private static final int KEYBYTES = 16;
    //
    private final SecureRandom random; // only used to generate seed
    private int SN;                    // sequence number  (0000..FFFF)
    private final Spritz spritz;       // cipher engine
    private final byte[] iv;

    public Crypto16() {
        spritz = new Spritz();
        iv = new byte[2];
        random = new SecureRandom();
        random.generateSeed(KEYBYTES);
    }

    /*
     * We decide here that 128 bit keys are sufficient
     */
    public void setKey(byte[] key) throws InvalidKeyException {
        if (key.length != KEYBYTES) {
            throw new InvalidKeyException("Fatal: Key length must be " + (KEYBYTES * 8) + " bits");
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
        SN = random.nextInt(65536);             // 2^16

        iv[0] = (byte) ((SN >>> 8) & 0xFF);     // msb
        iv[1] = (byte) (SN & 0xFF);             // lsb

        spritz.getPrime();      // note: getPrime() inludes an absorbStop() internally
        spritz.absorb(iv);
    }

    /**
     * Method to increment the 16-bit sequence number
     * 
     * @return 16 bit sequence number
     */
    public int newSendPacket() {
        // increment sequence number
        SN = ((SN + 1) % 65536) & 0xFFFF;       // 16 bits

        iv[0] = (byte) ((SN >>> 8) & 0xFF);     // msb
        iv[1] = (byte) (SN & 0xFF);             // lsb
        
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

        iv[0] = (byte) ((SN >>> 8) & 0xFF);
        iv[1] = (byte) (SN & 0xFF);
        
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
