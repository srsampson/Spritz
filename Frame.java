/*
 * Frame.java
 *
 * Voice Encryption Frames
 */

public final class Frame {

    private final byte[] pdw;     // 32-bit SYNC + 32-bit Packet Definition Word

    public Frame(int vers, int mode) {
        this.pdw = new byte[Main.cbpf];                                         // 8 bytes
        System.arraycopy(Main.sync, 0, this.pdw, 0, Main.sync.length);          // 4 bytes
        this.pdw[4] = (byte) (((vers & 0x0F) << 4 | (mode & 0x0F)) & 0xFF);     // 1 byte
    }

    /**
     * Method to change the Version and Mode nibbles
     * 
     * @param vers an int representing the current version (4-bits)
     * @param mode an int representing the current mode (4-bits)
     */
    public void changeVersionMode(int vers, int mode) {
        this.pdw[4] = (byte) (((vers & 0x0F) << 4 | (mode & 0x0F)) & 0xFF);     // 1 byte
    }

    /**
     * Method to convert an array of bytes to bits
     * 
     * @param data an array of 8 bytes
     * @return an array of 64 boolean bits
     */
    private boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[Main.cbpf];
        int bit, byten;

        // unpack bits
        bit = 7;
        byten = 0;

        for (int i = 0; i < Main.cbpf; i++) {                       // 64 bits
            bits[i] = ((data[byten] >>> bit) & 0x1) == 1;
            bit--;

            if (bit < 0) {
                bit = 7;
                byten++;
            }
        }

        return bits;
    }

    /**
     * A Method to produce the next Header frame
     * 
     * @param sequenceNumber a pointer to an integer containing the next value
     * @param rollover a pointer to an integer containing the next value
     * @return an array of 64 boolean bits
     */
    public boolean[] getNextFrameHeader(int[] sequenceNumber, int[] rollover) {
        this.pdw[5] = (byte) (rollover[0] & 0xFF);
        this.pdw[6] = (byte) ((sequenceNumber[0] >> 8) & 0xFF);      // msb
        this.pdw[7] = (byte) (sequenceNumber[0] & 0xFF);             // lsb

        return bytesToBits(this.pdw);
    }

    /**
     * A method to produce the next Data frame
     * 
     * @param data an array of bytes to be converted to bits
     * @return an array of 64 boolean bits
     */
    public boolean[] getNextFrameData(byte[] data) {
        return bytesToBits(data);
    }
}
