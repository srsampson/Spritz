#### Spritz - A Spritz Cipher in Java

Used to send packets with a plaintext sequence number as a nonce. Thus making a block cipher from a stream cipher.

```
+-------+--------------------------+----------+------------------+-----+
| FLAGS | Counter/Seqeuence Number |    FEC   | Encrypted Packet | CRC |
+-------+--------------------------+----------+------------------+-----+
```
#### RC4-CM (RC4 Counter Mode)

The RC4 algorithm has been modified to utilize a Sequence Number, and a Rollover Counter. The Sequence Number and Rollover Counter are like an Initial Vector (IV) with a counter (CTR). The keyed S-Box is then reset every superframe. Thus, the missing or damaged packets won't affect other packets. These sequence numbers are started off with random values each time the "transmit" button enables the start of transmission.

Each superframe is a complete unit, and the Sequence Number is incremented before each frame. When the sequence number rolls over, the Rollover counter is incremented. The Sequence Number and Rollover Counter starting values are randomly chosen each time the PTT is enabled. The sequence number is 16-bits, the rollover counter is 8-bits. These two are used along with the RC4 S-Box to provide the encryption stream, used to exclusive-or with the data.

The S-Box is reset to the initial keyed values every superframe. The number of frames in a superframe are very small due to the medium of Shortwave radio, and its changing ionosphere. So in this case (with only nine frames) the rollover counter will very likely never get incremented (unless the random 16-bit sequence number is very near the rollover point), however the algorithm is generic, and can also be used at VHF, UHF, or Microwave, with their larger packet sizes.

On receive, the combined 24-bit Sequence Number and Rollover Counter are extracted from the header, and used during decryption of the vocoder, data, or image frames.

Note 1: As of 2015, researchers have determined that one out of every 16 million RC4 keys is weak, and the number of attempts required to mount an attack is estimated to be 1 billion.

#### Possible Frame Encoding Method

The data frames can be configured in many ways. You could use 6-bit ASCII, 8-bit ASCII, or even 16-bit Unicode. Maybe even 4-bit codes for PL-Tones. You can enable many modes using the 4-bit mode and 4-bit version fields.

```
+-----------------------------------------------------------------------+
|                        CODEC2 1600 (8 Bytes)                          |
+-----------------------------------------------------------------------+
|                            VOICE FRAME                                |
+-----------------------------------------------------------------------+
     64 Bits per Frame
     40 ms

+--------+--------+--------+--------+--------+--------+--------+--------+
| BYTE 1 | BYTE 2 | BYTE 3 | BYTE 4 | BYTE 5 | BYTE 6 | BYTE 7 | BYTE 8 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                     DATA FRAME (Data, Text, Image)                    |
+-----------------------------------------------------------------------+
     64 Bits per Frame
     40 ms

     40 ms        40 ms     40 ms     40 ms                     40 ms   
     64 Bits      64 BITS   64 BITS   64 BITS                   64 BITS
+---------------+---------+---------+---------+--    ---    --+---------+   
| HEADER FRAME  | FRAME 1 | FRAME 2 | FRAME 3 |               | FRAME 9 |   
+------+--------+---------+---------+---------+--    ---    --+---------+   
| SYNC |  PDW   |       VOICE/DATA FRAME (360 ms)                       |   
+------+--------+--------------------------------    ---    ------------+   
|                              SUPERFRAME                               |   
+------------------------------------------------    ---    ------------+   
     640 Bits   
     400 ms   

+---------+---------+---------+---------+
|   0x1A  |   0xCF  |   0xFC  |   0x1D  |
+---------+---------+---------+---------+
|               SYNC WORD               |
+---------------------------------------+
     32 bits
     20 ms

 4 Bits  4 Bits    8 Bits     16 Bits
+-------+-------+----------+------------+
|VERSION| MODE  | ROLLOVER | SEQUENCE # |
+-------+-------+----------+------------+
|        PACKET DEFINITION WORD         |
+---------------------------------------+
     32 Bits
     20 ms

Version = 0000
Mode = 0001 Voice Frame
Mode = 0010 Data Frame
Mode = 0011 Image Frame
Mode = 0111 PL Tone Frame
```
