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
