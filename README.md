#### Spritz - A Spritz Cipher in Java

Used to send packets with a plaintext sequence number as a nonce. Thus making a block cipher from a stream cipher.

```
+-------+--------------------------+----------+------------------+-----+
| FLAGS | Counter/Seqeuence Number |    FEC   | Encrypted Packet | CRC |
+-------+--------------------------+----------+------------------+-----+
```
