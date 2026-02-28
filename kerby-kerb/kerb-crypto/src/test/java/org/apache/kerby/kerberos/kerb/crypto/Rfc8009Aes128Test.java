/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.crypto;

import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha256Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes128Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * RFC 8009 test vectors for etype 19: aes128-cts-hmac-sha256-128.
 * Test vectors from RFC 8009, Appendix A.
 */
public class Rfc8009Aes128Test {

    private static final EncryptionType ETYPE = EncryptionType.AES128_CTS_HMAC_SHA256_128;

    /**
     * RFC 8009, Appendix A.1: String-to-key for etype 19.
     *
     * Passphrase:  "password"
     * Salt:        16-byte random UTF-8 sequence || "ATHENA.MIT.EDUraeburn"
     * Iterations:  32768
     * saltp:       "aes128-cts-hmac-sha256-128" || 0x00 || salt
     * 128-bit key: 089BCA48B105EA6EA77CA5D2F39DC5E7
     *
     * The KDC-provided salt in the RFC 8009 Appendix A test vector includes
     * 16 specific random (but valid UTF-8) bytes before "ATHENA.MIT.EDUraeburn".
     */
    @Test
    public void testStr2Key() throws Exception {
        String password = "password";
        // RFC 8009 Appendix A.1 salt = 16 random bytes + "ATHENA.MIT.EDUraeburn" (valid UTF-8)
        byte[] randomPrefix = {0x10, (byte) 0xDF, (byte) 0x9D, (byte) 0xD7, (byte) 0x83, (byte) 0xE5,
                               (byte) 0xBC, (byte) 0x8A, (byte) 0xCE, (byte) 0xA1, 0x73, 0x0E, 0x74, 0x35, 0x5F, 0x61};
        byte[] saltSuffix = "ATHENA.MIT.EDUraeburn".getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = new byte[randomPrefix.length + saltSuffix.length];
        System.arraycopy(randomPrefix, 0, saltBytes, 0, randomPrefix.length);
        System.arraycopy(saltSuffix, 0, saltBytes, randomPrefix.length, saltSuffix.length);
        String salt = new String(saltBytes, StandardCharsets.UTF_8);
        String expectedHex = "089BCA48B105EA6EA77CA5D2F39DC5E7";

        EncryptionKey key = EncryptionHandler.string2Key(password, salt, null, ETYPE);
        String actualHex = HexUtil.bytesToHex(key.getKeyData()).toUpperCase();

        if (!actualHex.equals(expectedHex)) {
            fail("str2key mismatch for etype 19:\n  expected: " + expectedHex
                    + "\n  actual:   " + actualHex);
        }
    }

    /**
     * RFC 8009, Appendix A.2: Key derivation for etype 19 (usage 2).
     *
     * Base key: 3705D96080C17728A0E800EAB6E0D23C
     * Ke (0xAA): 9B197DD1E8C5609D6E67C3E37C62C72E
     * Ki (0x55): 9FDA0E56AB2D85E1569A688696C26A6C
     * Kc (0x99): B31A018A48F54776F403E9A396325DC3
     */
    @Test
    public void testKeyDerivation() throws Exception {
        byte[] baseKey = HexUtil.hex2bytes("3705D96080C17728A0E800EAB6E0D23C");

        AesSha2KeyMaker km = new AesSha2KeyMaker(new Aes128Provider(), new Sha256Provider());

        byte[] constantKe = HexUtil.hex2bytes("00000002AA");
        byte[] constantKi = HexUtil.hex2bytes("0000000255");
        byte[] constantKc = HexUtil.hex2bytes("0000000299");

        byte[] ke = km.dk(baseKey, constantKe);
        byte[] ki = km.dk(baseKey, constantKi);
        byte[] kc = km.dk(baseKey, constantKc);

        String expectedKe = "9B197DD1E8C5609D6E67C3E37C62C72E";
        String expectedKi = "9FDA0E56AB2D85E1569A688696C26A6C";
        String expectedKc = "B31A018A48F54776F403E9A396325DC3";

        assertDerivedKey("Ke", expectedKe, ke);
        assertDerivedKey("Ki", expectedKi, ki);
        assertDerivedKey("Kc", expectedKc, kc);
    }

    /**
     * Verify encrypt/decrypt round-trip for etype 19.
     */
    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        EncryptionKey key = EncryptionHandler.string2Key("password", "ATHENA.MIT.EDUraeburn",
                null, ETYPE);
        byte[] plaintext = "Hello, Kerby!".getBytes("UTF-8");
        KeyUsage usage = KeyUsage.AS_REQ_PA_ENC_TS;

        byte[] ciphertext = EncryptionHandler.encrypt(plaintext, key, usage).getCipher();
        byte[] decrypted = EncryptionHandler.decrypt(ciphertext, key, usage);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    /**
     * Verify PRF for etype 19.
     * RFC 8009 §6: PRF(key, seed) = HMAC-SHA256(key, "prf" || seed) truncated to 32 bytes.
     */
    @Test
    public void testPrf() throws Exception {
        EncryptionKey key = EncryptionHandler.string2Key("password", "ATHENA.MIT.EDUraeburn",
                null, ETYPE);
        EncTypeHandler handler = EncryptionHandler.getEncHandler(ETYPE);

        byte[] prfOutput = handler.prf(key.getKeyData(), "test".getBytes("UTF-8"));
        assertThat(prfOutput).hasSize(32); // SHA-256 output size
    }

    private void assertDerivedKey(String label, String expectedHex, byte[] actual) {
        byte[] expected = HexUtil.hex2bytes(expectedHex);
        if (!Arrays.equals(expected, actual)) {
            fail("Key derivation mismatch for " + label + ":\n"
                    + "  expected: " + expectedHex + "\n"
                    + "  actual:   " + HexUtil.bytesToHex(actual).toUpperCase());
        }
    }
}
