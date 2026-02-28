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

import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha384Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes256Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.util.CryptoUtil;
import org.apache.kerby.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * RFC 8009 test vectors for etype 20: aes256-cts-hmac-sha384-192.
 * Test vectors from RFC 8009, Appendix A.
 */
public class Rfc8009Aes256Test {

    private static final EncryptionType ETYPE = EncryptionType.AES256_CTS_HMAC_SHA384_192;

    /**
     * RFC 8009, Appendix A.4: String-to-key for etype 20.
     *
     * Passphrase:  "password"
     * Salt:        16-byte random UTF-8 sequence || "ATHENA.MIT.EDUraeburn"
     * Iterations:  32768
     * saltp:       "aes256-cts-hmac-sha384-192" || 0x00 || salt
     * 256-bit key: 45BD806DBF6A833A9CFFC1C94589A222367A79BC21C413718906E9F578A78467
     *
     * The KDC-provided salt in the RFC 8009 Appendix A test vector includes
     * 16 specific random (but valid UTF-8) bytes before "ATHENA.MIT.EDUraeburn".
     */
    @Test
    public void testStr2Key() throws Exception {
        assumeTrue(CryptoUtil.isAES256Enabled());

        String password = "password";
        // RFC 8009 Appendix A.4 salt = 16 random bytes + "ATHENA.MIT.EDUraeburn" (valid UTF-8)
        byte[] randomPrefix = {0x10, (byte) 0xDF, (byte) 0x9D, (byte) 0xD7, (byte) 0x83, (byte) 0xE5,
                               (byte) 0xBC, (byte) 0x8A, (byte) 0xCE, (byte) 0xA1, 0x73, 0x0E, 0x74, 0x35, 0x5F, 0x61};
        byte[] saltSuffix = "ATHENA.MIT.EDUraeburn".getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = new byte[randomPrefix.length + saltSuffix.length];
        System.arraycopy(randomPrefix, 0, saltBytes, 0, randomPrefix.length);
        System.arraycopy(saltSuffix, 0, saltBytes, randomPrefix.length, saltSuffix.length);
        String salt = new String(saltBytes, StandardCharsets.UTF_8);
        String expectedHex = "45BD806DBF6A833A9CFFC1C94589A222367A79BC21C413718906E9F578A78467";

        EncryptionKey key = EncryptionHandler.string2Key(password, salt, null, ETYPE);
        String actualHex = HexUtil.bytesToHex(key.getKeyData()).toUpperCase();

        if (!actualHex.equals(expectedHex)) {
            fail("str2key mismatch for etype 20:\n  expected: " + expectedHex
                    + "\n  actual:   " + actualHex);
        }
    }

    /**
     * RFC 8009, Appendix A.5: Key derivation for etype 20 (usage 2).
     *
     * For etype 20: ke = 256 bits, ki = kc = 192 bits (not 256).
     *
     * Base key: 6D404D37FAF79F9DF0D33568D3206698 00EB483647 2EA8A026D16B71824 60C52 (32 bytes)
     * Ke (0xAA, k=256): 56AB22BEE63D82D7BC5227F6773F8EA7A5EB1C825160C38312980C442E5C7E49
     * Ki (0x55, k=192): 69B16514E3CD8E56B82010D5C73012B622C4D00FFC23ED1F
     * Kc (0x99, k=192): EF5718BE86CC84963D8BBB5031E9F5C4BA41F28FAF69E73D
     */
    @Test
    public void testKeyDerivation() throws Exception {
        assumeTrue(CryptoUtil.isAES256Enabled());

        byte[] baseKey = HexUtil.hex2bytes(
                "6D404D37FAF79F9DF0D33568D3206698" + "00EB4836472EA8A026D16B7182460C52");

        AesSha2KeyMaker km = new AesSha2KeyMaker(new Aes256Provider(), new Sha384Provider());

        byte[] constantKe = HexUtil.hex2bytes("00000002AA");
        byte[] constantKi = HexUtil.hex2bytes("0000000255");
        byte[] constantKc = HexUtil.hex2bytes("0000000299");

        byte[] ke = km.dk(baseKey, constantKe);             // 32 bytes (256 bits)
        byte[] ki = km.dkWithBits(baseKey, constantKi, 192); // 24 bytes (192 bits)
        byte[] kc = km.dkWithBits(baseKey, constantKc, 192); // 24 bytes (192 bits)

        assertThat(ke).hasSize(32);
        assertThat(ki).hasSize(24);
        assertThat(kc).hasSize(24);

        String expectedKe = "56AB22BEE63D82D7BC5227F6773F8EA7A5EB1C825160C38312980C442E5C7E49";
        String expectedKi = "69B16514E3CD8E56B82010D5C73012B622C4D00FFC23ED1F";
        String expectedKc = "EF5718BE86CC84963D8BBB5031E9F5C4BA41F28FAF69E73D";

        assertDerivedKey("Ke", expectedKe, ke);
        assertDerivedKey("Ki", expectedKi, ki);
        assertDerivedKey("Kc", expectedKc, kc);
    }

    /**
     * Verify encrypt/decrypt round-trip for etype 20.
     */
    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        assumeTrue(CryptoUtil.isAES256Enabled());

        EncryptionKey key = EncryptionHandler.string2Key("password", "ATHENA.MIT.EDUraeburn",
                null, ETYPE);
        byte[] plaintext = "Hello, Kerby RFC 8009!".getBytes("UTF-8");
        KeyUsage usage = KeyUsage.AS_REQ_PA_ENC_TS;

        byte[] ciphertext = EncryptionHandler.encrypt(plaintext, key, usage).getCipher();
        byte[] decrypted = EncryptionHandler.decrypt(ciphertext, key, usage);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    /**
     * Verify PRF for etype 20.
     * RFC 8009 §6: PRF(key, seed) = HMAC-SHA384(key, "prf" || seed) truncated to 48 bytes.
     */
    @Test
    public void testPrf() throws Exception {
        assumeTrue(CryptoUtil.isAES256Enabled());

        EncryptionKey key = EncryptionHandler.string2Key("password", "ATHENA.MIT.EDUraeburn",
                null, ETYPE);
        EncTypeHandler handler = EncryptionHandler.getEncHandler(ETYPE);

        byte[] prfOutput = handler.prf(key.getKeyData(), "test".getBytes("UTF-8"));
        assertThat(prfOutput).hasSize(48); // SHA-384 output size
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
