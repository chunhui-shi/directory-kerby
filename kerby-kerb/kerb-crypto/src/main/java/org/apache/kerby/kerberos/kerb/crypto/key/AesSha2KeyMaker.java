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
package org.apache.kerby.kerberos.kerb.crypto.key;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha384Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.AesProvider;
import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;
import org.apache.kerby.kerberos.kerb.crypto.util.Pbkdf;

import java.security.GeneralSecurityException;

/**
 * Key maker for RFC 8009 etypes 19 (aes128-cts-hmac-sha256-128) and
 * 20 (aes256-cts-hmac-sha384-192).
 *
 * Key derivation function (KDF-HMAC-SHA2, NIST SP800-108 counter mode):
 *   KDF(key, constant) = k-truncate(HMAC-Hash(key, 0x00000001 || constant || 0x00 || k_bits))
 * where k_bits is the desired output size in bits encoded as a 4-byte big-endian integer.
 *
 * RFC 8009 Section 4 specifies that the PBKDF2 salt is constructed as:
 *   saltp = enctype-name || 0x00 || salt
 * where enctype-name is the RFC name of the encryption type (e.g. "aes128-cts-hmac-sha256-128").
 */
public class AesSha2KeyMaker extends DkKeyMaker {

    private final HashProvider hashProvider;
    private final String saltPrefix;

    /**
     * @param encProvider  AES provider (Aes128Provider or Aes256Provider)
     * @param hashProvider hash provider (Sha256Provider or Sha384Provider)
     * @param saltPrefix   RFC 8009 enctype name prepended to the PBKDF2 salt
     *                     (e.g. "aes128-cts-hmac-sha256-128").
     *                     Pass null when str2key is not used (checksum-only contexts).
     */
    public AesSha2KeyMaker(AesProvider encProvider, HashProvider hashProvider, String saltPrefix) {
        super(encProvider);
        this.hashProvider = hashProvider;
        this.saltPrefix = saltPrefix;
    }

    /**
     * Convenience constructor for checksum contexts where str2key is not called.
     */
    public AesSha2KeyMaker(AesProvider encProvider, HashProvider hashProvider) {
        this(encProvider, hashProvider, null);
    }

    /**
     * RFC 8009 KDF: derive a key of the same size as the encryption key.
     */
    @Override
    public byte[] dk(byte[] key, byte[] constant) throws KrbException {
        int keyBits = encProvider().keySize() * 8;
        return dkWithBits(key, constant, keyBits);
    }

    /**
     * RFC 8009 KDF: derive a key of outputBits size.
     * Used for etype-20 ki/kc derivation where ki=kc = 192 bits, not 256 bits.
     */
    public byte[] dkWithBits(byte[] key, byte[] constant, int outputBits) throws KrbException {
        int outputBytes = outputBits / 8;

        // Build HMAC input: 0x00000001 || constant || 0x00 || outputBits_BE
        byte[] kdfInput = new byte[4 + constant.length + 1 + 4];
        kdfInput[0] = 0x00;
        kdfInput[1] = 0x00;
        kdfInput[2] = 0x00;
        kdfInput[3] = 0x01;
        System.arraycopy(constant, 0, kdfInput, 4, constant.length);
        kdfInput[4 + constant.length] = 0x00;
        kdfInput[5 + constant.length] = (byte) ((outputBits >> 24) & 0xFF);
        kdfInput[6 + constant.length] = (byte) ((outputBits >> 16) & 0xFF);
        kdfInput[7 + constant.length] = (byte) ((outputBits >> 8) & 0xFF);
        kdfInput[8 + constant.length] = (byte) (outputBits & 0xFF);

        // T1 = HMAC-Hash(key, kdfInput); one block is sufficient for our key sizes
        byte[] t1 = Hmac.hmac(hashProvider, key, kdfInput);

        // k-truncate to outputBytes
        byte[] result = new byte[outputBytes];
        System.arraycopy(t1, 0, result, 0, outputBytes);
        return result;
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        // RFC 8009 uses 32768 default iterations (vs 4096 for RFC 3962)
        int iterCount = getIterCount(param, 32768);

        // RFC 8009 Section 4: saltp = enctype-name || 0x00 || salt
        byte[] saltBytes = getSaltBytes(salt, saltPrefix);
        int keySize = encProvider().keySize();

        byte[] random;
        try {
            if (hashProvider instanceof Sha384Provider) {
                random = Pbkdf.pbkdf2Sha384(string.toCharArray(), saltBytes, iterCount, keySize);
            } else {
                random = Pbkdf.pbkdf2Sha256(string.toCharArray(), saltBytes, iterCount, keySize);
            }
        } catch (GeneralSecurityException e) {
            throw new KrbException("pbkdf2 failed", e);
        }

        byte[] tmpKey = random2Key(random);
        return dk(tmpKey, KERBEROS_CONSTANT);
    }

    public HashProvider hashProvider() {
        return hashProvider;
    }
}
