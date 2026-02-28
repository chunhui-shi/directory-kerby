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
package org.apache.kerby.kerberos.kerb.crypto.enc;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.util.BytesUtil;
import org.apache.kerby.kerberos.kerb.crypto.util.Confounder;
import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;

import java.nio.charset.StandardCharsets;

/**
 * Abstract encryption handler for RFC 8009 etypes (19 and 20).
 *
 * Differences from KeKiHmacSha1Enc:
 * - PRF uses HMAC-Hash(key, "prf" || seed) truncated to prfSize bytes (RFC 8009 §6)
 * - Checksum uses HMAC-SHA256 or HMAC-SHA384 (not SHA-1)
 * - Key derivation uses RFC 8009 HMAC-based KDF (not AES-CBC DR)
 * - For etype 20: ki is 192 bits (maclen), not 256 bits (keylen)
 */
public abstract class KeKiHmacSha2Enc extends KeKiEnc {

    private final AesSha2KeyMaker sha2km;
    private final int prfOutSize;

    public KeKiHmacSha2Enc(EncryptProvider encProvider, HashProvider hashProvider,
                            AesSha2KeyMaker km, int prfSize) {
        super(encProvider, hashProvider);
        this.sha2km = km;
        this.prfOutSize = prfSize;
        keyMaker(km);
    }

    @Override
    public int prfSize() {
        return prfOutSize;
    }

    /**
     * Integrity key size in bits for the ki derivation.
     * For etype 19: 128 bits (same as ke). For etype 20: 192 bits (maclen, not keylen).
     */
    protected int integrityKeyBits() {
        return checksumSize() * 8;
    }

    /**
     * RFC 8009 §6: PRF(base-key, octet-string) =
     *   HMAC-Hash(base-key, "prf" || octet-string), truncated to prfSize bytes.
     */
    @Override
    public byte[] prf(byte[] key, byte[] seed) throws KrbException {
        byte[] prfLabel = "prf".getBytes(StandardCharsets.UTF_8);
        byte[] input = new byte[prfLabel.length + seed.length];
        System.arraycopy(prfLabel, 0, input, 0, prfLabel.length);
        System.arraycopy(seed, 0, input, prfLabel.length, seed.length);

        byte[] hash = Hmac.hmac(hashProvider(), key, input);
        byte[] output = new byte[prfOutSize];
        System.arraycopy(hash, 0, output, 0, prfOutSize);
        return output;
    }

    @Override
    protected byte[] makeChecksum(byte[] key, byte[] data, int hashSize) throws KrbException {
        byte[] hash = Hmac.hmac(hashProvider(), key, data);
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }

    /**
     * Override encryptWith to derive ki with integrityKeyBits() (192 for etype 20).
     * Etype 20: ke=256 bits, ki=192 bits; etype 19: both 128 bits.
     */
    @Override
    protected void encryptWith(byte[] workBuffer, int[] workLens,
                               byte[] key, byte[] iv, int usage, boolean raw) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int inputLen = workLens[2];
        int paddingLen = workLens[3];

        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage >> 24) & 0xff);
        constant[1] = (byte) ((usage >> 16) & 0xff);
        constant[2] = (byte) ((usage >> 8) & 0xff);
        constant[3] = (byte) (usage & 0xff);
        constant[4] = (byte) 0xaa;

        byte[] ke = sha2km.dk(key, constant);
        constant[4] = (byte) 0x55;
        byte[] ki = sha2km.dkWithBits(key, constant, integrityKeyBits());

        if (!raw) {
            byte[] tmpEnc = new byte[confounderLen + inputLen + paddingLen];
            byte[] confounder = Confounder.makeBytes(confounderLen);
            System.arraycopy(confounder, 0, tmpEnc, 0, confounderLen);
            System.arraycopy(workBuffer, confounderLen + checksumLen,
                    tmpEnc, confounderLen, inputLen);
            for (int i = confounderLen + inputLen; i < paddingLen; ++i) {
                tmpEnc[i] = 0;
            }

            byte[] checksum = makeChecksum(ki, tmpEnc, checksumLen);
            encProvider().encrypt(ke, iv, tmpEnc);

            System.arraycopy(tmpEnc, 0, workBuffer, 0, tmpEnc.length);
            System.arraycopy(checksum, 0, workBuffer, tmpEnc.length, checksum.length);
        } else {
            encProvider().encrypt(ke, iv, workBuffer);
        }
    }

    /**
     * Override decryptWith to derive ki with integrityKeyBits() (192 for etype 20).
     */
    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage, boolean raw) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        byte[] constant = new byte[5];
        BytesUtil.int2bytes(usage, constant, 0, true);
        constant[4] = (byte) 0xaa;
        byte[] ke = sha2km.dk(key, constant);
        constant[4] = (byte) 0x55;
        byte[] ki = sha2km.dkWithBits(key, constant, integrityKeyBits());

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, 0, tmpEnc, 0, confounderLen + dataLen);

        if (!raw) {
            byte[] checksum = new byte[checksumLen];
            System.arraycopy(workBuffer, confounderLen + dataLen, checksum, 0, checksumLen);

            encProvider().decrypt(ke, iv, tmpEnc);
            byte[] newChecksum = makeChecksum(ki, tmpEnc, checksumLen);

            if (!checksumEqual(checksum, newChecksum)) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
            }

            byte[] data = new byte[dataLen];
            System.arraycopy(tmpEnc, confounderLen, data, 0, dataLen);
            return data;
        } else {
            encProvider().decrypt(ke, iv, tmpEnc);
            return tmpEnc;
        }
    }

    public AesSha2KeyMaker sha2KeyMaker() {
        return sha2km;
    }
}
