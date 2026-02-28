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
package org.apache.kerby.kerberos.kerb.crypto.cksum;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha384Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes256Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.util.BytesUtil;
import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;

/**
 * Checksum handler for RFC 8009 etype 20: HMAC-SHA384-192-AES256.
 *
 * RFC 8009 specifies that for etype 20, kc must be 192 bits (24 bytes),
 * even though the AES-256 key and ke/ki are 256 bits (32 bytes).
 * This class overrides doChecksumWithKey() to use dkWithBits(..., 192).
 */
public class HmacSha384Aes256CheckSum extends KcCheckSum {

    private final AesSha2KeyMaker aesSha2km;

    public HmacSha384Aes256CheckSum() {
        super(new Aes256Provider(), new Sha384Provider(),
                48 /* computeSize: full SHA-384 output */,
                24 /* outputSize: 192-bit truncated checksum */);
        this.aesSha2km = new AesSha2KeyMaker(new Aes256Provider(), new Sha384Provider());
        keyMaker(aesSha2km);
    }

    /**
     * Override to use 192-bit kc derivation instead of the default 256-bit.
     */
    @Override
    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                        byte[] key, int usage) throws KrbException {
        byte[] constant = new byte[5];
        BytesUtil.int2bytes(usage, constant, 0, true);
        constant[4] = (byte) 0x99;
        // RFC 8009: kc for etype 20 is 192 bits, not 256 bits
        byte[] kc = aesSha2km.dkWithBits(key, constant, 192);
        return mac(kc, data, start, len);
    }

    @Override
    protected byte[] mac(byte[] kc, byte[] data, int start, int len) throws KrbException {
        return Hmac.hmac(hashProvider(), kc, data, start, len);
    }

    @Override
    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA384_192_AES256;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public int cksumSize() {
        return 24;
    }

    @Override
    public int keySize() {
        return 32;
    }

    @Override
    public int confounderSize() {
        return 16;
    }
}
