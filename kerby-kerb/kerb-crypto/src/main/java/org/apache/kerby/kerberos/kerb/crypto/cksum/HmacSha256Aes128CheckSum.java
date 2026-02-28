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
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha256Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes128Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;

/**
 * Checksum handler for RFC 8009 etype 19: HMAC-SHA256-128-AES128.
 *
 * The kc derivation uses k=128 bits (same as the AES-128 key size),
 * so the standard KcCheckSum.doChecksumWithKey() works correctly here.
 */
public class HmacSha256Aes128CheckSum extends KcCheckSum {

    public HmacSha256Aes128CheckSum() {
        super(new Aes128Provider(), new Sha256Provider(),
                32 /* computeSize: full SHA-256 output */,
                16 /* outputSize: 128-bit truncated checksum */);
        keyMaker(new AesSha2KeyMaker(new Aes128Provider(), new Sha256Provider()));
    }

    @Override
    protected byte[] mac(byte[] kc, byte[] data, int start, int len) throws KrbException {
        return Hmac.hmac(hashProvider(), kc, data, start, len);
    }

    @Override
    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA256_128_AES128;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public int cksumSize() {
        return 16;
    }

    @Override
    public int keySize() {
        return 16;
    }

    @Override
    public int confounderSize() {
        return 16;
    }
}
