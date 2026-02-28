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

import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha256Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes128Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

/**
 * Encryption handler for RFC 8009 etype 19: aes128-cts-hmac-sha256-128.
 */
public class Aes128CtsHmacSha256Enc extends KeKiHmacSha2Enc {

    static final String ETYPE_NAME = "aes128-cts-hmac-sha256-128";

    public Aes128CtsHmacSha256Enc() {
        super(new Aes128Provider(), new Sha256Provider(),
                new AesSha2KeyMaker(new Aes128Provider(), new Sha256Provider(), ETYPE_NAME),
                32 /* prfSize: SHA-256 output = 32 bytes */);
    }

    @Override
    public int checksumSize() {
        return 128 / 8; // 16 bytes
    }

    @Override
    public EncryptionType eType() {
        return EncryptionType.AES128_CTS_HMAC_SHA256_128;
    }

    @Override
    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA256_128_AES128;
    }
}
