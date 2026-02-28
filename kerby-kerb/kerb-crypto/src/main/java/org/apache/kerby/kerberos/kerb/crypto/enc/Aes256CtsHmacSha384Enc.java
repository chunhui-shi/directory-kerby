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

import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha384Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes256Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesSha2KeyMaker;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

/**
 * Encryption handler for RFC 8009 etype 20: aes256-cts-hmac-sha384-192.
 *
 * Note: for etype 20, ki is 192 bits (not 256), so integrityKeyBits() returns 192.
 */
public class Aes256CtsHmacSha384Enc extends KeKiHmacSha2Enc {

    static final String ETYPE_NAME = "aes256-cts-hmac-sha384-192";

    public Aes256CtsHmacSha384Enc() {
        super(new Aes256Provider(), new Sha384Provider(),
                new AesSha2KeyMaker(new Aes256Provider(), new Sha384Provider(), ETYPE_NAME),
                48 /* prfSize: SHA-384 output = 48 bytes */);
    }

    @Override
    public int checksumSize() {
        return 192 / 8; // 24 bytes
    }

    @Override
    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA384_192;
    }

    @Override
    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA384_192_AES256;
    }
}
