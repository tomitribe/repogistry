/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.tomitribe.tribestream.registryng.service.cipher;

import lombok.extern.java.Log;
import org.apache.deltaspike.core.api.config.ConfigProperty;
import org.tomitribe.tribestream.registryng.documentation.Description;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Log
@ApplicationScoped
public class CryptoService {
    private static final String DEFAULT_SECRET = "K795kXxjoW926ys07l48KYUC";

    @Inject
    @Description("The seed to cipher sensitive data passed in URLs.")
    @ConfigProperty(name = "tribe.registry.crypto.secret.value", defaultValue = DEFAULT_SECRET)
    private String secret;

    @Inject
    @Description("The secret algorithm to use.")
    @ConfigProperty(name = "tribe.registry.crypto.secret.algorithm", defaultValue = "DESede")
    private String algorithm;

    @Inject
    @Description("The cipher algorithm to use to pass sensitive data in URLs.")
    @ConfigProperty(name = "tribe.registry.crypto.cipher", defaultValue = "DESede")
    private String cipher;

    @PostConstruct
    private void init() {
        if (DEFAULT_SECRET.equals(secret)) {
            log.warning("You are running with the default secret, probably think to customize it setting tribe.registry.crypto.secret.value.");
        }
    }

    public String toUrlString(final String value) {
        try {
            final Cipher c = Cipher.getInstance(cipher);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
            return Base64.getUrlEncoder().encodeToString(c.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] fromUrlString(final String value) {
        try {
            final Cipher c = Cipher.getInstance(cipher);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
            return c.doFinal(Base64.getUrlDecoder().decode(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }
}
