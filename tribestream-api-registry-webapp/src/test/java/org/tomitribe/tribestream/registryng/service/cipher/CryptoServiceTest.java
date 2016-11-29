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

import org.apache.openejb.testing.Application;
import org.apache.tomee.embedded.junit.TomEEEmbeddedSingleRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.tomitribe.tribestream.registryng.test.Registry;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class CryptoServiceTest {
    @Application
    private Registry registry;

    @Rule
    public final TestRule rule = new TomEEEmbeddedSingleRunner.Rule(this);

    @Inject
    private CryptoService service;

    @Test
    public void crypt() {
        final String from = "from";
        final String crypted = service.toUrlString(from);
        assertNotEquals(from, crypted);
        assertEquals(from, new String(service.fromUrlString(crypted), StandardCharsets.UTF_8));
    }
}
