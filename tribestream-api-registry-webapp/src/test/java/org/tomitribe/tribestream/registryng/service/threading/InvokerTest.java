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
package org.tomitribe.tribestream.registryng.service.threading;

import org.apache.openejb.testing.Application;
import org.apache.tomee.embedded.junit.TomEEEmbeddedSingleRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.tomitribe.tribestream.registryng.test.Registry;

import javax.inject.Inject;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

public class InvokerTest {
    @Application
    private Registry registry;

    @Rule
    public final TestRule rule = new TomEEEmbeddedSingleRunner.Rule(this);

    @Inject
    private Invoker invoker;

    @Test
    public void iterations() {
        final AtomicInteger total = new AtomicInteger();
        invoker.invoke(5, 15, null, -1, total::incrementAndGet);
        assertEquals(15, total.get());
    }

    @Test
    public void duration() {
        invoker.invoke(5, 0, "1 seconds", -1, () -> {}); // ensure JVM is "hot" enough for this kind of test to pass

        final long start = System.currentTimeMillis();
        invoker.invoke(5, 0, "10 seconds", -1, () -> {});
        final long end = System.currentTimeMillis();
        assertEquals(10, TimeUnit.MILLISECONDS.toSeconds(end - start), 4 /*yes 40% but 4s only, should be good enough*/);
    }
}
