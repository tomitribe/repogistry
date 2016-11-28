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
