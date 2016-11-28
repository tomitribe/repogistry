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
package org.tomitribe.tribestream.registryng.service.client;

import org.apache.openejb.testing.Application;
import org.apache.tomee.embedded.junit.TomEEEmbeddedSingleRunner;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.tribestream.registryng.entities.Endpoint;
import org.tomitribe.tribestream.registryng.entities.TryMeExecution;
import org.tomitribe.tribestream.registryng.test.Registry;

import javax.annotation.Resource;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.UserTransaction;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.stream.Stream;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class GenericClientServiceTest {
    @Application
    private Registry registry;

    @Rule
    public final TestRule rule = new TomEEEmbeddedSingleRunner.Rule(this);

    @Inject
    private GenericClientService client;

    @PersistenceContext
    private EntityManager em;

    @Resource
    private UserTransaction ut;

    @After
    public void cleanUp() {
        registry.restoreData();
    }

    @Test
    public void tryMeExecutionCrud() { // not split cause logic is quite trivial there
        final Endpoint endpoint = em.createQuery("select e from Endpoint e", Endpoint.class).setMaxResults(1).getSingleResult();
        {   // count with no execution
            assertEquals(0, client.countExecutions(endpoint.getId()));
        }
        {   // one execution
            final GenericClientService.Request request = new GenericClientService.Request();
            request.setUrl("http://test");
            request.setMethod("POST");
            request.setHeaders(new HashMap<String, String>() {{
                put("Some-Header", "Value");
            }});
            final TryMeExecution out = client.save(endpoint.getId(), request, new GenericClientService.Response(204, new HashMap<String, String>() {{
                put("Some-Header", "Value");
            }}, "{}", 0), null);
            assertEquals(1, client.countExecutions(endpoint.getId()));

            // check we can find pages
            final Collection<TryMeExecution> executions = client.findExecutions(endpoint.getId(), 0, 2);
            assertNotNull(executions);
            assertEquals(1, executions.size());

            // we can find item
            final TryMeExecution execution = client.find(out.getId());
            Stream.of(execution.getRequest(), execution.getResponse(), execution.getCreatedBy(), execution.getUpdatedBy(), execution.getUpdatedAt(), execution.getCreatedAt())
                    .forEach(Assert::assertNotNull);

            assertEquals(executions.iterator().next().getId(), execution.getId());

            // check we can deserialize
            final GenericClientService.Request loadedRequest = client.loadExecutionMember(GenericClientService.Request.class, execution.getRequest());
            assertEquals("POST", loadedRequest.getMethod());
            assertEquals(new HashMap<String, String>() {{
                put("Some-Header", "Value");
            }}, loadedRequest.getHeaders());
            assertEquals("http://test", loadedRequest.getUrl());
            assertNull(loadedRequest.getPayload());
        }
    }

    @Test
    public void digest() {
        assertEquals("sha-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", client.digestHeader("test", "sha-256"));
    }

    @Test
    public void basic() {
        assertEquals("Basic YTpiNDU2OEBfODclKg==", client.basicHeader("a", "b4568@_87%*"));
    }

    @Test
    public void signature() {
        assertEquals(
                "Signature keyId=\"key\",algorithm=\"hmac-sha256\",headers=\"(request-target) date\",signature=\"OdYumDua8K9Nb/3PZvWdNxbZDTNl33JfObSE4tE/npg=\"",
                client.httpSign(asList("(request-target)", "date"), "POST", "/foo/bar?q=u", "key", "chut", Algorithm.HMAC_SHA256.getJmvName(), new HashMap<String, String>() {{
                    put("date", new Date(0).toString()); // ensure test can be re-executed
                }}));
    }

    @Test
    public void oauth2() {
        assertEquals(
                "bearer awesome-token",
                client.oauth2Header("password", "testuser", "testpassword", null, "client", "client secret", registry.root() + "/api/mock/oauth2/token", false));
    }

    @Test(expected = NullPointerException.class)
    public void badRequest() {
        client.invoke(new GenericClientService.Request());
    }

    @Test
    public void notAuthenticated() {
        final GenericClientService.Request request = new GenericClientService.Request();
        request.setUrl(registry.root() + "/api/spy");
        request.setMethod("GET");

        final GenericClientService.Response response = client.invoke(request);
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    @Test
    public void get() throws UnsupportedEncodingException {
        final GenericClientService.Request request = new GenericClientService.Request();
        request.setHeaders(new HashMap<String, String>() {{
            put("test-header", "test");
            put("Authorization", registry.basicHeader());
        }});
        request.setUrl(registry.root() + "/api/spy");
        request.setMethod("GET");

        final GenericClientService.Response response = client.invoke(request);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertTrue(response.getPayload(), response.getPayload().contains("GET/api/spy"));
        assertTrue(response.getPayload(), response.getPayload().contains("test-header=test"));
        assertTrue(response.getPayload(), response.getPayload().contains("authorization=Basic dXRlc3Q6cHRlc3Q="));
        assertEquals("application/octet-stream", response.getHeaders().get("content-type"));
    }

    @Test
    public void post() throws UnsupportedEncodingException {
        final GenericClientService.Request request = new GenericClientService.Request();
        request.setHeaders(new HashMap<String, String>() {{
            put("test-header", "test");
            put("Authorization", registry.basicHeader());
        }});
        request.setUrl(registry.root() + "/api/spy");
        request.setMethod("POST");
        request.setPayload("{\"test\":\"val\"}");

        final GenericClientService.Response response = client.invoke(request);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertTrue(response.getPayload(), response.getPayload().contains("POST/api/spy"));
        assertTrue(response.getPayload(), response.getPayload().contains("test-header=test"));
        assertTrue(response.getPayload(), response.getPayload().contains("authorization=Basic dXRlc3Q6cHRlc3Q="));
        assertTrue(response.getPayload(), response.getPayload().endsWith("{\"test\":\"val\"}"));
        assertEquals("application/octet-stream", response.getHeaders().get("content-type"));
    }
}
