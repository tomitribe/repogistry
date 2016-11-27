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
package org.tomitribe.tribestream.registryng.resources;

import org.apache.openejb.testing.Application;
import org.apache.tomee.embedded.junit.TomEEEmbeddedSingleRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.tribestream.registryng.entities.Endpoint;
import org.tomitribe.tribestream.registryng.test.Registry;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;

import static java.util.Arrays.asList;
import static javax.ws.rs.client.Entity.entity;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ClientResourceTest {
    @Application
    private Registry registry;

    @Rule
    public final TestRule rule = new TomEEEmbeddedSingleRunner.Rule(this);

    @PersistenceContext
    private EntityManager em;

    @Test
    public void executions() {
        final Endpoint endpoint = em.createQuery("select e from Endpoint e", Endpoint.class).setMaxResults(1).getSingleResult();
        try {
            final ClientResource.ExecutionId saved = registry.target()
                    .path("/api/try/execution/save/{eid}")
                    .resolveTemplate("eid", endpoint.getId())
                    .request(APPLICATION_JSON_TYPE)
                    .post(entity(new ClientResource.Execution() {{
                        setRequest(new ClientResource.HttpRequest() {{
                            setMethod("GET");
                            setUrl("http://test.com?foo=1");
                            setIgnoreSsl(true);
                            setHeaders(new HashMap<String, String>() {{
                                put("Identity", "me");
                            }});
                        }});
                        setResponse(new ClientResource.HttpResponse() {{
                            setPayload("{\"empty\":true}");
                            setError("oops");
                        }});
                    }}, APPLICATION_JSON_TYPE), ClientResource.ExecutionId.class);
            assertNotNull(saved.getId());

            final ClientResource.Execution execution = registry.target()
                    .path("api/try/execution/find/{id}")
                    .resolveTemplate("id", saved.getId())
                    .request(APPLICATION_JSON_TYPE)
                    .get(ClientResource.Execution.class);

            assertEquals("GET", execution.getRequest().getMethod());
            assertEquals("http://test.com?foo=1", execution.getRequest().getUrl());
            assertEquals(new HashMap<String, String>() {{
                put("Identity", "me");
            }}, execution.getRequest().getHeaders());

            assertEquals("oops", execution.getResponse().getError());
            assertEquals("{\"empty\":true}", execution.getResponse().getPayload());

            final ClientResource.Executions all = registry.target()
                    .path("api/try/execution/endpoint/find/{eId}")
                    .resolveTemplate("eId", endpoint.getId())
                    .request(APPLICATION_JSON_TYPE)
                    .get(ClientResource.Executions.class);
            assertEquals(1, all.getTotal());
            assertEquals(1, all.getItems().size());
        } finally {
            registry.restoreData();
        }
    }

    @Test
    public void oauth2() throws UnsupportedEncodingException {
        final ClientResource.ComputedHeader header = registry.target()
                .path("/api/try/header/oauth2")
                .request(APPLICATION_JSON_TYPE)
                .post(entity(new ClientResource.OAuth2Header() {{
                    setClientId("client");
                    setClientSecret("client secret");
                    setEndpoint(registry.root() + "/api/mock/oauth2/token");
                    setGrantType("password");
                    setUsername("testuser");
                    setPassword("testpassword");
                    setHeader("oauth2");
                }}, APPLICATION_JSON_TYPE), ClientResource.ComputedHeader.class);
        assertEquals("oauth2", header.getName());
        assertEquals("bearer awesome-token", header.getValue());
    }

    @Test
    public void signature() throws UnsupportedEncodingException {
        final ClientResource.ComputedHeader header = registry.target()
                .path("/api/try/header/signature")
                .request(APPLICATION_JSON_TYPE)
                .post(entity(new ClientResource.HttpSignatureHeader() {{
                    setMethod("GET");
                    setUrl(registry.root() + "/api/spy");
                    setRequestHeaders(new HashMap<String, String>() {{
                        put("Date", new Date(0).toString()); // ensure test can be re-executed
                    }});
                    setHeaders(asList("(request-target)", "date"));
                    setHeader("signature");
                    setAlgorithm(Algorithm.HMAC_SHA256.getJmvName());
                    setAlias("key");
                    setSecret("chut");
                }}, APPLICATION_JSON_TYPE), ClientResource.ComputedHeader.class);
        assertEquals("signature", header.getName());
        assertEquals(
                "Signature keyId=\"key\",algorithm=\"hmac-sha256\",headers=\"(request-target) date\"," +
                "signature=\"niZ0RzylAhy4DtKNcUZl0441+gUxON9t9GVS+KMfOJk=\"", header.getValue());
    }

    @Test
    public void basic() throws UnsupportedEncodingException {
        final ClientResource.ComputedHeader header = registry.target()
                .path("/api/try/header/basic")
                .request(APPLICATION_JSON_TYPE)
                .post(entity(new ClientResource.BasicHeader() {{
                    setUsername("u");
                    setPassword("p");
                    setHeader("basic");
                }}, APPLICATION_JSON_TYPE), ClientResource.ComputedHeader.class);
        assertEquals("basic", header.getName());
        assertEquals("Basic dTpw", header.getValue());
    }

    @Test
    public void request() throws UnsupportedEncodingException {
        final ClientResource.HttpRequest request = new ClientResource.HttpRequest();
        request.setMethod("GET");
        request.setUrl(registry.root() + "/api/spy");
        request.setHeaders(new HashMap<String, String>() {{
            put("Authorization", registry.basicHeader());
            put("Date", new Date(0).toString()); // ensure test can be re-executed
        }});
        request.setDigest(new ClientResource.DigestHeader() {{
            setAlgorithm("sha-256");
        }});

        final ClientResource.HttpResponse response = registry.target()
                .path("/api/try")
                .request(APPLICATION_JSON_TYPE)
                .post(entity(request, APPLICATION_JSON_TYPE), ClientResource.HttpResponse.class);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertTrue(response.getPayload(), response.getPayload().contains("GET/api/spy"));
        assertTrue(response.getPayload(), response.getPayload().contains("digest=sha-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    }
}
