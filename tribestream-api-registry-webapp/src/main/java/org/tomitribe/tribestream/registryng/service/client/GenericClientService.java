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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.deltaspike.core.api.config.ConfigProperty;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.tribestream.registryng.documentation.Description;
import org.tomitribe.tribestream.registryng.entities.Endpoint;
import org.tomitribe.tribestream.registryng.entities.TryMeExecution;
import org.tomitribe.tribestream.registryng.security.LoginContext;
import org.tomitribe.util.Duration;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static java.util.Collections.emptyMap;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toMap;

// here we dont reuse client instances to avoid to handle thread safety since it is not a high throughput service
@ApplicationScoped
public class GenericClientService {
    @Inject
    @Description("Timeout for the request done with the `try me` feature.")
    @ConfigProperty(name = "tribe.registry.ui.try-me.timeout", defaultValue = "30 seconds")
    private String timeoutLiteral;

    @Inject
    @Getter
    @Description("Default endpoint used for oauth2 request when not specified in the UI.")
    @ConfigProperty(name = "tribe.registry.ui.try-me.oauth2.default-endpoint")
    private String oauth2Endpoint;

    @Inject
    @Description("Default OAuth2 client used.")
    @ConfigProperty(name = "tribe.registry.ui.try-me.oauth2.client.name")
    private String oauth2Client;

    @Inject
    @Description("Default OAuth2 client secret used (only with `tribe.registry.ui.try-me.oauth2.client.name`).")
    @ConfigProperty(name = "tribe.registry.ui.try-me.oauth2.client.secret")
    private String oauth2ClientSecret;

    @PersistenceContext
    private EntityManager em;

    @Inject
    private LoginContext user;

    private final ObjectMapper executionMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

    private String timeout;

    @PostConstruct
    private void init() {
        timeout = String.valueOf(new Duration(timeoutLiteral, TimeUnit.MILLISECONDS).getTime(TimeUnit.MILLISECONDS));
    }

    public String oauth2Header(final String grantType,
                               final String username,
                               final String password,
                               final String refreshToken,
                               final String clientId,
                               final String clientSecret,
                               final String endpoint,
                               final String tokenType,
                               final boolean ignoreSsl) {
        final Client client = newClient(ignoreSsl && endpoint != null && endpoint.startsWith("https"));
        try {
            final Form form = new Form();
            switch (ofNullable(grantType).map(g -> g.toLowerCase(Locale.ENGLISH)).orElse("password")) {
                case "password":
                    form.param("username", username).param("password", password).param("grant_type", "password");
                    break;
                case "refresh_token":
                    form.param("refresh_token", refreshToken).param("grant_type", "refreshToken");
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported oauth2 grant_type: " + grantType);
            }

            final String clientName = ofNullable(clientId).orElse(oauth2Client);
            ofNullable(clientName)
                    .ifPresent(c -> form.param("client_id", c));
            ofNullable(oauth2Client != null && oauth2Client.equals(clientName) && clientSecret == null ? oauth2ClientSecret : clientSecret)
                    .ifPresent(c -> form.param("client_secret", c));

            final Token token = client
                    .target(ofNullable(endpoint).orElse(oauth2Endpoint))
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE), Token.class);
            return ofNullable(tokenType).orElse(ofNullable(token.getToken_type()).map(h -> "empty".equals(h) ? "" : h).orElse("")) + " " + token.getAccess_token();
        } finally {
            client.close();
        }
    }

    public String httpSign(final List<String> headers,
                           final String method,
                           final String path,
                           final String alias,
                           final String secret,
                           final String algorithm,
                           final Map<String, String> requestHeaders) {
        final String uri;
        if (path.startsWith("https://") || path.startsWith("http://")) {
            final URL url;
            try {
                url = new URL(path);
            } catch (final MalformedURLException e) {
                throw new IllegalArgumentException(e);
            }
            uri = url.getPath() + ofNullable(url.getQuery()).filter(q -> q != null && !q.isEmpty()).map(q -> '?' + q).orElse("");
        } else {
            uri = path;
        }

        try {
            final Signer signer = new Signer(
                    new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm),
                    new Signature(alias, algorithm, null, headers));

            headers.forEach(h -> { // some particular and common headers to ensure we can handle autoamtically
                switch (h.toLowerCase(Locale.ENGLISH)) {
                    case "date": {
                        if (!requestHeaders.keySet().stream().filter(s -> s.equalsIgnoreCase("date")).findAny().isPresent()) {
                            requestHeaders.put("date", new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US) {{
                                setTimeZone(TimeZone.getTimeZone("GMT"));
                            }}.format(new Date()));
                        }
                        break;
                    }
                    case "(request-target)": // virtual header handled in Signer
                        break;
                    default:
                        if (!requestHeaders.containsKey(h)) {
                            throw new IllegalArgumentException(h + " header not yet supported");
                        }
                }
            });

            return signer.sign(method, uri, requestHeaders).toString();
        } catch (final IOException ioe) {
            throw new IllegalStateException(ioe);
        }
    }

    public String basicHeader(final String username, final String password) {
        return "Basic " + Base64.getEncoder().encodeToString(
                Stream.of(username, password).collect(joining(":")).getBytes(StandardCharsets.UTF_8));
    }

    public String digestHeader(final String payload, final String algorithm) {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        digest.update(payload.getBytes(StandardCharsets.UTF_8));
        return algorithm + '=' + Base64.getEncoder().encodeToString(digest.digest());
    }

    @Transactional
    public int countExecutions(final String id) {
        return em.createNamedQuery("TryMeExecution.count", Number.class)
                .setParameter("endpointId", id)
                .getSingleResult().intValue();
    }

    @Transactional
    public TryMeExecution save(final String endpointId, final Request request, final Response response,
                               final String error) {
        final Date now = new Date();
        final TryMeExecution execution = new TryMeExecution();
        execution.setCreatedAt(now);
        execution.setUpdatedAt(now);
        execution.setCreatedBy(user.getUsername());
        execution.setUpdatedBy(execution.getCreatedBy());
        execution.setEndpoint(requireNonNull(em.find(Endpoint.class, endpointId)));
        execution.setResponseError(error);
        try {
            execution.setRequest(executionMapper.writeValueAsString(request));
            execution.setResponse(executionMapper.writeValueAsString(response));
        } catch (final JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
        em.persist(execution);
        return execution;
    }

    public <T> T loadExecutionMember(final Class<T> type, final String value) {
        try {
            return executionMapper.readValue(value, type);
        } catch (final IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public TryMeExecution find(final String execution) {
        return em.find(TryMeExecution.class, execution);
    }

    public Collection<TryMeExecution> findExecutions(final String endpointId, final int from, final int max) {
        return em.createNamedQuery("TryMeExecution.findByEndpoint", TryMeExecution.class)
                .setParameter("endpointId", endpointId)
                .setFirstResult(from)
                .setMaxResults(max)
                .getResultList();
    }

    public Response invoke(final Request request) {
        final Client client = newClient(request.isIgnoreSsl() && request.getUrl() != null && request.getUrl().startsWith("https"));

        final javax.ws.rs.core.Response response;
        try {
            final Map<String, String> headers = new HashMap<>(ofNullable(request.getHeaders()).orElse(emptyMap()));
            final Invocation.Builder builder = client.target(request.getUrl()).request(headers.getOrDefault("Accept", MediaType.WILDCARD));
            headers.forEach(builder::header);

            final String payload = request.getPayload();
            final long start = System.nanoTime();
            if (payload == null || payload.isEmpty()) {
                response = builder.method(request.method);
            } else {
                response = builder.method(request.method, Entity.entity(
                        payload,
                        headers.computeIfAbsent("Content-Type", k -> payload.startsWith("{") ?
                                MediaType.APPLICATION_JSON : (payload.startsWith("<") ? MediaType.APPLICATION_XML : MediaType.WILDCARD))));
            }
            final long end = System.nanoTime();
            return new Response(
                    response.getStatus(),
                    response.getStringHeaders().entrySet().stream()
                            .collect(toMap(
                                    Map.Entry::getKey,
                                    t -> t.getValue().stream().collect(joining(",")),
                                    (s, s2) -> Stream.of(s, s2).filter(v -> v != null).collect(joining(",")))),
                    response.getStatus() != javax.ws.rs.core.Response.Status.NO_CONTENT.getStatusCode() ? response.readEntity(String.class) : "",
                    TimeUnit.NANOSECONDS.toMillis(end - start));
        } finally {
            client.close();
        }
    }

    private Client newClient(final boolean ignoreSsl) {
        final ClientBuilder builder = ClientBuilder.newBuilder();
        if (ignoreSsl) {
            builder.sslContext(getSSLContext()).hostnameVerifier((s, session) -> true);
        }
        return builder.build()
                .property("http.connection.timeout", timeout)
                .property("http.receive.timeout", timeout)
                .property("jersey.config.client.connectTimeout", timeout)
                .property("jersey.config.client.readTimeout", timeout);
    }

    private SSLContext getSSLContext() {
        try {
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                    // no-op
                }

                @Override
                public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                    // no-op
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

            }}, new SecureRandom());
            return sslContext;
        } catch (final NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }

    @Data
    public static class Request {
        private boolean ignoreSsl;
        private String method;
        private String url;
        private Map<String, String> headers;
        private String payload;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Response {
        private int status;
        private Map<String, String> headers;
        private String payload;
        private long clientExecutionDurationMs;
    }

    @Data
    public static class Token {
        private String access_token;
        private String token_type;
    }
}
