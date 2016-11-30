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

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.deltaspike.core.api.config.ConfigProperty;
import org.tomitribe.tribestream.registryng.documentation.Description;
import org.tomitribe.tribestream.registryng.entities.TryMeExecution;
import org.tomitribe.tribestream.registryng.security.SecurityService;
import org.tomitribe.tribestream.registryng.service.cipher.CryptoService;
import org.tomitribe.tribestream.registryng.service.client.GenericClientService;
import org.tomitribe.tribestream.registryng.service.threading.Invoker;
import org.tomitribe.util.Duration;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.annotation.Annotation;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

@Path("try")
@ApplicationScoped
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class ClientResource {
    @Inject
    private GenericClientService service;

    @Inject
    private Invoker invoker;

    @Resource(name = "registry/thread/invoker-pool")
    private ManagedExecutorService mes; // for request processing, NOT invocations, see Invoker

    @Inject
    @Description("How many errors are tolerated before closing the scenario based execution.")
    @ConfigProperty(name = "tribe.registry.tryme.write-errors", defaultValue = "2")
    private Integer toleratedWriteErrors;

    @Inject
    @Description("Default timeout for parallel invocation without a time constraint.")
    @ConfigProperty(name = "tribe.registry.tryme.timeout", defaultValue = "20 seconds")
    private String timeoutConfig;
    private long timeout;

    @Inject
    private SecurityService security;

    @Inject
    private CryptoService cryptoService;

    private final Annotation[] annotations = new Annotation[0];
    private final byte[] dataStart = "data:".getBytes(StandardCharsets.UTF_8);
    private final byte[] dataEnd = "\n\n".getBytes(StandardCharsets.UTF_8);
    private final GenericType<Collection<LightHttpResponse>> collectionLightResponsesType = new GenericType<Collection<LightHttpResponse>>() {
    };

    @PostConstruct
    private void init() {
        timeout = new Duration(timeoutConfig, TimeUnit.MILLISECONDS).getTime(TimeUnit.MILLISECONDS);
    }

    @GET
    @Path("execution/find/{id}")
    public Execution save(@PathParam("id") final String execution) {
        return ofNullable(service.find(execution))
                .map(this::toExecution)
                .orElseThrow(() -> new WebApplicationException(Response.Status.NOT_FOUND));
    }

    @GET
    @Path("execution/endpoint/find/{endpoint-id}")
    public Executions findAll(@PathParam("endpoint-id") final String endpointId,
                              @QueryParam("page-size") @DefaultValue("10") final int size,
                              @QueryParam("page") @DefaultValue("0") final int page) {
        return new Executions(
                service.countExecutions(endpointId),
                service.findExecutions(endpointId, page * size, size).stream()
                        .map(this::toExecution)
                        .collect(toList()));
    }

    @POST
    @Path("execution/save/{endpoint-id}")
    public ExecutionId save(final Execution execution, @PathParam("endpoint-id") final String endpointId) {
        final HttpResponse response = execution.getResponse();
        return new ExecutionId(service.save(
                endpointId,
                toRequest(execution.getRequest()),
                new GenericClientService.Response(response.getStatus(), response.getHeaders(), response.getPayload(), response.getClientExecutionDurationMs()),
                execution.getResponse().getError())
                .getId());
    }

    @POST
    @Path("invoke")
    public HttpResponse invoke(final HttpRequest request) {
        try {
            final GenericClientService.Request req = toRequest(request);

            final Scenario scenario = request.getScenario();
            if (scenario != null && (scenario.getThreads() > 1 || scenario.getDuration() != null || scenario.getInvocations() > 1)) {
                throw new WebApplicationException(Response.Status.BAD_REQUEST); // use /invoke/parallel
            } else {
                final GenericClientService.Response response = service.invoke(req);
                return new HttpResponse(response.getStatus(), response.getHeaders(), response.getPayload(), null, response.getClientExecutionDurationMs());
            }
        } catch (final RuntimeException re) {
            return new HttpResponse(-1, emptyMap(), null, re.getMessage() /*TODO: analyze it?*/, -1);
        }
    }

    @POST
    @Path("crypt")
    public CryptoData crypto(final CryptoData data) {
        return new CryptoData(cryptoService.toUrlString(data.getData()));
    }

    @GET
    @Path("defaults")
    public Map<String, String> defaults() {
        return ofNullable(service.getOauth2Endpoint()).map(e -> singletonMap("oauth2Endpoint", e)).orElse(emptyMap());
    }

    @GET // more portable way to do a download from a browser
    @Path("download")
    @Consumes(APPLICATION_JSON)
    @Produces(TEXT_PLAIN)
    public Response download(@QueryParam("output-type") @DefaultValue("csv") final String extension,
                             @QueryParam("filename") @DefaultValue("responses") final String filename,
                             @QueryParam("data") final String base64EncodedResponses,
                             @Context final HttpServletRequest httpServletRequest,
                             @Context final Providers providers) {
        final DownloadResponses downloadResponses = loadPayload(DownloadResponses.class, providers, base64EncodedResponses);
        final String auth = downloadResponses.getIdentity();
        security.check(auth, httpServletRequest, () -> {
        }, () -> {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        });

        final String contentType;
        final StreamingOutput builder;
        switch (extension) {
            case "csv":
                contentType = TEXT_PLAIN;
                builder = output -> {
                    final CSVFormat format = CSVFormat.EXCEL.withHeader("Status", "Duration (ms)", "Error");
                    final StringWriter buffer = new StringWriter();
                    try (final CSVPrinter print = format.print(buffer)) {
                        downloadResponses.getData().forEach(r -> {
                            try {
                                print.printRecord(r.getStatus(), r.getClientExecutionDurationMs(), r.getError());
                            } catch (final IOException e) { // quite unlikely
                                throw new IllegalStateException(e);
                            }
                        });
                    }
                    output.write(buffer.toString().getBytes(StandardCharsets.UTF_8));
                };
                break;
            default:
                throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.OK)
                .header("ContentType", contentType)
                .header("Content-Disposition", "attachment; filename=\"" + filename + '.' + extension + "\"")
                .entity(builder)
                .build();
    }

    @GET
    @Path("invoke/stream")
    @Produces("text/event-stream") // will be part of JAX-RS 2.1, for now just making it working
    public void invokeScenario(
            @Suspended final AsyncResponse asyncResponse,
            @Context final Providers providers,
            @Context final HttpServletRequest httpServletRequest,
            // base64 encoded json with the request and identify since EventSource doesnt handle it very well
            // TODO: use a ciphering with a POST endpoint to avoid to have it readable (or other)
            @QueryParam("request") final String requestBytes) {
        final SseRequest in = loadPayload(SseRequest.class, providers, requestBytes);

        final String auth = in.getIdentity();
        security.check(auth, httpServletRequest, () -> {
        }, () -> {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        });

        final GenericClientService.Request req = toRequest(in.getHttp());
        final Scenario scenario = in.getHttp().getScenario();

        final MultivaluedHashMap<String, Object> fakeHttpHeaders = new MultivaluedHashMap<>();
        final ConcurrentMap<Future<?>, Boolean> computations = new ConcurrentHashMap<>();
        final MessageBodyWriter<LightHttpResponse> writerResponse = providers.getMessageBodyWriter(
                LightHttpResponse.class, LightHttpResponse.class,
                annotations, APPLICATION_JSON_TYPE);
        final MessageBodyWriter<ScenarioEnd> writerEnd = providers.getMessageBodyWriter(
                ScenarioEnd.class, ScenarioEnd.class,
                annotations, APPLICATION_JSON_TYPE);

        // not jaxrs one cause cxf wraps this one and prevents the flush() to works
        final HttpServletResponse httpServletResponse = HttpServletResponse.class.cast(httpServletRequest.getAttribute("tribe.registry.response"));
        httpServletResponse.setHeader("Content-Type", "text/event-stream");
        try {
            httpServletResponse.flushBuffer();
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }

        final ServletOutputStream out;
        try {
            out = httpServletResponse.getOutputStream();
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }

        mes.submit(() -> {
            final AtomicReference<Invoker.Handle> handleRef = new AtomicReference<>();

            try {
                // we compute some easy stats asynchronously
                final Map<Integer, AtomicInteger> sumPerResponse = new HashMap<>();
                final AtomicInteger total = new AtomicInteger();
                final AtomicLong min = new AtomicLong();
                final AtomicLong max = new AtomicLong();
                final AtomicLong sum = new AtomicLong();

                final AtomicInteger writeErrors = new AtomicInteger(0);

                final long start = System.currentTimeMillis();
                handleRef.set(invoker.invoke(scenario.getThreads(), scenario.getInvocations(), scenario.getDuration(), timeout, () -> {
                    if (handleRef.get().isCancelled()) {
                        return;
                    }

                    LightHttpResponse resp;
                    try {
                        final GenericClientService.Response invoke = service.invoke(req);
                        resp = new LightHttpResponse(invoke.getStatus(), null, invoke.getClientExecutionDurationMs());
                    } catch (final RuntimeException e) {
                        resp = new LightHttpResponse(-1, e.getMessage(), -1);
                    }

                    // let's process it in an environment where synchronisation is fine
                    final LightHttpResponse respRef = resp;
                    computations.put(mes.submit(() -> {
                        synchronized (out) {
                            try {
                                out.write(dataStart);
                                writerResponse.writeTo(respRef, LightHttpResponse.class, LightHttpResponse.class, annotations, APPLICATION_JSON_TYPE, fakeHttpHeaders, out);
                                out.write(dataEnd);
                                out.flush();
                            } catch (final IOException e) {
                                if (writeErrors.incrementAndGet() > toleratedWriteErrors) {
                                    handleRef.get().cancel();
                                }
                                throw new IllegalStateException(e);
                            }
                        }

                        if (handleRef.get().isCancelled()) {
                            return;
                        }

                        final long clientExecutionDurationMs = respRef.getClientExecutionDurationMs();

                        total.incrementAndGet();
                        sumPerResponse.computeIfAbsent(respRef.getStatus(), k -> new AtomicInteger()).incrementAndGet();
                        sum.addAndGet(clientExecutionDurationMs);
                        {
                            long m = min.get();
                            do {
                                m = min.get();
                                if (min.compareAndSet(m, clientExecutionDurationMs)) {
                                    break;
                                }
                            } while (m > clientExecutionDurationMs);
                        }

                        {
                            long m = max.get();
                            do {
                                m = max.get();
                                if (max.compareAndSet(m, clientExecutionDurationMs)) {
                                    break;
                                }
                            } while (m < clientExecutionDurationMs);
                        }
                    }), true);
                }));

                handleRef.get().await();

                final long end = System.currentTimeMillis();

                do { // wait all threads finished to compute the stats
                    final Iterator<Future<?>> iterator = computations.keySet().iterator();
                    while (iterator.hasNext()) {
                        try {
                            iterator.next().get(timeout, TimeUnit.MILLISECONDS);
                        } catch (final InterruptedException e) {
                            Thread.interrupted();
                        } catch (final ExecutionException | TimeoutException e) {
                            throw new IllegalStateException(e.getCause());
                        } finally {
                            iterator.remove();
                        }
                    }
                } while (!computations.isEmpty());

                if (handleRef.get().isCancelled()) {
                    return;
                }

                try {
                    out.write(dataStart);
                    writerEnd.writeTo(new ScenarioEnd(
                                    sumPerResponse.entrySet().stream().collect(toMap(Map.Entry::getKey, t -> t.getValue().get())),
                                    end - start, total.get(), min.get(), max.get(), sum.get() * 1. / total.get()),
                            ScenarioEnd.class, ScenarioEnd.class, annotations, APPLICATION_JSON_TYPE, new MultivaluedHashMap<>(), out);
                    out.write(dataEnd);
                    out.flush();
                } catch (final IOException e) {
                    throw new IllegalStateException(e);
                }
            } finally {
                try {
                    // cxf will skip it since we already write ourself
                    asyncResponse.resume("");
                } catch (final RuntimeException re) {
                    // no-op: not that important
                }
            }
        });
    }

    @POST
    @Path("header/oauth2")
    public ComputedHeader getOAuth2(final OAuth2Header request, @QueryParam("ignore-ssl") @DefaultValue("false") final boolean ignoreSsl) {
        return ofNullable(request)
                .filter(o -> o.getUsername() != null || o.getRefreshToken() != null)
                .map(o -> new ComputedHeader(request.getHeader(), service.oauth2Header(
                        o.getGrantType(), o.getUsername(), o.getPassword(), o.getRefreshToken(), o.getClientId(), o.getClientSecret(),
                        o.getEndpoint(), o.getTokenType(), ignoreSsl)))
                .orElseThrow(() -> new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    @POST
    @Path("header/basic")
    public ComputedHeader getBasic(final BasicHeader request) {
        return ofNullable(request)
                .filter(b -> b.getUsername() != null)
                .map(o -> new ComputedHeader(request.getHeader(), service.basicHeader(o.getUsername(), o.getPassword())))
                .orElseThrow(() -> new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    @POST
    @Path("header/signature")
    public ComputedHeader getSignature(final HttpSignatureHeader request) {
        return ofNullable(request) // should be the last one cause can depend on other headers potentially
                .filter(o -> o.getHeaders() != null && !o.getHeaders().isEmpty() && o.getAlias() != null && o.getSecret() != null)
                .map(o -> {
                    final URL url;
                    try {
                        url = new URL(request.getUrl());
                    } catch (final MalformedURLException e) {
                        throw new IllegalArgumentException(e);
                    }
                    return new ComputedHeader(
                            request.getHeader(),
                            service.httpSign(
                                    ofNullable(o.getHeaders()).orElseGet(() -> singletonList("(request-target)")), request.getMethod(),
                                    url.getPath() + ofNullable(url.getQuery()).filter(q -> q != null && !q.isEmpty()).map(q -> "?" + q).orElse(""),
                                    o.getAlias(), o.getSecret(),
                                    ofNullable(o.getAlgorithm()).orElse("hmac-sha256"),
                                    request.getRequestHeaders()));
                })
                .orElseThrow(() -> new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    private <T> T loadPayload(final Class<T> type, final Providers providers, final String data) {
        try {
            return providers.getMessageBodyReader(type, type, annotations, APPLICATION_JSON_TYPE)
                    .readFrom(type, type, annotations, APPLICATION_JSON_TYPE, new MultivaluedHashMap<>(), new ByteArrayInputStream(cryptoService.fromUrlString(data)));
        } catch (final IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Execution toExecution(final TryMeExecution e) {
        final GenericClientService.Request request = service.loadExecutionMember(GenericClientService.Request.class, e.getRequest());
        final GenericClientService.Response response = service.loadExecutionMember(GenericClientService.Response.class, e.getResponse());
        return new Execution(
                e.getId(),
                new HttpRequest(
                        request.isIgnoreSsl(), request.getMethod(), request.getUrl(), request.getHeaders(),
                        null, null, null,
                        ofNullable(request.getHeaders()).orElse(emptyMap()).entrySet().stream()  // we guess it there but enough
                                .filter(h -> h.getKey().toLowerCase(Locale.ENGLISH).equals("Digest"))
                                .findFirst()
                                .map(h -> new DigestHeader("Digest", h.getValue()))
                                .orElse(null),
                        request.getPayload(),
                        null /*not yet supported*/),
                new HttpResponse(response.getStatus(), response.getHeaders(), response.getPayload(), e.getResponseError(), response.getClientExecutionDurationMs()));
    }

    private GenericClientService.Request toRequest(final HttpRequest request) {
        final GenericClientService.Request req = new GenericClientService.Request();

        req.setMethod(request.getMethod());
        req.setUrl(request.getUrl());
        req.setPayload(request.getPayload());
        req.setIgnoreSsl(request.isIgnoreSsl());
        req.setHeaders(new HashMap<>(ofNullable(request.getHeaders()).orElse(emptyMap())));

        ofNullable(request.getOauth2())
                .filter(o -> o.getUsername() != null || o.getRefreshToken() != null)
                .ifPresent(o -> {
                    if (req.getHeaders().put(
                            ofNullable(o.getHeader()).orElse("Authorization"),
                            service.oauth2Header(
                                    ofNullable(o.getGrantType()).orElse("password"),
                                    o.getUsername(),
                                    o.getPassword(),
                                    o.getRefreshToken(),
                                    o.getClientId(),
                                    o.getClientSecret(),
                                    o.getEndpoint(),
                                    o.getTokenType(),
                                    request.isIgnoreSsl())) != null) {
                        throw new IllegalArgumentException("You already have a " + o.getHeader() + " header, oauth2 would overwrite it, please fix the request");
                    }
                });
        ofNullable(request.getBasic())
                .filter(o -> o.getUsername() != null)
                .ifPresent(o -> {
                    if (req.getHeaders().put(
                            ofNullable(o.getHeader()).orElse("Authorization"),
                            service.basicHeader(
                                    o.getUsername(),
                                    o.getPassword())) != null) {
                        throw new IllegalArgumentException("You already have a " + o.getHeader() + " header, basic would overwrite it, please fix the request");
                    }
                });
        ofNullable(request.getDigest())
                .filter(o -> o.getAlgorithm() != null)
                .ifPresent(o -> {
                    if (req.getHeaders().put(
                            ofNullable(o.getHeader()).orElse("Digest"),
                            service.digestHeader(ofNullable(request.getPayload()).orElse(""), o.getAlgorithm())) != null) {
                        throw new IllegalArgumentException("You already have a " + o.getHeader() + " header, digest would overwrite it, please fix the request");
                    }
                });
        ofNullable(request.getSignature())
                .filter(o -> o.getSecret() != null)
                .ifPresent(o -> {
                    if (req.getHeaders().put(
                            ofNullable(o.getHeader()).orElse("Authorization"),
                            service.httpSign(
                                    ofNullable(o.getHeaders()).orElse(emptyList()),
                                    ofNullable(o.getMethod()).filter(u -> u != null && !u.isEmpty()).orElse(request.getMethod()),
                                    ofNullable(o.getUrl()).filter(u -> u != null && !u.isEmpty()).orElse(request.getUrl()),
                                    o.getAlias(),
                                    o.getSecret(),
                                    ofNullable(o.getAlgorithm()).orElse("hmac-sha256"),
                                    ofNullable(o.getRequestHeaders()).filter(h -> h != null && !h.isEmpty()).orElseGet(req::getHeaders))) != null) {
                        throw new IllegalArgumentException("You already have a " + o.getHeader() + " header, signature would overwrite it, please fix the request");
                    }
                });
        return req;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Scenario {
        private int threads;
        private int invocations;
        private String duration;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ComputedHeader {
        private String name;
        private String value;
    }

    @Data
    public static class OAuth2Header {
        private String header;
        private String grantType;
        private String username;
        private String password;
        private String refreshToken;
        private String clientId;
        private String clientSecret;
        private String endpoint;
        private String tokenType;
    }

    @Data
    public static class HttpSignatureHeader {
        private String header;
        private String method;
        private String url;
        private Map<String, String> requestHeaders;
        private List<String> headers;
        private String algorithm;
        private String alias;
        private String secret;
    }

    @Data
    public static class BasicHeader {
        private String header;
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class DigestHeader {
        private String header;
        private String algorithm;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HttpRequest {
        private boolean ignoreSsl;
        private String method;
        private String url;
        private Map<String, String> headers;
        private OAuth2Header oauth2;
        private HttpSignatureHeader signature;
        private BasicHeader basic;
        private DigestHeader digest;
        private String payload;
        private Scenario scenario;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HttpResponse {
        private int status;
        private Map<String, String> headers;
        private String payload;
        private String error;
        private long clientExecutionDurationMs;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class LightHttpResponse {
        private int status;
        private String error;
        private long clientExecutionDurationMs;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ScenarioEnd {
        private Map<Integer, Integer> countPerStatus;
        private long duration;
        private long total;
        private long min;
        private long max;
        private double average;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Executions {
        private int total;
        private Collection<Execution> items;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Execution {
        private String executionId;
        private HttpRequest request;
        private HttpResponse response;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ExecutionId {
        private String id;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class SseRequest {
        private HttpRequest http;
        private String identity;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class DownloadResponses {
        private Collection<LightHttpResponse> data;
        private String identity;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CryptoData {
        private String data;
    }
}
