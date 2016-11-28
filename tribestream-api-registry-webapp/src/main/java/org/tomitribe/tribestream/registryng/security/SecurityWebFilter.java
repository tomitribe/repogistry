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
package org.tomitribe.tribestream.registryng.security;

import org.apache.deltaspike.core.api.config.ConfigProperty;
import org.tomitribe.tribestream.registryng.documentation.Description;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;

@WebFilter(urlPatterns = "/api/*", asyncSupported = true)
public class SecurityWebFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(SecurityWebFilter.class.getName());

    @Inject
    private SecurityService securityService;

    /**
     * Contains all request URIs that are available without authentication.
     * Everything that is not under /api is available because the filter does not apply for these requests.
     */
    private Set<String> urlWhiteList;

    @Inject
    @Description("The comma separated list of URL not requiring any valid logged in user. Defaults match server expectation, it is not recommanded to remove them.")
    @ConfigProperty(
            name = "tribe.registry.security.filter.whitelist",
            defaultValue = "/api/server/info,/api/login,/api/security/oauth2,/api/security/oauth2/status,/api/try/invoke/stream")
    private String whitelistConfig;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        urlWhiteList = Stream.of(whitelistConfig.split(","))
                .map(p -> filterConfig.getServletContext().getContextPath() + p)
                .collect(toSet());
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

        // to let jaxrs endpoint use the raw response for advanced cases
        httpServletRequest.setAttribute("tribe.registry.response", servletResponse);

        if (isSecuredPath(httpServletRequest)) {
            securityService.check(
                    httpServletRequest.getHeader("Authorization"), httpServletRequest,
                    () -> {
                        try {
                            filterChain.doFilter(servletRequest, servletResponse);
                        } catch (IOException | ServletException e) {
                            throw new IllegalStateException(e);
                        }
                    },
                    () -> {
                        try {
                            sendUnauthorizedResponse(servletResponse);
                        } catch (final IOException e) {
                            throw new IllegalStateException(e);
                        }
                    });
        } else {
            LOGGER.fine(() -> "Request to " + httpServletRequest.getRequestURI() + " is not secured.");
            filterChain.doFilter(servletRequest, servletResponse);

        }
    }

    private boolean isSecuredPath(HttpServletRequest httpServletRequest) {
        return !urlWhiteList.contains(httpServletRequest.getRequestURI());
    }

    private void sendUnauthorizedResponse(ServletResponse servletResponse) throws IOException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Override
    public void destroy() {

    }
}
