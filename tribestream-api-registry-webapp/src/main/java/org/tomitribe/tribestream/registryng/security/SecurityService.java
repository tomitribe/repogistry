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

import lombok.extern.java.Log;
import org.apache.catalina.User;
import org.tomitribe.tribestream.registryng.entities.AccessToken;
import org.tomitribe.tribestream.registryng.security.oauth2.AccessTokenService;
import org.tomitribe.tribestream.registryng.security.oauth2.InvalidTokenException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;

@Log
@ApplicationScoped
public class SecurityService {
    @Inject
    private AccessTokenService accessTokenService;

    @Inject
    private LoginContext loginContext;

    // basically enable to do the security check programmatically for some specific endpoints like EventSource client ones
    // NOT designed to be widely used!
    public void check(final String authHeader,
                      final HttpServletRequest request,
                      final Runnable onValid,
                      final Runnable onError) {
        if (authHeader == null) {
            log.log(Level.FINE, "No Authorization header");
            onError.run();
            return;
        }

        if (authHeader.startsWith("Basic ")) {

            if (loginBasic(request, authHeader)) {
                onValid.run();
                try {
                    request.logout();
                } catch (final ServletException e) {
                    throw new IllegalStateException(e);
                }
            } else {
                onError.run();
            }

        } else if (authHeader.startsWith("Bearer ")) {

            try {
                final AccessToken token = accessTokenService.findToken(authHeader.substring("Bearer ".length()));
                loginContext.setUsername(token.getUsername());
                loginContext.setRoles(Stream.of(Optional
                        .ofNullable(token.getScope()).map(s -> s.split(" ")).orElseGet(() -> new String[0]))
                        .collect(toSet()));
                onValid.run();
            } catch (final InvalidTokenException e) {
                log.log(Level.INFO, "Token could not be validated!", e);
                onError.run();
            }

        } else {
            log.log(Level.FINE, "Unsupported authorization header");
            onError.run();
        }
    }

    private boolean loginBasic(final HttpServletRequest httpServletRequest, final String authHeader) {

        final String encodedToken = authHeader.substring("Basic ".length());
        final String clearToken = new String(Base64.getDecoder().decode(encodedToken), StandardCharsets.UTF_8);
        final String[] userPassword = clearToken.split(":");
        if (userPassword.length != 2) {
            return false;
        }
        final String username = userPassword[0];
        final String password = userPassword[1];
        try {
            httpServletRequest.login(username, password);
            loginContext.setUsername(username);
            Principal principal = httpServletRequest.getUserPrincipal();
            if (principal instanceof User) {
                Set<String> roles = new HashSet<>();
                User.class.cast(principal).getGroups()
                        .forEachRemaining(group ->
                                group.getRoles().forEachRemaining(role -> roles.add(role.getRolename())));
                User.class.cast(principal).getRoles()
                        .forEachRemaining(role -> roles.add(role.getRolename()));
                loginContext.setRoles(roles);
            }
            return true;
        } catch (final ServletException e) {
            log.log(Level.WARNING, e, () -> String.format("Login failed for user %s", username));
            return false;
        }
    }
}
