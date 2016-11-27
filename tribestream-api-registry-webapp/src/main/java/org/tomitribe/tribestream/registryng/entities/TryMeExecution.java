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
package org.tomitribe.tribestream.registryng.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;

@Getter
@Setter
@Entity
@NamedQueries({
        @NamedQuery(name = "TryMeExecution.count", query = "select count(e) from TryMeExecution e where e.endpoint.id = :endpointId"),
        @NamedQuery(name = "TryMeExecution.findByEndpoint", query = "select e from TryMeExecution e where e.endpoint.id = :endpointId")
})
public class TryMeExecution extends AbstractEntity {
    @ManyToOne(optional = false)
    private Endpoint endpoint;

    @Lob
    private String request;

    @Lob
    private String response;

    @Lob
    private String responseError;
}
