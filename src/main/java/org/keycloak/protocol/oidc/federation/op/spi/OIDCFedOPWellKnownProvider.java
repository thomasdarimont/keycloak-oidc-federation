package org.keycloak.protocol.oidc.federation.op.spi;
/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.federation.common.beans.EntityStatement;
import org.keycloak.protocol.oidc.federation.common.beans.Metadata;
import org.keycloak.protocol.oidc.federation.common.beans.OPMetadata;
import org.keycloak.protocol.oidc.federation.common.exceptions.InternalServerErrorException;
import org.keycloak.protocol.oidc.federation.common.helpers.FedUtils;
import org.keycloak.protocol.oidc.federation.op.model.OIDCFedConfigService;
import org.keycloak.protocol.oidc.federation.op.rest.FederationOPService;
import org.keycloak.protocol.oidc.federation.op.rest.OIDCFederationResourceProvider;
import org.keycloak.protocol.oidc.federation.op.rest.OIDCFederationResourceProviderFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

import ext.federation.entity.OIDCFedConfigEntity;

public class OIDCFedOPWellKnownProvider extends OIDCWellKnownProvider {

    public static final List<String> CLIENT_REGISTRATION_TYPES_SUPPORTED = Arrays.asList("automatic", "explicit");

    private final KeycloakSession session;
    private final OIDCFedConfigService configurationService;

    public OIDCFedOPWellKnownProvider(KeycloakSession session) {
        super(session);
        this.session = session;
        this.configurationService = new OIDCFedConfigService(session);
    }

    @Override
    public Object getConfig() {
        
        OIDCFedConfigEntity conf =configurationService.getEntity();
        //realm without authority hints must not expose this web service
        if (conf == null || conf.getConfiguration() == null || conf.getConfiguration().getAuthorityHints().isEmpty())
            throw new NotFoundException("This realm is not a OIDC Federation member");
        
        UriInfo frontendUriInfo = session.getContext().getUri(UrlType.FRONTEND);
        UriInfo backendUriInfo = session.getContext().getUri(UrlType.BACKEND);

        RealmModel realm = session.getContext().getRealm();

        UriBuilder frontendUriBuilder = RealmsResource.realmBaseUrl(frontendUriInfo);
        UriBuilder backendUriBuilder = RealmsResource.realmBaseUrl(backendUriInfo);

        OPMetadata config;
        try {
            config = from(((OIDCConfigurationRepresentation) super.getConfig()));
        } catch (IOException e) {
            throw new InternalServerErrorException("Could not form the configuration response");
        }

        //additional federation-specific configuration
        if (!"automatic".equals(conf.getConfiguration().getRegistrationType()))
            config.setFederationRegistrationEndpoint(backendUriBuilder.clone().path(OIDCFederationResourceProviderFactory.ID)
                .path(OIDCFederationResourceProvider.class, "getFederationOPService")
                .path(FederationOPService.class, "getFederationRegistration").build(realm.getName()).toString());
        Map<String, List<String>> clientRegMap = new HashMap<>();
        clientRegMap.put("ar", Collections.singletonList("request_object"));
        config.setClientRegistrationAuthnMethodsSupported(clientRegMap);
        config.setClientRegistrationTypesSupported(
            "both".equals(conf.getConfiguration().getRegistrationType()) ? CLIENT_REGISTRATION_TYPES_SUPPORTED
                : Collections.singletonList(conf.getConfiguration().getRegistrationType()));


        Metadata metadata = new Metadata();
        metadata.setOpenIdProviderMetadata(config);

        EntityStatement entityStatement = new EntityStatement();
        entityStatement.setMetadata(metadata);
        entityStatement.setAuthorityHints(new ArrayList<>(conf.getConfiguration().getAuthorityHints()));
        entityStatement.setJwks(FedUtils.getKeySet(session));
        entityStatement.issuer(Urls.realmIssuer(frontendUriInfo.getBaseUri(), realm.getName()));
        entityStatement.subject(Urls.realmIssuer(frontendUriInfo.getBaseUri(), realm.getName()));
        entityStatement.issuedNow();
        entityStatement.exp((long) Time.currentTime() + Long.valueOf(conf.getConfiguration().getExpirationTime()));

        //sign and encode entity statement
        String encodedToken = session.tokens().encode(entityStatement);

        return encodedToken;
    }

    public static OPMetadata from(OIDCConfigurationRepresentation representation) throws IOException {
        return JsonSerialization.readValue(JsonSerialization.writeValueAsString(representation), OPMetadata.class);
    }

}
