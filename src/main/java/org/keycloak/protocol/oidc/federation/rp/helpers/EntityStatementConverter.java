package org.keycloak.protocol.oidc.federation.rp.helpers;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.common.util.Time;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.federation.common.beans.EntityStatement;
import org.keycloak.protocol.oidc.federation.common.beans.Metadata;
import org.keycloak.protocol.oidc.federation.common.beans.RPMetadata;
import org.keycloak.protocol.oidc.federation.common.helpers.FedUtils;
import org.keycloak.protocol.oidc.federation.rp.broker.OIDCFedIdentityProviderConfig;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class EntityStatementConverter {

    public static EntityStatement convertOIDCFedOpToEntityStatement(OIDCFedIdentityProviderConfig config, KeycloakSession session) throws IOException {

        RPMetadata rp = new RPMetadata();
        rp.setClientRegistrationTypes(Collections.singletonList(config.getClientRegistrationTypes()));
        rp.setClientName(config.getDisplayName());
        rp.setJwksUri(config.getJwksUrl());
        rp.setPolicyUri(config.getIssuer());
        if (config.getLogoutUrl() != null && !config.getLogoutUrl().isEmpty())
            rp.setPostLogoutRedirectUris(Collections.singletonList(config.getLogoutUrl()));
        rp.setScope(config.getDefaultScope());
        rp.setTokenEndpointAuthMethod(config.getClientAuthMethod());
        rp.setGrantTypes(Collections.singletonList(OAuth2Constants.AUTHORIZATION_CODE));
        rp.setApplicationType("web");

        Metadata metadata = new Metadata();
        metadata.setRelyingPartyMetadata(rp);

        EntityStatement entityStatement = new EntityStatement();
        entityStatement.setMetadata(metadata);
        entityStatement.setAuthorityHints(config.getAuthorityHints());
        entityStatement.setJwks(FedUtils.getKeySet(session));
        entityStatement.issuer(config.getClientId());
        entityStatement.subject(config.getClientId());
        entityStatement.issuedNow();
        entityStatement.exp((long) Time.currentTime() + config.getExpired());
        entityStatement.addAudience(config.getOpEntityIdentifier());
        return entityStatement;
    }

    public static IdentityProviderModel convertEntityStatementToIdp(RPMetadata rp, RealmModel realm, String alias) {
        IdentityProviderModel model = realm.getIdentityProviderByAlias(alias);
        //RPMetadata rp = entityStatement.getMetadata().getRp();
        model.setDisplayName(rp.getClientName());
        model.setEnabled(true);
        Map<String, String> config = model.getConfig();
        config.put(OIDCIdentityProviderConfig.JWKS_URL, rp.getJwksUri());
        config.put(OIDCIdentityProviderConfig.USE_JWKS_URL, String.valueOf(rp.getJwksUri() != null));
        config.put("issuer", rp.getPolicyUri());
        if (rp.getPostLogoutRedirectUris() != null && !rp.getPostLogoutRedirectUris().isEmpty()) {
            config.put("logoutUrl", rp.getPostLogoutRedirectUris().get(0));
        }
        config.put("defaultScope", rp.getScope());
        config.put("clientId", rp.getClientId());
        config.put("clientSecret", rp.getClientSecret());
        config.put("clientAuthMethod", rp.getTokenEndpointAuthMethod());
        try {
            config.put(OIDCFedIdentityProviderConfig.TRUST_ANCHOR_IDS, JsonSerialization.writeValueAsString(Collections.singletonList(rp.getTrustAnchorId())));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        config.put(OIDCFedIdentityProviderConfig.EXPIRED, String.valueOf(rp.getClientSecretExpiresAt()));
        model.setConfig(config);

        realm.updateIdentityProvider(model);

        return model;
    }

}
