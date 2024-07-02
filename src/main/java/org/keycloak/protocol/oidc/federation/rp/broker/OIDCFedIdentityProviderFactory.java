package org.keycloak.protocol.oidc.federation.rp.broker;

import com.google.auto.service.AutoService;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import java.util.HashMap;
import java.util.Map;

@AutoService(IdentityProviderFactory.class)
public class OIDCFedIdentityProviderFactory extends AbstractIdentityProviderFactory<OIDCFedIdentityProvider> {

    public static final String PROVIDER_ID = "oidc-federation";

    @Override
    public String getName() {
        return "OpenID Connect Federation";
    }

    @Override
    public OIDCFedIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OIDCFedIdentityProvider(session, new OIDCFedIdentityProviderConfig(model));
    }

    @Override
    public OIDCFedIdentityProviderConfig createConfig() {
        return new OIDCFedIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String config) {
        //may be needed to implement later
        return new HashMap<>();
    }
}