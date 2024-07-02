package org.keycloak.protocol.oidc.federation.common.beans;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Metadata {

    @JsonProperty("openid_provider")
    private OPMetadata openIdProviderMetadata;

    @JsonProperty("federation_entity")
    private FederationEntity federationEntity;

    @JsonProperty("openid_relying_party")
    private RPMetadata relyingPartyMetadata;

    public OPMetadata getOpenIdProviderMetadata() {
        return openIdProviderMetadata;
    }

    public void setOpenIdProviderMetadata(OPMetadata openIdProviderMetadata) {
        this.openIdProviderMetadata = openIdProviderMetadata;
    }

    public FederationEntity getFederationEntity() {
        return federationEntity;
    }

    public void setFederationEntity(FederationEntity federationEntity) {
        this.federationEntity = federationEntity;
    }

    public RPMetadata getRelyingPartyMetadata() {
        return relyingPartyMetadata;
    }

    public void setRelyingPartyMetadata(RPMetadata relyingPartyMetadata) {
        this.relyingPartyMetadata = relyingPartyMetadata;
    }

}
