package org.keycloak.protocol.oidc.federation.common.beans;

import com.fasterxml.jackson.annotation.JsonProperty;

public class MetadataPolicy {

    @JsonProperty("openid_relying_party")
    private RPMetadataPolicy relyingPartyPolicy;

    @JsonProperty("openid_provider")
    private OPMetadataPolicy openIdProviderPolicy;

    public MetadataPolicy() {
    }

    public MetadataPolicy(RPMetadataPolicy relyingPartyPolicy) {
        this.relyingPartyPolicy = relyingPartyPolicy;
    }

    public MetadataPolicy(OPMetadataPolicy openIdProviderPolicy) {
        this.openIdProviderPolicy = openIdProviderPolicy;
    }

    public RPMetadataPolicy getRelyingPartyPolicy() {
        return relyingPartyPolicy;
    }

    public void setRelyingPartyPolicy(RPMetadataPolicy relyingPartyPolicy) {
        this.relyingPartyPolicy = relyingPartyPolicy;
    }

    public OPMetadataPolicy getOpenIdProviderPolicy() {
        return openIdProviderPolicy;
    }

    public void setOpenIdProviderPolicy(OPMetadataPolicy openIdProviderPolicy) {
        this.openIdProviderPolicy = openIdProviderPolicy;
    }

}
