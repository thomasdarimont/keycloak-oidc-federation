package org.keycloak.protocol.oidc.federation.op.model;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "OIDC_FEDERATION_CONFIG")
public class OIDCFedConfigEntity {

    // TODO add database index
    @Id
    @Column(name = "REALM_ID", nullable = false)
    private String realmId;

    @Column(name = "CONFIGURATION", nullable = false)
    @Convert(converter = OIDCFedConfigJsonConverter.class)
    private OIDCFedConfig configuration;

    public OIDCFedConfigEntity() {
    }

    public OIDCFedConfigEntity(String realmId, OIDCFedConfig configuration) {
        this.realmId = realmId;
        this.configuration = configuration;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public OIDCFedConfig getConfiguration() {
        return configuration;
    }

    public void setConfiguration(OIDCFedConfig configuration) {
        this.configuration = configuration;
    }

}
