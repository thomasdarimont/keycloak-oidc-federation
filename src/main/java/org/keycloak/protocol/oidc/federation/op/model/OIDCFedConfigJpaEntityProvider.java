package org.keycloak.protocol.oidc.federation.op.model;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import ext.federation.entity.OIDCFedConfigEntity;

import java.util.Collections;
import java.util.List;

public class OIDCFedConfigJpaEntityProvider implements JpaEntityProvider {

    // List of your JPA entities.
    @Override
    public List<Class<?>> getEntities() {
        return Collections.singletonList(OIDCFedConfigEntity.class);
    }

    // This is used to return the location of the Liquibase changelog file.
    // You can return null if you don't want Liquibase to create and update the DB schema.
    @Override
    public String getChangelogLocation() {
        return "META-INF/changelog/oidc-federation-changelog.xml";
    }

    // Helper method, which will be used internally by Liquibase.
    @Override
    public String getFactoryId() {
        return OIDCFedConfigJpaEntityProviderFactory.ID;
    }

    @Override
    public void close() {

    }

}