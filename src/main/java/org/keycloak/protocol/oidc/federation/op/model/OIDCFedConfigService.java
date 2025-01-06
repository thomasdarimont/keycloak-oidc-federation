package org.keycloak.protocol.oidc.federation.op.model;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import ext.federation.entity.OIDCFedConfigEntity;

public class OIDCFedConfigService {

    private final RealmModel realm;

    private final EntityManager em;

    public OIDCFedConfigService(KeycloakSession session) {
        realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
        }
        em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    public OIDCFedConfigEntity getEntity() {
        return em.find(OIDCFedConfigEntity.class, realm.getId());
    }

    public void saveEntity(OIDCFedConfigEntity config) {
        em.persist(config);
    }


    public void deleteEntity() throws NotFoundException {
        OIDCFedConfigEntity entity = em.find(OIDCFedConfigEntity.class, realm.getId());
        if (entity == null) {
            throw new NotFoundException(String.format("Realm %s does not have", realm.getName()));
        }
        em.remove(entity);
    }

}
