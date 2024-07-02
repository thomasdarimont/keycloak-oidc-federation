package org.keycloak.protocol.oidc.federation.op.tasks;

import org.keycloak.provider.Provider;

public interface ClientExpiryTasks extends Provider {

    void scheduleTask(String id, String realmId, long expiresAt);

}
