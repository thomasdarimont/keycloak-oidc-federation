package org.keycloak.protocol.oidc.federation.op.tasks;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.oidc.federation.common.helpers.FedUtils;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;

@AutoService(ClientExpiryTasksFactory.class)
public class DefaultClientExpiryTasksFactory implements ClientExpiryTasksFactory {

    private static final Logger LOG = Logger.getLogger(DefaultClientExpiryTasksFactory.class);

    public static final String PROVIDER_ID = "client-expiry-tasks";

    @Override
    public DefaultClientExpiryTasks create(KeycloakSession session) {
        return new DefaultClientExpiryTasks(session);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory sessionFactory) {

        sessionFactory.register(new ProviderEventListener() {
            @Override
            public void onEvent(ProviderEvent event) {
                if (event instanceof PostMigrationEvent) {
                    startFederationSecretsExpirationTracker(sessionFactory);
                }
            }
        });
    }

    private void startFederationSecretsExpirationTracker(KeycloakSessionFactory sessionFactory) {
        LOG.info("### starting federation secrets expiration tracker");
        KeycloakSession session = sessionFactory.create();
        session.getTransactionManager().begin();
        DefaultClientExpiryTasks cl = create(session);
        session.realms().getRealmsStream().forEach(realm -> realm.getClientsStream().forEach(client -> {

            if (!client.getAttributes().containsKey(FedUtils.SECRET_EXPIRES_AT)) {
                return;
            }

            String secretExpiresAtValue = client.getAttributes().get(FedUtils.SECRET_EXPIRES_AT);
            cl.scheduleTask(client.getId(), realm.getId(), Long.parseLong(secretExpiresAtValue));
        }));
        session.getTransactionManager().commit();
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


}
