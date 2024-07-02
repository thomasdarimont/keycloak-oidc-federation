package org.keycloak.protocol.oidc.federation.op.tasks;

import com.google.auto.service.AutoService;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

@AutoService(Spi.class)
public class ClientExpiryTasksSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "client-expiry-tasks-spi";
    }


    @Override
    public Class<? extends Provider> getProviderClass() {
        return ClientExpiryTasks.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ClientExpiryTasksFactory.class;
    }


}
