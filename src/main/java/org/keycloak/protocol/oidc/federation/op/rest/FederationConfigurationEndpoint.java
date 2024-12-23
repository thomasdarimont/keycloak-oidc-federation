package org.keycloak.protocol.oidc.federation.op.rest;


import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.federation.op.model.OIDCFedConfig;
import org.keycloak.protocol.oidc.federation.op.model.OIDCFedConfigService;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

import ext.federation.entity.OIDCFedConfigEntity;

public class FederationConfigurationEndpoint {

    private static final Logger logger = Logger.getLogger(FederationConfigurationEndpoint.class);

    private final KeycloakSession session;
    private final AdminPermissionEvaluator auth;
    private final OIDCFedConfigService configurationService;

    public FederationConfigurationEndpoint(KeycloakSession session) {
        this.session = session;
        this.auth = authenticateRealmAdminRequest();
        this.configurationService = new OIDCFedConfigService(session);

    }

    private AdminPermissionEvaluator authenticateRealmAdminRequest() {
        HttpHeaders headers = session.getContext().getRequestHeaders();
        String tokenString = AppAuthManager.extractAuthorizationHeaderToken(headers);
        if (tokenString == null) {
            throw new NotAuthorizedException("Bearer");
        }
        AccessToken token;
        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new NotAuthorizedException("Bearer token format error");
        }
        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
        if (!realm.getId().equals(session.getContext().getRealm().getId())) {
            throw new NotAuthorizedException("False realm in token");
        }

        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null) {
            logger.debug("Token not valid");
            throw new NotAuthorizedException("Bearer");
        }

        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null) {
            throw new NotFoundException("Could not find client for authorization");
        }

        AdminAuth adminAuth = new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
        return AdminPermissions.evaluator(session, realm, adminAuth);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public OIDCFedConfig getConfiguration() {
        this.auth.realm().requireViewRealm();
        OIDCFedConfigEntity entity = configurationService.getEntity();
        return entity != null ? entity.getConfiguration() : null;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response saveConfiguration(OIDCFedConfig configuration) {
        this.auth.realm().requireManageRealm();
        RealmModel realmModel = session.getContext().getRealm();
        try {
            OIDCFedConfigEntity entity = configurationService.getEntity();
            if (entity == null) {
                entity = new OIDCFedConfigEntity(realmModel.getId(), configuration);
            } else {
                entity.setConfiguration(configuration);
            }
            configurationService.saveEntity(entity);
            return Response.ok(configuration).build();
        } catch (Exception ex) {
            return ErrorResponse.error("Failed to create configuration for the realm " + realmModel.getName(), Response.Status.NOT_FOUND).getResponse();
        }
    }

    @DELETE
    public Response deleteConfiguration() {
        this.auth.realm().requireManageRealm();
        try {
            configurationService.deleteEntity();
        } catch (NotFoundException e) {
            e.printStackTrace();
            return ErrorResponse.error(e.getMessage(), Response.Status.NOT_FOUND).getResponse();
        }
        return Response.noContent().build();
    }


}
