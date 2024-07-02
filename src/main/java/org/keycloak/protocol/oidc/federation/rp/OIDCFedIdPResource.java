package org.keycloak.protocol.oidc.federation.rp;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.federation.common.TrustChain;
import org.keycloak.protocol.oidc.federation.common.beans.EntityStatement;
import org.keycloak.protocol.oidc.federation.common.exceptions.BadSigningOrEncryptionException;
import org.keycloak.protocol.oidc.federation.common.exceptions.UnparsableException;
import org.keycloak.protocol.oidc.federation.common.exceptions.serializers.ExceptionMessage;
import org.keycloak.protocol.oidc.federation.common.helpers.FedUtils;
import org.keycloak.protocol.oidc.federation.common.processes.TrustChainProcessor;
import org.keycloak.protocol.oidc.federation.rp.broker.OIDCFedIdentityProviderConfig;
import org.keycloak.protocol.oidc.federation.rp.helpers.EntityStatementConverter;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

import java.io.IOException;
import java.net.URL;
import java.util.List;

public class OIDCFedIdPResource {

    private static final Logger logger = Logger.getLogger(OIDCFedIdPResource.class);

    private final KeycloakSession session;
    private final OIDCFedIdentityProviderConfig config;
    private final RealmModel realm;

    public OIDCFedIdPResource(KeycloakSession session, RealmModel realm, OIDCFedIdentityProviderConfig config) {
        this.session = session;
        this.config = config;
        this.realm = realm;
    }

    @GET
    @Path(".well-known/oidc-federation")
    @Produces(MediaType.APPLICATION_JSON)
    public String getConfiguration() {

        // form here the response of the well-known
        return String.format("{\"status\": \"Success\", \"realm\": \"%s\"}", realm.getName());
    }

    @GET
    @Path("explicit-registration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response excplicitRegistration() {
        AdminPermissionEvaluator auth = authenticateRealmAdminRequest();
        if (!"explicit".equals(config.getClientRegistrationTypes()))
            return Response.status(Response.Status.BAD_REQUEST).entity(new ExceptionMessage("This OIDC Federation RP does not support excplicit registration")).build();

        TrustChainProcessor trustChainProcessor = new TrustChainProcessor();
        String federationRegistrationUrl;
        try {
            String jwtStatement = FedUtils.getSelfSignedToken(config.getOpEntityIdentifier());
            EntityStatement opStatement = trustChainProcessor.parseAndValidateSelfSigned(jwtStatement);
            if (opStatement.getMetadata() == null || opStatement.getMetadata().getOpenIdProviderMetadata() == null || opStatement.getMetadata().getOpenIdProviderMetadata().getFederationRegistrationEndpoint() == null || opStatement.getMetadata().getOpenIdProviderMetadata().getClientRegistrationTypesSupported() == null || !opStatement.getMetadata().getOpenIdProviderMetadata().getClientRegistrationTypesSupported().contains("explicit"))
                return Response.status(Response.Status.BAD_REQUEST).entity(new ExceptionMessage("This is not a OIDC Federation OP or it does not support excplicit registration")).build();

            List<TrustChain> trustChains = trustChainProcessor.constructTrustChainsFromJWT(jwtStatement, config.getTrustAnchorIds(), false);
            if (!trustChains.isEmpty()) {
                federationRegistrationUrl = opStatement.getMetadata().getOpenIdProviderMetadata().getFederationRegistrationEndpoint();
            } else {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Exception in fetching .well-known")).build();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Exception in fetching .well-known")).build();
        } catch (UnparsableException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Exception in parsing entity statement of .well-known")).build();
        } catch (BadSigningOrEncryptionException e) {
            e.printStackTrace();
            return Response.status(Response.Status.UNAUTHORIZED).entity(new ExceptionMessage("No valid token for .well-known")).build();
        }

        try {
            EntityStatement statement = EntityStatementConverter.convertOIDCFedOpToEntityStatement(config, session);
            String token = session.tokens().encode(statement);

            String entityResponse = FedUtils.getJoseContentFromPost(new URL(federationRegistrationUrl), token);
            try {
                EntityStatement responseStatement = trustChainProcessor.parseAndValidateSelfSigned(entityResponse);
                // do antything with policy and authority hint???
                if (responseStatement.getMetadata() == null || responseStatement.getMetadata().getRelyingPartyMetadata() == null || responseStatement.getAuthorityHints() == null || !config.getTrustAnchorIds().contains(responseStatement.getMetadata().getRelyingPartyMetadata().getTrustAnchorId()))
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Wrong OP Response entity statement")).build();

                IdentityProviderModel model = EntityStatementConverter.convertEntityStatementToIdp(responseStatement.getMetadata().getRelyingPartyMetadata(), realm, config.getAlias());
                IdentityProviderRepresentation representation = ModelToRepresentation.toRepresentation(realm, model);
                return Response.ok(representation).build();
            } catch (UnparsableException e) {
                e.printStackTrace();
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Exception in parsing OP Response entity statement")).build();
            } catch (BadSigningOrEncryptionException e) {
                e.printStackTrace();
                return Response.status(Response.Status.UNAUTHORIZED).entity(new ExceptionMessage("No valid token for OP Response entity statement")).build();
            }
            // entityResponse parse and save
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ExceptionMessage("Exception in registration process")).build();
        }

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

}
