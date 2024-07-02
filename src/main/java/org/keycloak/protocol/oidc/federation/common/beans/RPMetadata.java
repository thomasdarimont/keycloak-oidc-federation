package org.keycloak.protocol.oidc.federation.common.beans;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.common.util.Time;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

import java.util.List;

public class RPMetadata extends OIDCClientRepresentation {

    @JsonProperty("client_registration_types")
    private List<String> clientRegistrationTypes;

    @JsonProperty("organization_name")
    private String organizationName;

    @JsonProperty("trust_anchor_id")
    private String trustAnchorId;

    public RPMetadata() {

    }

    public RPMetadata(OIDCClientRepresentation oidcClient, List<String> clientRegistrationTypes, String organizationName) {
        this.setContacts(oidcClient.getContacts());
        this.setDefaultAcrValues(oidcClient.getDefaultAcrValues());
        this.setGrantTypes(oidcClient.getGrantTypes());
        this.setPostLogoutRedirectUris(oidcClient.getPostLogoutRedirectUris());
        this.setRedirectUris(oidcClient.getRedirectUris());
        this.setRequestUris(oidcClient.getRequestUris());
        this.setResponseTypes(oidcClient.getResponseTypes());
        this.setApplicationType(oidcClient.getApplicationType());
        this.setClientId(oidcClient.getClientId());
        this.setClientName(oidcClient.getClientName());
        this.setClientSecret(oidcClient.getClientSecret());
        this.setClientSecretExpiresAt(oidcClient.getClientSecretExpiresAt());
        this.setClientUri(oidcClient.getClientUri());
        this.setDefaultAcrValues(oidcClient.getDefaultAcrValues());
        this.setDefaultMaxAge(oidcClient.getDefaultMaxAge());
        this.setIdTokenEncryptedResponseAlg(oidcClient.getIdTokenEncryptedResponseAlg());
        this.setIdTokenEncryptedResponseEnc(oidcClient.getIdTokenEncryptedResponseEnc());
        this.setIdTokenSignedResponseAlg(oidcClient.getIdTokenSignedResponseAlg());
        this.setIdTokenSignedResponseAlg(oidcClient.getIdTokenSignedResponseAlg());
        this.setJwks(oidcClient.getJwks());
        this.setJwksUri(oidcClient.getJwksUri());
        this.setLogoUri(oidcClient.getLogoUri());
        this.setPolicyUri(oidcClient.getPolicyUri());
        this.setRegistrationAccessToken(oidcClient.getRegistrationAccessToken());
        this.setRegistrationClientUri(oidcClient.getRegistrationClientUri());
        this.setRequestObjectEncryptionAlg(oidcClient.getRequestObjectEncryptionAlg());
        this.setRequestObjectEncryptionEnc(oidcClient.getRequestObjectEncryptionEnc());
        this.setRequestObjectSigningAlg(oidcClient.getRequestObjectSigningAlg());
        this.setRequireAuthTime(oidcClient.getRequireAuthTime());
        this.setScope(oidcClient.getScope());
        this.setSectorIdentifierUri(oidcClient.getSectorIdentifierUri());
        this.setSoftwareId(oidcClient.getSoftwareId());
        this.setSubjectType(oidcClient.getSubjectType());
        this.setTlsClientAuthSubjectDn(oidcClient.getTlsClientAuthSubjectDn());
        this.setTlsClientCertificateBoundAccessTokens(oidcClient.getTlsClientCertificateBoundAccessTokens());
        this.setTokenEndpointAuthMethod(oidcClient.getTokenEndpointAuthMethod());
        this.setTokenEndpointAuthSigningAlg(oidcClient.getTokenEndpointAuthSigningAlg());
        this.setTosUri(oidcClient.getTosUri());
        this.setUserinfoEncryptedResponseAlg(oidcClient.getUserinfoEncryptedResponseAlg());
        this.setUserinfoEncryptedResponseEnc(oidcClient.getUserinfoEncryptedResponseEnc());
        this.setUserinfoSignedResponseAlg(oidcClient.getUserinfoSignedResponseAlg());
        this.clientRegistrationTypes = clientRegistrationTypes;
        this.organizationName = organizationName;
        this.setClientIdIssuedAt(Time.currentTime());

    }

    public List<String> getClientRegistrationTypes() {
        return clientRegistrationTypes;
    }

    public void setClientRegistrationTypes(List<String> clientRegistrationTypes) {
        this.clientRegistrationTypes = clientRegistrationTypes;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getTrustAnchorId() {
        return trustAnchorId;
    }

    public void setTrustAnchorId(String trustAnchorId) {
        this.trustAnchorId = trustAnchorId;
    }

}
