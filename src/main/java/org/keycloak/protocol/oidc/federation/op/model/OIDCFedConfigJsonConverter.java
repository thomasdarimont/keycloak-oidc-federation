package org.keycloak.protocol.oidc.federation.op.model;

import jakarta.persistence.AttributeConverter;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class OIDCFedConfigJsonConverter implements AttributeConverter<OIDCFedConfig, String> {

    @Override
    public String convertToDatabaseColumn(OIDCFedConfig config) {
        try {
            return JsonSerialization.writeValueAsString(config);
        } catch (IOException e) {
            throw new RuntimeException("Could not convert to Json", e);
        }
    }

    @Override
    public OIDCFedConfig convertToEntityAttribute(String json) {
        try {
            return JsonSerialization.readValue(json, OIDCFedConfig.class);
        } catch (IOException e) {
            throw new RuntimeException("Could not convert from Json", e);
        }
    }
}

