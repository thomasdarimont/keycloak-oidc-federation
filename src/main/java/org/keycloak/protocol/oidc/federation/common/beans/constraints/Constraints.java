package org.keycloak.protocol.oidc.federation.common.beans.constraints;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Constraints {

    @JsonProperty("naming_constraints")
    private NamingConstraints namingConstraints;

    @JsonProperty("max_path_length")
    private Integer maxPathLength;

    public NamingConstraints getNamingConstraints() {
        return namingConstraints;
    }

    public void setNamingConstraints(NamingConstraints namingConstraints) {
        this.namingConstraints = namingConstraints;
    }

    public Integer getMaxPathLength() {
        return maxPathLength;
    }

    public void setMaxPathLength(Integer maxPathLength) {
        this.maxPathLength = maxPathLength;
    }

}
