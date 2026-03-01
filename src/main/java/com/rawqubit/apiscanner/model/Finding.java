package com.rawqubit.apiscanner.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Finding {

    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    public enum Category {
        BROKEN_OBJECT_LEVEL_AUTH,
        BROKEN_AUTHENTICATION,
        EXCESSIVE_DATA_EXPOSURE,
        RATE_LIMITING,
        BROKEN_FUNCTION_LEVEL_AUTH,
        MASS_ASSIGNMENT,
        SECURITY_MISCONFIGURATION,
        INJECTION,
        IMPROPER_ASSETS_MANAGEMENT,
        INSUFFICIENT_LOGGING,
        MISSING_ENCRYPTION,
        MISSING_AUTH
    }

    private String id;
    private String title;
    private String description;
    private Severity severity;
    private Category category;
    private String endpoint;
    private String method;
    private String remediation;
    private String owaspRef;
    private double cvssScore;
    private boolean aiEnhanced;
}
