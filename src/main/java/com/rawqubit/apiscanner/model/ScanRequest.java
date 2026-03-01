package com.rawqubit.apiscanner.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ScanRequest {

    /** Raw OpenAPI/Swagger YAML or JSON spec content. */
    private String specContent;

    /** URL pointing to a publicly accessible OpenAPI spec. */
    private String specUrl;

    /** Optional: target base URL of the API being scanned. */
    private String targetUrl;

    /** Whether to include AI-powered deep analysis (requires OPENAI_API_KEY). */
    private boolean aiAnalysis = true;

    /** Minimum CVSS severity to include in the report (low/medium/high/critical). */
    private String minSeverity = "low";
}
