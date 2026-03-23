package com.rawqubit.apiscanner.analyzer;

import com.rawqubit.apiscanner.model.Finding;
import com.rawqubit.apiscanner.model.Finding.Category;
import com.rawqubit.apiscanner.model.Finding.Severity;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Core heuristic analyzer that inspects an OpenAPI spec for OWASP API Top 10 vulnerabilities.
 */
@Slf4j
@Component
public class ApiSecurityAnalyzer {

    public List<Finding> analyze(OpenAPI spec) {
        List<Finding> findings = new ArrayList<>();

        if (spec.getPaths() == null) {
            return findings;
        }

        spec.getPaths().forEach((path, pathItem) -> {
            getAllOperations(pathItem).forEach((method, operation) -> {
                findings.addAll(checkMissingAuth(path, method, operation, spec));
                findings.addAll(checkExcessiveDataExposure(path, method, operation));
                findings.addAll(checkMissingRateLimiting(path, method, operation));
                findings.addAll(checkInjectionRisk(path, method, operation));
                findings.addAll(checkMassAssignment(path, method, operation));
                findings.addAll(checkSensitiveDataInPath(path, method, operation));
            });
        });

        findings.addAll(checkMissingHttps(spec));
        findings.addAll(checkWeakSecuritySchemes(spec));
        findings.addAll(checkMissingGlobalSecurity(spec));

        log.info("Analysis complete: {} findings across {} paths",
                findings.size(), spec.getPaths().size());
        return findings;
    }

    // -----------------------------------------------------------------------
    // OWASP API1: Broken Object Level Authorization
    // -----------------------------------------------------------------------

    private List<Finding> checkMissingAuth(String path, String method, Operation op, OpenAPI spec) {
        List<Finding> results = new ArrayList<>();

        boolean hasAuth = (op.getSecurity() != null && !op.getSecurity().isEmpty())
                || (spec.getSecurity() != null && !spec.getSecurity().isEmpty());

        if (!hasAuth && isDataMutationMethod(method)) {
            results.add(Finding.builder()
                    .id(UUID.randomUUID().toString())
                    .title("Missing Authentication on Data-Mutating Endpoint")
                    .description(String.format(
                            "The endpoint %s %s performs data mutation but has no security requirement defined.",
                            method.toUpperCase(), path))
                    .severity(Severity.HIGH)
                    .category(Category.MISSING_AUTH)
                    .endpoint(path)
                    .method(method.toUpperCase())
                    .remediation("Add a security requirement to this operation or globally. Use OAuth2, JWT Bearer, or API Key schemes.")
                    .owaspRef("OWASP API2:2023 - Broken Authentication")
                    .cvssScore(7.5)
                    .aiEnhanced(false)
                    .build());
        }
        return results;
    }

    // -----------------------------------------------------------------------
    // OWASP API3: Excessive Data Exposure
    // -----------------------------------------------------------------------

    private List<Finding> checkExcessiveDataExposure(String path, String method, Operation op) {
        List<Finding> results = new ArrayList<>();

        if (op.getResponses() == null) return results;

        op.getResponses().forEach((code, response) -> {
            if (response.getContent() == null) return;
            response.getContent().forEach((mediaType, content) -> {
                if (content.getSchema() == null) return;
                // Flag responses with no schema constraints (inline object with no properties defined)
                if ("object".equals(content.getSchema().getType())
                        && (content.getSchema().getProperties() == null
                        || content.getSchema().getProperties().isEmpty())) {
                    results.add(Finding.builder()
                            .id(UUID.randomUUID().toString())
                            .title("Unconstrained Response Schema — Potential Excessive Data Exposure")
                            .description(String.format(
                                    "%s %s returns an unconstrained object schema in response %s. " +
                                    "This may expose sensitive fields not intended for the client.",
                                    method.toUpperCase(), path, code))
                            .severity(Severity.MEDIUM)
                            .category(Category.EXCESSIVE_DATA_EXPOSURE)
                            .endpoint(path)
                            .method(method.toUpperCase())
                            .remediation("Define explicit response schemas with only the fields the client needs. " +
                                    "Use field-level filtering or response DTOs.")
                            .owaspRef("OWASP API3:2023 - Broken Object Property Level Authorization")
                            .cvssScore(5.3)
                            .aiEnhanced(false)
                            .build());
                }
            });
        });
        return results;
    }

    // -----------------------------------------------------------------------
    // OWASP API4: Lack of Resources & Rate Limiting
    // -----------------------------------------------------------------------

    private List<Finding> checkMissingRateLimiting(String path, String method, Operation op) {
        List<Finding> results = new ArrayList<>();

        boolean hasRateLimitExtension = op.getExtensions() != null
                && (op.getExtensions().containsKey("x-rate-limit")
                || op.getExtensions().containsKey("x-ratelimit-limit")
                || op.getExtensions().containsKey("x-throttling"));

        if (!hasRateLimitExtension && isHighRiskEndpoint(path)) {
            results.add(Finding.builder()
                    .id(UUID.randomUUID().toString())
                    .title("Missing Rate Limiting on High-Risk Endpoint")
                    .description(String.format(
                            "%s %s appears to be a high-risk endpoint (auth, search, upload) " +
                            "with no rate limiting extensions documented.",
                            method.toUpperCase(), path))
                    .severity(Severity.MEDIUM)
                    .category(Category.RATE_LIMITING)
                    .endpoint(path)
                    .method(method.toUpperCase())
                    .remediation("Implement rate limiting via a gateway (Kong, AWS API GW) or Spring's " +
                            "Bucket4j/Resilience4j. Document limits with x-ratelimit-limit extensions.")
                    .owaspRef("OWASP API4:2023 - Unrestricted Resource Consumption")
                    .cvssScore(5.3)
                    .aiEnhanced(false)
                    .build());
        }
        return results;
    }

    // -----------------------------------------------------------------------
    // OWASP API8: Injection
    // -----------------------------------------------------------------------

    private List<Finding> checkInjectionRisk(String path, String method, Operation op) {
        List<Finding> results = new ArrayList<>();

        if (op.getParameters() == null) return results;

        op.getParameters().forEach(param -> {
            if (param.getSchema() == null) return;
            boolean isStringWithNoPattern = "string".equals(param.getSchema().getType())
                    && param.getSchema().getPattern() == null
                    && param.getSchema().getEnum() == null
                    && param.getSchema().getMaxLength() == null;

            if (isStringWithNoPattern && "query".equals(param.getIn())) {
                results.add(Finding.builder()
                        .id(UUID.randomUUID().toString())
                        .title("Unvalidated String Parameter — Injection Risk")
                        .description(String.format(
                                "Parameter '%s' on %s %s is a string with no pattern, enum, or maxLength constraint. " +
                                "Unvalidated inputs are a common injection vector.",
                                param.getName(), method.toUpperCase(), path))
                        .severity(Severity.MEDIUM)
                        .category(Category.INJECTION)
                        .endpoint(path)
                        .method(method.toUpperCase())
                        .remediation("Add pattern, enum, or maxLength constraints to string parameters. " +
                                "Use Bean Validation (@Pattern, @Size) on controller method arguments.")
                        .owaspRef("OWASP API8:2023 - Security Misconfiguration / Injection")
                        .cvssScore(6.1)
                        .aiEnhanced(false)
                        .build());
            }
        });
        return results;
    }

    // -----------------------------------------------------------------------
    // OWASP API6: Mass Assignment
    // -----------------------------------------------------------------------

    private List<Finding> checkMassAssignment(String path, String method, Operation op) {
        List<Finding> results = new ArrayList<>();

        if (op.getRequestBody() == null || op.getRequestBody().getContent() == null) return results;

        op.getRequestBody().getContent().forEach((mediaType, content) -> {
            if (content.getSchema() == null) return;
            boolean noReadOnlyFields = content.getSchema().getProperties() == null
                    || content.getSchema().getProperties().values().stream()
                        .noneMatch(s -> s instanceof Schema && Boolean.TRUE.equals(((Schema<?>) s).getReadOnly()));

            if (noReadOnlyFields && isDataMutationMethod(method)) {
                results.add(Finding.builder()
                        .id(UUID.randomUUID().toString())
                        .title("Potential Mass Assignment — No readOnly Fields Defined")
                        .description(String.format(
                                "The request body for %s %s has no readOnly fields. " +
                                "Without explicit constraints, clients may be able to set privileged fields (e.g., role, isAdmin).",
                                method.toUpperCase(), path))
                        .severity(Severity.MEDIUM)
                        .category(Category.MASS_ASSIGNMENT)
                        .endpoint(path)
                        .method(method.toUpperCase())
                        .remediation("Mark sensitive fields (id, role, createdAt, isAdmin) as readOnly: true in the schema. " +
                                "Use separate request/response DTOs and never bind directly to domain entities.")
                        .owaspRef("OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows")
                        .cvssScore(6.5)
                        .aiEnhanced(false)
                        .build());
            }
        });
        return results;
    }

    // -----------------------------------------------------------------------
    // Sensitive Data in Path
    // -----------------------------------------------------------------------

    private List<Finding> checkSensitiveDataInPath(String path, String method, Operation op) {
        List<Finding> results = new ArrayList<>();
        List<String> sensitiveKeywords = List.of("password", "token", "secret", "key", "ssn", "credit");

        for (String keyword : sensitiveKeywords) {
            if (path.toLowerCase().contains(keyword)) {
                results.add(Finding.builder()
                        .id(UUID.randomUUID().toString())
                        .title("Sensitive Data in URL Path")
                        .description(String.format(
                                "The path '%s' contains the keyword '%s'. Sensitive data in URLs is logged by " +
                                "proxies, browsers, and servers, leading to unintentional exposure.",
                                path, keyword))
                        .severity(Severity.HIGH)
                        .category(Category.SECURITY_MISCONFIGURATION)
                        .endpoint(path)
                        .method(method.toUpperCase())
                        .remediation("Move sensitive data to request headers or the request body. Never include passwords, " +
                                "tokens, or secrets in URL paths or query strings.")
                        .owaspRef("OWASP API7:2023 - Server Side Request Forgery")
                        .cvssScore(7.2)
                        .aiEnhanced(false)
                        .build());
                break;
            }
        }
        return results;
    }

    // -----------------------------------------------------------------------
    // Global checks
    // -----------------------------------------------------------------------

    private List<Finding> checkMissingHttps(OpenAPI spec) {
        List<Finding> results = new ArrayList<>();
        if (spec.getServers() == null) return results;

        spec.getServers().forEach(server -> {
            if (server.getUrl() != null && server.getUrl().startsWith("http://")) {
                results.add(Finding.builder()
                        .id(UUID.randomUUID().toString())
                        .title("API Server Uses HTTP Instead of HTTPS")
                        .description("The server URL '" + server.getUrl() + "' uses plain HTTP. " +
                                "All API traffic should be encrypted in transit.")
                        .severity(Severity.CRITICAL)
                        .category(Category.MISSING_ENCRYPTION)
                        .endpoint(server.getUrl())
                        .method("ALL")
                        .remediation("Configure TLS on your server and update the spec to use https://. " +
                                "Use HSTS headers to enforce HTTPS.")
                        .owaspRef("OWASP API2:2023 - Broken Authentication")
                        .cvssScore(9.1)
                        .aiEnhanced(false)
                        .build());
            }
        });
        return results;
    }

    private List<Finding> checkWeakSecuritySchemes(OpenAPI spec) {
        List<Finding> results = new ArrayList<>();
        if (spec.getComponents() == null || spec.getComponents().getSecuritySchemes() == null) return results;

        spec.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
            if (SecurityScheme.Type.HTTP.equals(scheme.getType())
                    && "basic".equalsIgnoreCase(scheme.getScheme())) {
                results.add(Finding.builder()
                        .id(UUID.randomUUID().toString())
                        .title("HTTP Basic Authentication Scheme Detected")
                        .description("Security scheme '" + name + "' uses HTTP Basic authentication. " +
                                "Basic auth transmits credentials as Base64-encoded plaintext and is easily compromised.")
                        .severity(Severity.HIGH)
                        .category(Category.BROKEN_AUTHENTICATION)
                        .endpoint("components/securitySchemes/" + name)
                        .method("N/A")
                        .remediation("Replace HTTP Basic auth with OAuth 2.0 + JWT Bearer tokens or API keys " +
                                "with proper rotation policies.")
                        .owaspRef("OWASP API2:2023 - Broken Authentication")
                        .cvssScore(7.5)
                        .aiEnhanced(false)
                        .build());
            }
        });
        return results;
    }

    private List<Finding> checkMissingGlobalSecurity(OpenAPI spec) {
        List<Finding> results = new ArrayList<>();
        boolean hasGlobalSecurity = spec.getSecurity() != null && !spec.getSecurity().isEmpty();
        boolean hasSecuritySchemes = spec.getComponents() != null
                && spec.getComponents().getSecuritySchemes() != null
                && !spec.getComponents().getSecuritySchemes().isEmpty();

        if (!hasGlobalSecurity && !hasSecuritySchemes) {
            results.add(Finding.builder()
                    .id(UUID.randomUUID().toString())
                    .title("No Security Schemes Defined in Spec")
                    .description("The OpenAPI spec defines no security schemes and no global security requirements. " +
                            "This suggests the API may be entirely unauthenticated.")
                    .severity(Severity.CRITICAL)
                    .category(Category.MISSING_AUTH)
                    .endpoint("global")
                    .method("ALL")
                    .remediation("Define at least one security scheme (OAuth2, JWT Bearer, API Key) and apply it " +
                            "globally or per-operation.")
                    .owaspRef("OWASP API2:2023 - Broken Authentication")
                    .cvssScore(9.8)
                    .aiEnhanced(false)
                    .build());
        }
        return results;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private Map<String, Operation> getAllOperations(PathItem pathItem) {
        Map<String, Operation> ops = new LinkedHashMap<>();
        if (pathItem.getGet() != null)    ops.put("get",    pathItem.getGet());
        if (pathItem.getPost() != null)   ops.put("post",   pathItem.getPost());
        if (pathItem.getPut() != null)    ops.put("put",    pathItem.getPut());
        if (pathItem.getPatch() != null)  ops.put("patch",  pathItem.getPatch());
        if (pathItem.getDelete() != null) ops.put("delete", pathItem.getDelete());
        return ops;
    }

    private boolean isDataMutationMethod(String method) {
        return List.of("post", "put", "patch", "delete").contains(method.toLowerCase());
    }

    private boolean isHighRiskEndpoint(String path) {
        List<String> highRiskKeywords = List.of(
                "login", "auth", "token", "register", "signup", "search", "upload", "import", "export"
        );
        return highRiskKeywords.stream().anyMatch(k -> path.toLowerCase().contains(k));
    }
}
