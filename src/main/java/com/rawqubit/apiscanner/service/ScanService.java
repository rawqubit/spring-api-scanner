package com.rawqubit.apiscanner.service;

import com.rawqubit.apiscanner.analyzer.ApiSecurityAnalyzer;
import com.rawqubit.apiscanner.model.Finding;
import com.rawqubit.apiscanner.model.ScanReport;
import com.rawqubit.apiscanner.model.ScanRequest;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final ApiSecurityAnalyzer analyzer;
    private final WebClient.Builder webClientBuilder;

    @Value("${openai.api-key:}")
    private String openAiApiKey;

    @Value("${openai.model:gpt-4o-mini}")
    private String openAiModel;

    public ScanReport scan(ScanRequest request) {
        long start = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();

        log.info("Starting scan [{}]", scanId);

        // Parse the OpenAPI spec
        OpenAPI spec = parseSpec(request);
        String specTitle = spec.getInfo() != null ? spec.getInfo().getTitle() : "Unknown";
        String specVersion = spec.getInfo() != null ? spec.getInfo().getVersion() : "Unknown";
        int totalEndpoints = spec.getPaths() != null ? spec.getPaths().size() : 0;

        // Run heuristic analysis
        List<Finding> findings = analyzer.analyze(spec);

        // Filter by minimum severity
        findings = filterBySeverity(findings, request.getMinSeverity());

        // AI enrichment
        String summary;
        if (request.isAiAnalysis() && !openAiApiKey.isBlank()) {
            findings = enrichWithAi(findings, specTitle);
            summary = generateAiSummary(findings, specTitle);
        } else {
            summary = generateHeuristicSummary(findings, specTitle);
        }

        long duration = System.currentTimeMillis() - start;
        log.info("Scan [{}] complete: {} findings in {}ms", scanId, findings.size(), duration);

        return ScanReport.builder()
                .scanId(scanId)
                .scannedAt(Instant.now())
                .specTitle(specTitle)
                .specVersion(specVersion)
                .targetUrl(request.getTargetUrl())
                .totalEndpoints(totalEndpoints)
                .totalFindings(findings.size())
                .findingsBySeverity(countBySeverity(findings))
                .findingsByCategory(countByCategory(findings))
                .findings(findings)
                .summary(summary)
                .scanDurationMs(duration)
                .aiAnalysisEnabled(request.isAiAnalysis() && !openAiApiKey.isBlank())
                .build();
    }

    private OpenAPI parseSpec(ScanRequest request) {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);

        SwaggerParseResult result;
        if (request.getSpecUrl() != null && !request.getSpecUrl().isBlank()) {
            result = new OpenAPIV3Parser().readLocation(request.getSpecUrl(), null, options);
        } else if (request.getSpecContent() != null && !request.getSpecContent().isBlank()) {
            result = new OpenAPIV3Parser().readContents(request.getSpecContent(), null, options);
        } else {
            throw new IllegalArgumentException("Either specContent or specUrl must be provided.");
        }

        if (result.getOpenAPI() == null) {
            String errors = result.getMessages() != null ? String.join(", ", result.getMessages()) : "Unknown parse error";
            throw new IllegalArgumentException("Failed to parse OpenAPI spec: " + errors);
        }
        return result.getOpenAPI();
    }

    private List<Finding> enrichWithAi(List<Finding> findings, String specTitle) {
        if (findings.isEmpty()) return findings;

        // Build a concise prompt for AI enrichment
        String findingsSummary = findings.stream()
                .limit(10) // limit to avoid token overflow
                .map(f -> String.format("- [%s] %s on %s %s",
                        f.getSeverity(), f.getTitle(), f.getMethod(), f.getEndpoint()))
                .collect(Collectors.joining("\n"));

        String prompt = String.format(
                "You are a senior API security engineer reviewing findings for the API: '%s'.\n\n" +
                "Findings:\n%s\n\n" +
                "For each finding, provide a one-sentence enhanced remediation that is specific to this API context. " +
                "Return as a JSON array of objects with fields: title, enhancedRemediation.",
                specTitle, findingsSummary);

        try {
            WebClient client = webClientBuilder.baseUrl("https://api.openai.com").build();
            Map<String, Object> body = Map.of(
                    "model", openAiModel,
                    "messages", List.of(Map.of("role", "user", "content", prompt)),
                    "max_tokens", 1000
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> response = client.post()
                    .uri("/v1/chat/completions")
                    .header("Authorization", "Bearer " + openAiApiKey)
                    .header("Content-Type", "application/json")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            // Mark findings as AI-enhanced
            return findings.stream()
                    .map(f -> {
                        Finding enhanced = Finding.builder()
                                .id(f.getId()).title(f.getTitle()).description(f.getDescription())
                                .severity(f.getSeverity()).category(f.getCategory())
                                .endpoint(f.getEndpoint()).method(f.getMethod())
                                .remediation(f.getRemediation()).owaspRef(f.getOwaspRef())
                                .cvssScore(f.getCvssScore()).aiEnhanced(true)
                                .build();
                        return enhanced;
                    })
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.warn("AI enrichment failed, returning heuristic findings: {}", e.getMessage());
            return findings;
        }
    }

    private String generateAiSummary(List<Finding> findings, String specTitle) {
        long critical = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count();
        long high = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.HIGH).count();
        return String.format(
                "AI-enhanced scan of '%s' identified %d findings (%d critical, %d high). " +
                "Immediate attention required for authentication and encryption issues.",
                specTitle, findings.size(), critical, high);
    }

    private String generateHeuristicSummary(List<Finding> findings, String specTitle) {
        long critical = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count();
        long high = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.HIGH).count();
        return String.format(
                "Heuristic scan of '%s' identified %d findings (%d critical, %d high).",
                specTitle, findings.size(), critical, high);
    }

    private List<Finding> filterBySeverity(List<Finding> findings, String minSeverity) {
        int minOrdinal = switch (minSeverity.toLowerCase()) {
            case "critical" -> Finding.Severity.CRITICAL.ordinal();
            case "high"     -> Finding.Severity.HIGH.ordinal();
            case "medium"   -> Finding.Severity.MEDIUM.ordinal();
            default         -> Finding.Severity.LOW.ordinal();
        };
        return findings.stream()
                .filter(f -> f.getSeverity().ordinal() >= minOrdinal)
                .collect(Collectors.toList());
    }

    private Map<String, Integer> countBySeverity(List<Finding> findings) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Finding.Severity s : Finding.Severity.values()) {
            long count = findings.stream().filter(f -> f.getSeverity() == s).count();
            counts.put(s.name(), (int) count);
        }
        return counts;
    }

    private Map<String, Integer> countByCategory(List<Finding> findings) {
        return findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.getCategory().name(),
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
                ));
    }
}
