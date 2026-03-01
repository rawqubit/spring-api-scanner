# spring-api-scanner

**AI-powered REST API security scanner for OpenAPI specs.**

[![Java](https://img.shields.io/badge/Java-21-ED8B00?style=flat-square&logo=openjdk)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-6DB33F?style=flat-square&logo=spring)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red?style=flat-square)](https://owasp.org/API-Security/)

`spring-api-scanner` analyzes OpenAPI 3.x / Swagger 2.x specifications for OWASP API Top 10 vulnerabilities. It combines heuristic rule-based analysis with optional GPT-4o-mini enrichment to produce actionable security reports — all via a simple REST API.

---

## Features

- **OWASP API Top 10 Coverage** — Checks for broken auth, excessive data exposure, missing rate limiting, injection risks, mass assignment, weak security schemes, and more.
- **OpenAPI 3.x + Swagger 2.x** — Parse from a URL or raw YAML/JSON content.
- **AI-Enhanced Remediation** — Optional GPT-4o-mini enrichment provides context-aware, API-specific remediation advice.
- **Severity Filtering** — Filter findings by `low`, `medium`, `high`, or `critical`.
- **Rich JSON Reports** — Findings include CVSS scores, OWASP references, endpoint details, and remediation steps.
- **Spring Boot Actuator** — Built-in `/actuator/health` and `/actuator/metrics` endpoints.

---

## Quick Start

```bash
git clone https://github.com/rawqubit/spring-api-scanner
cd spring-api-scanner

# Optional: set your OpenAI key for AI-enhanced analysis
export OPENAI_API_KEY=sk-...

mvn spring-boot:run
```

### Scan a public OpenAPI spec

```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "specUrl": "https://petstore3.swagger.io/api/v3/openapi.json",
    "aiAnalysis": false,
    "minSeverity": "medium"
  }'
```

### Scan by URL (GET shorthand)

```bash
curl "http://localhost:8080/api/v1/scan?url=https://petstore3.swagger.io/api/v3/openapi.json&minSeverity=high"
```

---

## API Reference

### `POST /api/v1/scan`

| Field | Type | Description |
|-------|------|-------------|
| `specUrl` | `string` | URL to a public OpenAPI spec |
| `specContent` | `string` | Raw YAML or JSON spec content |
| `targetUrl` | `string` | Optional base URL of the live API |
| `aiAnalysis` | `boolean` | Enable GPT-4o-mini enrichment (default: `true`) |
| `minSeverity` | `string` | Minimum severity: `low`, `medium`, `high`, `critical` |

### Response: `ScanReport`

```json
{
  "scanId": "a1b2c3...",
  "scannedAt": "2025-01-15T10:30:00Z",
  "specTitle": "Petstore API",
  "totalEndpoints": 12,
  "totalFindings": 7,
  "findingsBySeverity": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 4, "LOW": 0 },
  "findings": [
    {
      "title": "No Security Schemes Defined in Spec",
      "severity": "CRITICAL",
      "category": "MISSING_AUTH",
      "endpoint": "global",
      "cvssScore": 9.8,
      "owaspRef": "OWASP API2:2023 - Broken Authentication",
      "remediation": "Define at least one security scheme...",
      "aiEnhanced": true
    }
  ],
  "summary": "AI-enhanced scan identified 7 findings (1 critical, 2 high).",
  "scanDurationMs": 342
}
```

---

## OWASP API Top 10 Coverage

| Check | OWASP Category | Severity |
|-------|---------------|----------|
| Missing authentication on mutation endpoints | API2 Broken Authentication | HIGH |
| No security schemes defined | API2 Broken Authentication | CRITICAL |
| HTTP Basic auth scheme | API2 Broken Authentication | HIGH |
| Unconstrained response schema | API3 Excessive Data Exposure | MEDIUM |
| Missing rate limiting on high-risk endpoints | API4 Rate Limiting | MEDIUM |
| Unvalidated string parameters | API8 Injection | MEDIUM |
| No readOnly fields on request body | API6 Mass Assignment | MEDIUM |
| Sensitive data in URL path | API7 Security Misconfiguration | HIGH |
| HTTP server URL (no TLS) | API2 Broken Authentication | CRITICAL |

---

## Configuration

```yaml
# application.yml
openai:
  api-key: ${OPENAI_API_KEY:}   # Optional — enables AI enrichment
  model: gpt-4o-mini
```

---

## Running Tests

```bash
mvn test
```

---

## License

MIT — see [LICENSE](LICENSE).
