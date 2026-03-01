package com.rawqubit.apiscanner.controller;

import com.rawqubit.apiscanner.model.ScanReport;
import com.rawqubit.apiscanner.model.ScanRequest;
import com.rawqubit.apiscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;

    /**
     * Scan an OpenAPI spec for security vulnerabilities.
     *
     * POST /api/v1/scan
     * Body: { "specUrl": "https://...", "aiAnalysis": true, "minSeverity": "low" }
     *   OR: { "specContent": "<raw yaml/json>", "aiAnalysis": true }
     */
    @PostMapping
    public ResponseEntity<ScanReport> scan(@RequestBody ScanRequest request) {
        log.info("Scan request received: specUrl={}, aiAnalysis={}",
                request.getSpecUrl(), request.isAiAnalysis());
        ScanReport report = scanService.scan(request);
        return ResponseEntity.ok(report);
    }

    /**
     * Quick scan by URL — GET /api/v1/scan?url=https://...
     */
    @GetMapping
    public ResponseEntity<ScanReport> scanByUrl(
            @RequestParam String url,
            @RequestParam(defaultValue = "true") boolean aiAnalysis,
            @RequestParam(defaultValue = "low") String minSeverity) {

        ScanRequest request = new ScanRequest();
        request.setSpecUrl(url);
        request.setAiAnalysis(aiAnalysis);
        request.setMinSeverity(minSeverity);
        return ResponseEntity.ok(scanService.scan(request));
    }
}
