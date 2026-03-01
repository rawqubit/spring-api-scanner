package com.rawqubit.apiscanner.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ScanReport {

    private String scanId;
    private Instant scannedAt;
    private String specTitle;
    private String specVersion;
    private String targetUrl;
    private int totalEndpoints;
    private int totalFindings;
    private Map<String, Integer> findingsBySeverity;
    private Map<String, Integer> findingsByCategory;
    private List<Finding> findings;
    private String summary;
    private long scanDurationMs;
    private boolean aiAnalysisEnabled;
}
