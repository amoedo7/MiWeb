package com.desarrollamo.webamo;

import org.json.JSONException;
import org.json.JSONObject;

public final class AuditCheck {
    public static final String PASS = "pass";
    public static final String WARN = "warn";
    public static final String FAIL = "fail";
    public static final String INFO = "info";
    public static final String UNKNOWN = "unknown";

    public final String id;
    public final String category;
    public final String label;
    public final String status;
    public final String detail;
    public final int weight;
    public final String recommendation;
    public final String severity;
    public final String confidence;

    public AuditCheck(
            String id,
            String category,
            String label,
            String status,
            String detail,
            int weight,
            String recommendation,
            String severity,
            String confidence
    ) {
        this.id = id;
        this.category = category;
        this.label = label;
        this.status = status;
        this.detail = detail == null ? "" : detail;
        this.weight = Math.max(0, weight);
        this.recommendation = recommendation == null ? "" : recommendation;
        this.severity = severity == null || severity.isBlank() ? inferSeverity(status, weight) : severity;
        this.confidence = confidence == null || confidence.isBlank() ? "ALTA" : confidence;
    }

    public static AuditCheck of(String id, String category, String label, String status,
                                String detail, int weight, String recommendation) {
        return new AuditCheck(id, category, label, status, detail, weight, recommendation, "", "ALTA");
    }

    public static AuditCheck info(String id, String category, String label, String detail) {
        return new AuditCheck(id, category, label, INFO, detail, 0, "", "INFO", "ALTA");
    }

    public boolean isKnown() {
        return !UNKNOWN.equals(status);
    }

    public boolean isProblem() {
        return FAIL.equals(status) || WARN.equals(status);
    }

    public double earnedFactor() {
        if (PASS.equals(status) || INFO.equals(status)) return 1.0;
        if (WARN.equals(status)) return 0.5;
        return 0.0;
    }

    public int severityRank() {
        if ("CRÍTICA".equals(severity)) return 4;
        if ("ALTA".equals(severity)) return 3;
        if ("MEDIA".equals(severity)) return 2;
        if ("BAJA".equals(severity)) return 1;
        return 0;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("category", category);
        o.put("label", label);
        o.put("status", status);
        o.put("detail", detail);
        o.put("weight", weight);
        o.put("recommendation", recommendation);
        o.put("severity", severity);
        o.put("confidence", confidence);
        return o;
    }

    private static String inferSeverity(String status, int weight) {
        if (FAIL.equals(status)) return weight >= 5 ? "CRÍTICA" : weight >= 4 ? "ALTA" : "MEDIA";
        if (WARN.equals(status)) return weight >= 3 ? "MEDIA" : "BAJA";
        if (PASS.equals(status)) return "FORTALEZA";
        if (UNKNOWN.equals(status)) return "N/V";
        return "INFO";
    }
}
