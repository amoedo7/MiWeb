package com.desarrollamo.webamo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AuditReport {
    public String target = "";
    public String finalUrl = "";
    public int statusCode;
    public long elapsedMs;
    public int bodyBytes;
    public String contentType = "";
    public String platform = "No identificado";
    public String stack = "No identificado";
    public String renderMode = "No identificado";
    public String cdn = "No identificado";
    public String server = "";
    public String tlsVersion = "";
    public int tlsDaysLeft = Integer.MIN_VALUE;
    public int crawlPages;
    public int assetsDetected;
    public long sampledAssetBytes;
    public int thirdPartyHostCount;

    public int overallScore;
    public int overallCoverage;
    public String grade = "";
    public String risk = "";
    public int criticalCount;
    public int highCount;
    public int mediumCount;
    public int lowCount;

    public Integer previousScore;
    public Integer scoreDelta;
    public int regressions;
    public int resolved;

    public final LinkedHashMap<String, Integer> categoryScores = new LinkedHashMap<>();
    public final LinkedHashMap<String, Integer> categoryCoverage = new LinkedHashMap<>();
    public final List<AuditCheck> checks = new ArrayList<>();
    public final List<String> trackers = new ArrayList<>();
    public final List<String> cookies = new ArrayList<>();
    public final List<String> thirdPartyHosts = new ArrayList<>();
    public final List<String> notes = new ArrayList<>();

    public List<AuditCheck> problems() {
        List<AuditCheck> out = new ArrayList<>();
        for (AuditCheck check : checks) if (check.isProblem()) out.add(check);
        out.sort((a, b) -> {
            int severity = Integer.compare(b.severityRank(), a.severityRank());
            return severity != 0 ? severity : Integer.compare(b.weight, a.weight);
        });
        return out;
    }

    public List<AuditCheck> strengths() {
        List<AuditCheck> out = new ArrayList<>();
        for (AuditCheck check : checks) {
            if (AuditCheck.PASS.equals(check.status) && check.weight >= 2) out.add(check);
        }
        out.sort((a, b) -> Integer.compare(b.weight, a.weight));
        return out;
    }

    public int knownScoredChecks() {
        int n = 0;
        for (AuditCheck c : checks) if (c.weight > 0 && c.isKnown()) n++;
        return n;
    }

    public int scoredChecks() {
        int n = 0;
        for (AuditCheck c : checks) if (c.weight > 0) n++;
        return n;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("schema", "desarrollamo.webamo.v2");
        root.put("version", "0.1.1");
        root.put("target", target);
        root.put("final_url", finalUrl);
        root.put("status", statusCode);
        root.put("elapsed_ms", elapsedMs);
        root.put("body_bytes", bodyBytes);
        root.put("content_type", contentType);

        JSONObject fingerprint = new JSONObject();
        fingerprint.put("platform", platform);
        fingerprint.put("stack", stack);
        fingerprint.put("render", renderMode);
        fingerprint.put("cdn", cdn);
        fingerprint.put("server", server);
        fingerprint.put("tls_version", tlsVersion);
        fingerprint.put("tls_days_left", tlsDaysLeft == Integer.MIN_VALUE ? JSONObject.NULL : tlsDaysLeft);
        root.put("fingerprint", fingerprint);

        JSONObject scope = new JSONObject();
        scope.put("crawl_pages", crawlPages);
        scope.put("assets_detected", assetsDetected);
        scope.put("sampled_asset_bytes", sampledAssetBytes);
        scope.put("third_party_hosts", thirdPartyHostCount);
        scope.put("scored_checks", scoredChecks());
        scope.put("known_scored_checks", knownScoredChecks());
        scope.put("coverage", overallCoverage);
        root.put("scope", scope);

        JSONObject scores = new JSONObject();
        scores.put("overall", overallScore);
        scores.put("grade", grade);
        scores.put("risk", risk);
        JSONObject areas = new JSONObject();
        for (Map.Entry<String, Integer> e : categoryScores.entrySet()) {
            JSONObject row = new JSONObject();
            row.put("score", e.getValue());
            row.put("coverage", categoryCoverage.getOrDefault(e.getKey(), 100));
            areas.put(e.getKey().toLowerCase(), row);
        }
        scores.put("areas", areas);
        root.put("scores", scores);

        JSONObject severity = new JSONObject();
        severity.put("critical", criticalCount);
        severity.put("high", highCount);
        severity.put("medium", mediumCount);
        severity.put("low", lowCount);
        root.put("severity", severity);

        JSONArray rows = new JSONArray();
        for (AuditCheck check : checks) rows.put(check.toJson());
        root.put("checks", rows);
        root.put("trackers", new JSONArray(trackers));
        root.put("cookies", new JSONArray(cookies));
        root.put("third_party_hosts", new JSONArray(thirdPartyHosts));
        root.put("notes", new JSONArray(notes));

        JSONObject history = new JSONObject();
        history.put("previous_score", previousScore == null ? JSONObject.NULL : previousScore);
        history.put("delta", scoreDelta == null ? JSONObject.NULL : scoreDelta);
        history.put("regressions", regressions);
        history.put("resolved", resolved);
        root.put("history", history);

        root.put("note", "Auditoría pública, defensiva y no destructiva. Los controles no verificables se muestran como N/V; no es pentest, Lighthouse ni dictamen legal.");
        return root;
    }

    public String shareText() {
        StringBuilder out = new StringBuilder();
        out.append("WebAMO 0.1.1 · ").append(target).append('\n');
        out.append("Puntaje general: ").append(overallScore).append("/100 · ").append(grade)
                .append(" · Riesgo ").append(risk).append('\n');
        out.append("Cobertura: ").append(overallCoverage).append("% · ")
                .append(knownScoredChecks()).append('/').append(scoredChecks()).append(" controles puntuables\n\n");

        for (Map.Entry<String, Integer> e : categoryScores.entrySet()) {
            out.append(e.getKey()).append(' ').append(e.getValue()).append("/100")
                    .append(" (cob ").append(categoryCoverage.getOrDefault(e.getKey(), 100)).append("%) · ");
        }
        if (!categoryScores.isEmpty()) out.setLength(Math.max(0, out.length() - 3));
        out.append("\n\nPrioridades:\n");

        List<AuditCheck> problems = problems();
        if (problems.isEmpty()) {
            out.append("• No se detectaron problemas puntuables en la parte verificable.\n");
        } else {
            int max = Math.min(8, problems.size());
            for (int i = 0; i < max; i++) {
                AuditCheck c = problems.get(i);
                out.append("• [").append(c.severity).append("] ").append(c.label).append(": ").append(c.detail);
                if (!c.recommendation.isBlank()) out.append(" → ").append(c.recommendation);
                out.append('\n');
            }
        }

        out.append("\nAlcance: ").append(crawlPages).append(" pág. crawl · ")
                .append(assetsDetected).append(" assets · ")
                .append(thirdPartyHostCount).append(" hosts terceros.");
        if (previousScore != null) {
            out.append("\nHistorial: ").append(previousScore).append(" → ").append(overallScore)
                    .append(" (").append(scoreDelta >= 0 ? "+" : "").append(scoreDelta).append(")");
        }
        out.append("\n\nAuditoría no intrusiva realizada desde el dispositivo.");
        return out.toString();
    }
}
