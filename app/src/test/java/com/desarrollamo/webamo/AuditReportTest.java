package com.desarrollamo.webamo;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class AuditReportTest {
    @Test
    public void shareTextUsesCurrentVersionAndReadableSummary() {
        AuditReport report = new AuditReport();
        report.target = "https://example.com";
        report.overallScore = 85;
        report.grade = "MUY BIEN";
        report.risk = "ALTO";
        report.overallCoverage = 96;
        report.categoryScores.put(ScoreCalculator.SECURITY, 68);
        report.categoryCoverage.put(ScoreCalculator.SECURITY, 100);

        String text = report.shareText();

        assertTrue(text.startsWith("WebAMO 0.1.2 · https://example.com"));
        assertTrue(text.contains("Puntaje general: 85/100 · MUY BIEN · Riesgo ALTO"));
        assertTrue(text.contains("Auditoría no intrusiva realizada desde el dispositivo."));
    }
}
