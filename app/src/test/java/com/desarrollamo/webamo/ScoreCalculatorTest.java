package com.desarrollamo.webamo;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public final class ScoreCalculatorTest {
    @Test
    public void categoryScoreUsesWeightsAndWarnAsHalf() {
        List<AuditCheck> checks = new ArrayList<>();
        checks.add(AuditCheck.of("a", ScoreCalculator.SECURITY, "A", AuditCheck.PASS, "", 4, ""));
        checks.add(AuditCheck.of("b", ScoreCalculator.SECURITY, "B", AuditCheck.WARN, "", 4, ""));
        checks.add(AuditCheck.of("c", ScoreCalculator.SECURITY, "C", AuditCheck.FAIL, "", 2, ""));
        assertEquals(60, ScoreCalculator.scoreCategory(checks, ScoreCalculator.SECURITY));
    }

    @Test
    public void unknownReducesCoverageButDoesNotPretendToBeFailure() {
        List<AuditCheck> checks = new ArrayList<>();
        checks.add(AuditCheck.of("a", ScoreCalculator.PERFORMANCE, "A", AuditCheck.PASS, "", 4, ""));
        checks.add(AuditCheck.of("b", ScoreCalculator.PERFORMANCE, "B", AuditCheck.UNKNOWN, "", 4, ""));
        assertEquals(100, ScoreCalculator.scoreCategory(checks, ScoreCalculator.PERFORMANCE));
        assertEquals(50, ScoreCalculator.coverageCategory(checks, ScoreCalculator.PERFORMANCE));
    }

    @Test
    public void finalizeReportCreatesRiskAndGrade() {
        AuditReport report = new AuditReport();
        report.statusCode = 200;
        for (String cat : new String[]{
                ScoreCalculator.SECURITY, ScoreCalculator.SEO, ScoreCalculator.PERFORMANCE,
                ScoreCalculator.PRIVACY, ScoreCalculator.ACCESSIBILITY
        }) {
            report.checks.add(AuditCheck.of(cat, cat, "ok", AuditCheck.PASS, "", 5, ""));
        }
        ScoreCalculator.finalizeReport(report);
        assertEquals(100, report.overallScore);
        assertEquals("EXCELENTE", report.grade);
        assertEquals("BAJO", report.risk);
        assertEquals(100, report.overallCoverage);
    }

    @Test
    public void httpFailureCapsOverall() {
        AuditReport report = new AuditReport();
        report.statusCode = 503;
        for (String cat : new String[]{
                ScoreCalculator.SECURITY, ScoreCalculator.SEO, ScoreCalculator.PERFORMANCE,
                ScoreCalculator.PRIVACY, ScoreCalculator.ACCESSIBILITY
        }) {
            report.checks.add(AuditCheck.of(cat, cat, "ok", AuditCheck.PASS, "", 5, ""));
        }
        ScoreCalculator.finalizeReport(report);
        assertTrue(report.overallScore <= 35);
    }
}
