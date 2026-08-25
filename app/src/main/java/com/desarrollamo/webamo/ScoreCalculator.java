package com.desarrollamo.webamo;

import java.util.List;

public final class ScoreCalculator {
    public static final String SECURITY = "Seguridad";
    public static final String SEO = "SEO";
    public static final String PERFORMANCE = "Rendimiento";
    public static final String PRIVACY = "Privacidad";
    public static final String ACCESSIBILITY = "Accesibilidad";
    public static final String TECHNICAL = "Técnico";

    private static final String[] SCORED = {
            SECURITY, SEO, PERFORMANCE, PRIVACY, ACCESSIBILITY
    };

    private ScoreCalculator() {}

    public static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    public static int scoreCategory(List<AuditCheck> checks, String category) {
        double earned = 0;
        int knownWeight = 0;
        for (AuditCheck c : checks) {
            if (!category.equals(c.category) || c.weight <= 0 || !c.isKnown()) continue;
            knownWeight += c.weight;
            earned += c.weight * c.earnedFactor();
        }
        return knownWeight == 0 ? 0 : clamp((int) Math.round(earned * 100.0 / knownWeight));
    }

    public static int coverageCategory(List<AuditCheck> checks, String category) {
        int total = 0;
        int known = 0;
        for (AuditCheck c : checks) {
            if (!category.equals(c.category) || c.weight <= 0) continue;
            total += c.weight;
            if (c.isKnown()) known += c.weight;
        }
        return total == 0 ? 100 : clamp((int) Math.round(known * 100.0 / total));
    }

    public static void finalizeReport(AuditReport report) {
        report.categoryScores.clear();
        report.categoryCoverage.clear();
        for (String category : SCORED) {
            report.categoryScores.put(category, scoreCategory(report.checks, category));
            report.categoryCoverage.put(category, coverageCategory(report.checks, category));
        }

        double weighted =
                report.categoryScores.get(SECURITY) * 0.30 +
                report.categoryScores.get(SEO) * 0.25 +
                report.categoryScores.get(PERFORMANCE) * 0.20 +
                report.categoryScores.get(PRIVACY) * 0.10 +
                report.categoryScores.get(ACCESSIBILITY) * 0.15;
        report.overallScore = clamp((int) Math.round(weighted));

        int weightedKnown = 0;
        int weightedTotal = 0;
        for (AuditCheck c : report.checks) {
            if (c.weight <= 0 || !isScoredCategory(c.category)) continue;
            weightedTotal += c.weight;
            if (c.isKnown()) weightedKnown += c.weight;
        }
        report.overallCoverage = weightedTotal == 0 ? 100 :
                clamp((int) Math.round(weightedKnown * 100.0 / weightedTotal));

        if (report.statusCode == 0 || report.statusCode >= 500) report.overallScore = Math.min(report.overallScore, 35);
        else if (report.statusCode >= 400) report.overallScore = Math.min(report.overallScore, 50);

        report.grade = grade(report.overallScore);

        report.criticalCount = report.highCount = report.mediumCount = report.lowCount = 0;
        for (AuditCheck c : report.checks) {
            if (!c.isProblem()) continue;
            switch (c.severity) {
                case "CRÍTICA": report.criticalCount++; break;
                case "ALTA": report.highCount++; break;
                case "MEDIA": report.mediumCount++; break;
                case "BAJA": report.lowCount++; break;
            }
        }

        int security = report.categoryScores.getOrDefault(SECURITY, 0);
        if (report.criticalCount > 0 || security < 45) report.risk = "ALTO";
        else if (security < 70 || report.highCount > 0) report.risk = "MEDIO";
        else report.risk = "BAJO";
    }

    public static String grade(int score) {
        if (score >= 90) return "EXCELENTE";
        if (score >= 80) return "MUY BIEN";
        if (score >= 70) return "BIEN";
        if (score >= 55) return "MEJORABLE";
        if (score >= 40) return "FLOJA";
        return "CRÍTICA";
    }

    private static boolean isScoredCategory(String category) {
        for (String value : SCORED) if (value.equals(category)) return true;
        return false;
    }
}
