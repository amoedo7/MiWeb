package com.desarrollamo.webamo;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ScoreCalculatorTest {
    @Test
    public void perfectScoresStayPerfect() {
        assertEquals(100, ScoreCalculator.overall(100, 100, 100, 100, 100));
    }

    @Test
    public void overallUsesDocumentedWeights() {
        assertEquals(80, ScoreCalculator.overall(100, 100, 0, 100, 100));
    }

    @Test
    public void performanceRewardsFastSmallHtml() {
        assertEquals(100, ScoreCalculator.performance(300, 100_000));
    }

    @Test
    public void valuesAreClamped() {
        assertEquals(0, ScoreCalculator.clamp(-5));
        assertEquals(100, ScoreCalculator.clamp(130));
    }
}
