package com.desarrollamo.webamo;

public final class ScoreCalculator {
    private ScoreCalculator() {}

    public static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    public static int overall(int security, int seo, int performance, int privacy, int accessibility) {
        double weighted = clamp(security) * 0.30
                + clamp(seo) * 0.25
                + clamp(performance) * 0.20
                + clamp(privacy) * 0.15
                + clamp(accessibility) * 0.10;
        return clamp((int) Math.round(weighted));
    }

    public static int performance(long elapsedMs, int bytes) {
        int timeScore;
        if (elapsedMs <= 500) timeScore = 100;
        else if (elapsedMs <= 1000) timeScore = 85;
        else if (elapsedMs <= 2000) timeScore = 70;
        else if (elapsedMs <= 4000) timeScore = 50;
        else timeScore = 30;

        int sizeScore;
        if (bytes <= 300_000) sizeScore = 100;
        else if (bytes <= 700_000) sizeScore = 80;
        else if (bytes <= 1_500_000) sizeScore = 60;
        else sizeScore = 40;

        return clamp((int) Math.round(timeScore * 0.70 + sizeScore * 0.30));
    }
}
