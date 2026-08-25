package com.desarrollamo.webamo;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

import java.net.URL;
import java.util.Iterator;

public final class HistoryStore {
    private static final String PREFS = "webamo_history_v2";

    private HistoryStore() {}

    public static void compareAndSave(Context context, AuditReport report) {
        String key = hostKey(report.finalUrl);
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String previousRaw = prefs.getString(key, null);
        if (previousRaw != null) {
            try {
                JSONObject previous = new JSONObject(previousRaw);
                report.previousScore = previous.optInt("score", report.overallScore);
                report.scoreDelta = report.overallScore - report.previousScore;
                JSONObject oldChecks = previous.optJSONObject("checks");
                if (oldChecks != null) {
                    JSONObject current = snapshotChecks(report);
                    Iterator<String> keys = current.keys();
                    while (keys.hasNext()) {
                        String id = keys.next();
                        if (!oldChecks.has(id)) continue;
                        String oldStatus = oldChecks.optString(id, AuditCheck.UNKNOWN);
                        String newStatus = current.optString(id, AuditCheck.UNKNOWN);
                        int oldRank = statusRank(oldStatus);
                        int newRank = statusRank(newStatus);
                        if (newRank > oldRank && (AuditCheck.WARN.equals(newStatus) || AuditCheck.FAIL.equals(newStatus))) {
                            report.regressions++;
                        } else if (newRank < oldRank && (AuditCheck.WARN.equals(oldStatus) || AuditCheck.FAIL.equals(oldStatus))
                                && (AuditCheck.PASS.equals(newStatus) || AuditCheck.INFO.equals(newStatus))) {
                            report.resolved++;
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        try {
            JSONObject now = new JSONObject();
            now.put("score", report.overallScore);
            now.put("checked_at", System.currentTimeMillis());
            now.put("checks", snapshotChecks(report));
            prefs.edit().putString(key, now.toString()).apply();
        } catch (Exception ignored) {}
    }

    private static JSONObject snapshotChecks(AuditReport report) {
        JSONObject out = new JSONObject();
        for (AuditCheck c : report.checks) {
            if (c.weight <= 0) continue;
            try { out.put(c.id, c.status); } catch (Exception ignored) {}
        }
        return out;
    }

    private static int statusRank(String status) {
        if (AuditCheck.FAIL.equals(status)) return 3;
        if (AuditCheck.WARN.equals(status)) return 2;
        if (AuditCheck.UNKNOWN.equals(status)) return 1;
        return 0;
    }

    private static String hostKey(String url) {
        try {
            String host = new URL(url).getHost().toLowerCase();
            return host.startsWith("www.") ? host.substring(4) : host;
        } catch (Exception e) {
            return Integer.toHexString(url == null ? 0 : url.hashCode());
        }
    }
}
