package com.desarrollamo.webamo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public final class AuditReport {
    public String target;
    public String finalUrl;
    public int statusCode;
    public long elapsedMs;
    public int bodyBytes;
    public String contentType;
    public boolean https;
    public boolean hsts;
    public boolean csp;
    public boolean noSniff;
    public boolean referrerPolicy;
    public boolean permissionsPolicy;
    public boolean frameProtection;
    public String title;
    public String metaDescription;
    public String canonical;
    public String language;
    public int h1Count;
    public int images;
    public int imagesWithoutAlt;
    public boolean robotsOk;
    public boolean sitemapOk;
    public int securityScore;
    public int seoScore;
    public int performanceScore;
    public int privacyScore;
    public int accessibilityScore;
    public int overallScore;
    public final List<String> trackers = new ArrayList<>();
    public final List<String> cookies = new ArrayList<>();
    public final List<String> findings = new ArrayList<>();

    public JSONObject toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("schema", "desarrollamo.webamo.v1");
        root.put("target", target);
        root.put("final_url", finalUrl);
        root.put("status", statusCode);
        root.put("elapsed_ms", elapsedMs);
        root.put("body_bytes", bodyBytes);
        root.put("content_type", contentType == null ? JSONObject.NULL : contentType);

        JSONObject scores = new JSONObject();
        scores.put("overall", overallScore);
        scores.put("security", securityScore);
        scores.put("seo", seoScore);
        scores.put("performance", performanceScore);
        scores.put("privacy_signals", privacyScore);
        scores.put("accessibility_basic", accessibilityScore);
        root.put("scores", scores);

        JSONObject security = new JSONObject();
        security.put("https", https);
        security.put("hsts", hsts);
        security.put("csp", csp);
        security.put("nosniff", noSniff);
        security.put("referrer_policy", referrerPolicy);
        security.put("permissions_policy", permissionsPolicy);
        security.put("frame_protection", frameProtection);
        root.put("security", security);

        JSONObject seo = new JSONObject();
        seo.put("title", title == null ? JSONObject.NULL : title);
        seo.put("meta_description", metaDescription == null ? JSONObject.NULL : metaDescription);
        seo.put("canonical", canonical == null ? JSONObject.NULL : canonical);
        seo.put("lang", language == null ? JSONObject.NULL : language);
        seo.put("h1_count", h1Count);
        seo.put("images", images);
        seo.put("images_without_alt", imagesWithoutAlt);
        seo.put("robots_ok", robotsOk);
        seo.put("sitemap_ok", sitemapOk);
        root.put("seo", seo);

        root.put("trackers", new JSONArray(trackers));
        root.put("cookies", new JSONArray(cookies));
        root.put("findings", new JSONArray(findings));
        root.put("note", "Auditoría técnica no intrusiva. No es pentest, Lighthouse ni dictamen legal de privacidad.");
        return root;
    }

    public String shareText() {
        StringBuilder out = new StringBuilder();
        out.append("WebAMO · ").append(target).append('\n');
        out.append("Puntaje general: ").append(overallScore).append("/100\n");
        out.append("Seguridad ").append(securityScore)
                .append(" · SEO ").append(seoScore)
                .append(" · Rendimiento ").append(performanceScore)
                .append(" · Privacidad ").append(privacyScore)
                .append(" · Accesibilidad ").append(accessibilityScore).append("\n\n");
        for (String finding : findings) out.append("• ").append(finding).append('\n');
        if (!trackers.isEmpty()) out.append("\nRastreadores: ").append(String.join(", ", trackers)).append('\n');
        if (!cookies.isEmpty()) out.append("Cookies observadas: ").append(String.join(", ", cookies)).append('\n');
        out.append("\nAuditoría no intrusiva realizada desde el dispositivo.");
        return out.toString();
    }
}
