package com.desarrollamo.webamo;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AuditEngine {
    private static final int MAX_BYTES = 2_000_000;
    private static final int TIMEOUT_MS = 10_000;
    private static final Pattern TITLE = Pattern.compile("(?is)<title\\b[^>]*>(.*?)</title>");
    private static final Pattern META = Pattern.compile("(?is)<meta\\b[^>]*>");
    private static final Pattern LINK = Pattern.compile("(?is)<link\\b[^>]*>");
    private static final Pattern HTML = Pattern.compile("(?is)<html\\b[^>]*>");
    private static final Pattern H1 = Pattern.compile("(?is)<h1\\b[^>]*>");
    private static final Pattern IMG = Pattern.compile("(?is)<img\\b[^>]*>");
    private static final Pattern ATTR = Pattern.compile("(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*=\\s*([\"'])(.*?)\\2");

    private AuditEngine() {}

    public static AuditReport audit(String input) throws Exception {
        String target = normalizeUrl(input);
        long started = System.nanoTime();
        HttpURLConnection connection = open(target, TIMEOUT_MS);
        int status = connection.getResponseCode();
        String finalUrl = connection.getURL().toString();
        byte[] body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), MAX_BYTES);
        long elapsedMs = Math.max(1L, (System.nanoTime() - started) / 1_000_000L);

        AuditReport report = new AuditReport();
        report.target = target;
        report.finalUrl = finalUrl;
        report.statusCode = status;
        report.elapsedMs = elapsedMs;
        report.bodyBytes = body.length;
        report.contentType = connection.getContentType();
        report.https = finalUrl.toLowerCase(Locale.ROOT).startsWith("https://");
        report.hsts = hasHeader(connection, "Strict-Transport-Security");
        String csp = header(connection, "Content-Security-Policy");
        report.csp = csp != null && !csp.isBlank();
        report.noSniff = "nosniff".equalsIgnoreCase(header(connection, "X-Content-Type-Options"));
        report.referrerPolicy = hasHeader(connection, "Referrer-Policy");
        report.permissionsPolicy = hasHeader(connection, "Permissions-Policy");
        report.frameProtection = hasHeader(connection, "X-Frame-Options")
                || (csp != null && csp.toLowerCase(Locale.ROOT).contains("frame-ancestors"));
        collectCookies(connection, report.cookies);
        connection.disconnect();

        String html = decode(body, report.contentType);
        analyzeHtml(html, report);
        detectTrackers(html, report.trackers);
        report.robotsOk = checkResource(finalUrl, "/robots.txt");
        report.sitemapOk = checkResource(finalUrl, "/sitemap.xml");
        score(report);
        findings(report);
        return report;
    }

    static String normalizeUrl(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) throw new IllegalArgumentException("Escribí una URL.");
        if (!value.matches("(?i)^https?://.*")) value = "https://" + value;
        try {
            URL parsed = new URL(value);
            if (parsed.getHost() == null || parsed.getHost().isBlank()) throw new Exception();
            return parsed.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException("La URL no es válida.");
        }
    }

    private static HttpURLConnection open(String target, int timeout) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(target).openConnection();
        c.setInstanceFollowRedirects(true);
        c.setConnectTimeout(timeout);
        c.setReadTimeout(timeout);
        c.setRequestProperty("User-Agent", "WebAMO/0.1.0 (+https://github.com/amoedo7/MiWeb)");
        c.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
        return c;
    }

    private static byte[] readLimited(InputStream input, int limit) throws Exception {
        if (input == null) return new byte[0];
        try (InputStream in = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            while (total < limit) {
                int read = in.read(buffer, 0, Math.min(buffer.length, limit - total));
                if (read < 0) break;
                out.write(buffer, 0, read);
                total += read;
            }
            return out.toByteArray();
        }
    }

    private static String decode(byte[] body, String contentType) {
        Charset charset = StandardCharsets.UTF_8;
        if (contentType != null) {
            Matcher m = Pattern.compile("(?i)charset=([^;\\s]+)").matcher(contentType);
            if (m.find()) {
                try { charset = Charset.forName(m.group(1).replace("\"", "")); } catch (Exception ignored) {}
            }
        }
        return new String(body, charset);
    }

    private static void analyzeHtml(String html, AuditReport r) {
        Matcher title = TITLE.matcher(html);
        if (title.find()) r.title = cleanText(title.group(1));

        Matcher metaMatcher = META.matcher(html);
        while (metaMatcher.find()) {
            Map<String, String> attrs = attrs(metaMatcher.group());
            String key = firstNonEmpty(attrs.get("name"), attrs.get("property"));
            if (key != null && "description".equalsIgnoreCase(key)) r.metaDescription = attrs.get("content");
        }

        Matcher linkMatcher = LINK.matcher(html);
        while (linkMatcher.find()) {
            Map<String, String> attrs = attrs(linkMatcher.group());
            String rel = attrs.get("rel");
            if (rel != null && rel.toLowerCase(Locale.ROOT).contains("canonical")) {
                r.canonical = attrs.get("href");
                break;
            }
        }

        Matcher htmlTag = HTML.matcher(html);
        if (htmlTag.find()) r.language = attrs(htmlTag.group()).get("lang");

        r.h1Count = count(H1, html);
        Matcher imageMatcher = IMG.matcher(html);
        while (imageMatcher.find()) {
            r.images++;
            if (!attrs(imageMatcher.group()).containsKey("alt")) r.imagesWithoutAlt++;
        }
    }

    private static Map<String, String> attrs(String tag) {
        Map<String, String> map = new LinkedHashMap<>();
        Matcher matcher = ATTR.matcher(tag);
        while (matcher.find()) map.put(matcher.group(1).toLowerCase(Locale.ROOT), matcher.group(3).trim());
        return map;
    }

    private static int count(Pattern pattern, String text) {
        int count = 0;
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) count++;
        return count;
    }

    private static String cleanText(String text) {
        return text == null ? null : text.replaceAll("(?s)<[^>]+>", " ").replaceAll("\\s+", " ").trim();
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && !a.isBlank()) return a;
        return b != null && !b.isBlank() ? b : null;
    }

    private static void collectCookies(HttpURLConnection c, List<String> out) {
        Set<String> names = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> entry : c.getHeaderFields().entrySet()) {
            if (entry.getKey() == null || !"set-cookie".equalsIgnoreCase(entry.getKey())) continue;
            for (String cookie : entry.getValue()) {
                if (cookie == null) continue;
                int equals = cookie.indexOf('=');
                String name = (equals > 0 ? cookie.substring(0, equals) : cookie).trim();
                if (!name.isBlank()) names.add(name);
            }
        }
        out.addAll(names);
    }

    private static void detectTrackers(String html, List<String> out) {
        String text = html.toLowerCase(Locale.ROOT);
        Map<String, String[]> signatures = new LinkedHashMap<>();
        signatures.put("Google Analytics", new String[]{"google-analytics.com", "gtag(", "googletagmanager.com/gtag"});
        signatures.put("Google Tag Manager", new String[]{"googletagmanager.com/gtm", "gtm.js"});
        signatures.put("Google Ads / DoubleClick", new String[]{"doubleclick.net", "googleadservices.com"});
        signatures.put("Meta Pixel", new String[]{"connect.facebook.net", "fbq("});
        signatures.put("Hotjar", new String[]{"hotjar.com", "hj("});
        signatures.put("Microsoft Clarity", new String[]{"clarity.ms/tag", "clarity("});
        signatures.put("TikTok Pixel", new String[]{"analytics.tiktok.com", "ttq."});
        signatures.put("LinkedIn Insight", new String[]{"snap.licdn.com", "linkedin.com/insight"});
        for (Map.Entry<String, String[]> row : signatures.entrySet()) {
            for (String signature : row.getValue()) {
                if (text.contains(signature)) { out.add(row.getKey()); break; }
            }
        }
    }

    private static boolean checkResource(String finalUrl, String path) {
        HttpURLConnection c = null;
        try {
            URL base = new URL(finalUrl);
            URL resource = new URL(base.getProtocol(), base.getHost(), base.getPort(), path);
            c = open(resource.toString(), 4_000);
            c.setRequestMethod("GET");
            int code = c.getResponseCode();
            return code >= 200 && code < 400;
        } catch (Exception ignored) {
            return false;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static String header(HttpURLConnection c, String name) {
        for (Map.Entry<String, List<String>> entry : c.getHeaderFields().entrySet()) {
            if (entry.getKey() != null && name.equalsIgnoreCase(entry.getKey()) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static boolean hasHeader(HttpURLConnection c, String name) {
        String value = header(c, name);
        return value != null && !value.isBlank();
    }

    private static void score(AuditReport r) {
        int security = 0;
        if (r.https) security += 25;
        if (r.hsts) security += 15;
        if (r.csp) security += 20;
        if (r.noSniff) security += 10;
        if (r.referrerPolicy) security += 10;
        if (r.permissionsPolicy) security += 10;
        if (r.frameProtection) security += 10;
        r.securityScore = ScoreCalculator.clamp(security);

        int seo = 0;
        if (r.title != null && !r.title.isBlank()) seo += 20;
        if (r.metaDescription != null && !r.metaDescription.isBlank()) seo += 20;
        if (r.canonical != null && !r.canonical.isBlank()) seo += 15;
        if (r.h1Count == 1) seo += 15;
        if (r.language != null && !r.language.isBlank()) seo += 10;
        if (r.images == 0 || r.imagesWithoutAlt == 0) seo += 10;
        if (r.robotsOk) seo += 5;
        if (r.sitemapOk) seo += 5;
        r.seoScore = ScoreCalculator.clamp(seo);

        r.performanceScore = ScoreCalculator.performance(r.elapsedMs, r.bodyBytes);
        r.privacyScore = ScoreCalculator.clamp(100 - r.trackers.size() * 12 - r.cookies.size() * 4);

        int accessibility = 0;
        if (r.language != null && !r.language.isBlank()) accessibility += 25;
        if (r.h1Count == 1) accessibility += 25;
        if (r.images == 0 || r.imagesWithoutAlt == 0) accessibility += 35;
        if (r.title != null && !r.title.isBlank()) accessibility += 15;
        r.accessibilityScore = ScoreCalculator.clamp(accessibility);

        r.overallScore = ScoreCalculator.overall(r.securityScore, r.seoScore, r.performanceScore, r.privacyScore, r.accessibilityScore);
        if (r.statusCode < 200 || r.statusCode >= 400) r.overallScore = Math.min(r.overallScore, 45);
    }

    private static void findings(AuditReport r) {
        if (r.statusCode >= 200 && r.statusCode < 400) r.findings.add("La página respondió HTTP " + r.statusCode + " en " + r.elapsedMs + " ms.");
        else r.findings.add("La página respondió HTTP " + r.statusCode + ". Revisá disponibilidad y redirecciones.");
        if (!r.https) r.findings.add("La URL final no usa HTTPS.");
        if (!r.hsts && r.https) r.findings.add("Falta Strict-Transport-Security (HSTS).");
        if (!r.csp) r.findings.add("No se observó Content-Security-Policy.");
        if (!r.noSniff) r.findings.add("Falta X-Content-Type-Options: nosniff.");
        if (r.title == null || r.title.isBlank()) r.findings.add("Falta <title>.");
        if (r.metaDescription == null || r.metaDescription.isBlank()) r.findings.add("Falta meta description.");
        if (r.h1Count != 1) r.findings.add("Se detectaron " + r.h1Count + " H1; lo esperado como base es uno.");
        if (r.imagesWithoutAlt > 0) r.findings.add(r.imagesWithoutAlt + " de " + r.images + " imágenes no tienen atributo alt.");
        if (!r.robotsOk) r.findings.add("No se confirmó robots.txt con respuesta 2xx/3xx.");
        if (!r.sitemapOk) r.findings.add("No se confirmó sitemap.xml con respuesta 2xx/3xx.");
        if (!r.trackers.isEmpty()) r.findings.add("Señales de rastreo detectadas en el HTML: " + r.trackers.size() + ".");
        if (!r.cookies.isEmpty()) r.findings.add("Cookies observadas en la respuesta HTTP: " + r.cookies.size() + ".");
        if (r.findings.size() == 1) r.findings.add("No se detectaron faltantes básicos en esta lectura.");
    }
}
