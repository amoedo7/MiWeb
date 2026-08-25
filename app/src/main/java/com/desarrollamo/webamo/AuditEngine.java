package com.desarrollamo.webamo;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;

public final class AuditEngine {
    private static final int MAX_HTML = 4 * 1024 * 1024;
    private static final int MAIN_TIMEOUT = 10_000;
    private static final int SMALL_TIMEOUT = 4_500;
    private static final int MAX_CRAWL = 6;
    private static final int MAX_ASSETS = 18;
    private static final String UA =
            "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 WebAMO/0.1.1";

    private static final Pattern TAG = Pattern.compile("(?is)<([a-zA-Z][a-zA-Z0-9:-]*)\\b([^>]*)>");
    private static final Pattern ATTR = Pattern.compile("(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*=\\s*(?:([\"'])(.*?)\\2|([^\\s>]+))");
    private static final Pattern TITLE = Pattern.compile("(?is)<title\\b[^>]*>(.*?)</title>");
    private static final Pattern H = Pattern.compile("(?is)<h([1-6])\\b[^>]*>(.*?)</h\\1>");
    private static final Pattern BUTTON = Pattern.compile("(?is)<button\\b([^>]*)>(.*?)</button>");
    private static final Pattern ANCHOR = Pattern.compile("(?is)<a\\b([^>]*)>(.*?)</a>");
    private static final Pattern COMMENT = Pattern.compile("(?is)<!--(.*?)-->");
    private static final Pattern JSON_LD = Pattern.compile("(?is)<script\\b([^>]*)type\\s*=\\s*([\"'])application/ld\\+json\\2([^>]*)>(.*?)</script>");
    private static final Pattern URL_IN_TEXT = Pattern.compile("(?i)https?://[^\\s\"'<>\\\\]+");

    private AuditEngine() {}

    public static AuditReport audit(String input, boolean quick) throws Exception {
        AuditReport r = new AuditReport();
        r.target = normalizeUrl(input);

        FetchResult main = fetch(r.target, "GET", MAX_HTML, MAIN_TIMEOUT, null);
        if (main.status == 0) throw new IllegalStateException("No se pudo abrir la URL: " + main.error);
        r.finalUrl = main.finalUrl;
        r.statusCode = main.status;
        r.elapsedMs = main.elapsedMs;
        r.bodyBytes = main.body.length;
        r.contentType = main.headers.getOrDefault("content-type", "");
        r.server = main.headers.getOrDefault("server", "");
        r.cookies.addAll(cookieNames(main.setCookies));

        String html = decode(main.body, r.contentType);
        HtmlFacts f = parseHtml(html, r.finalUrl);

        fingerprint(r, main, html, f);
        addBaseChecks(r, main, html);
        addTlsAndDnsChecks(r);
        ResourceBundle resources = addRobotsSitemapSeoChecks(r, f, quick);
        AssetBundle assets = inspectAssets(r, f, html, quick);
        addPerformanceChecks(r, main, f, assets);
        addAccessibilityChecks(r, f);
        addPrivacyChecks(r, main, f, html, assets);
        addSecurityChecks(r, main, f, html, assets, quick);
        addTechnicalAndAiChecks(r, main, f, html, resources, assets, quick);
        if (!quick) addMiniCrawlChecks(r, f, resources);
        else add(r, "crawl", ScoreCalculator.SEO, "Mini-crawl", AuditCheck.UNKNOWN,
                "Omitido en modo rápido", 2, "");

        ScoreCalculator.finalizeReport(r);
        return r;
    }

    public static AuditReport audit(String input) throws Exception {
        return audit(input, false);
    }

    private static void addBaseChecks(AuditReport r, FetchResult main, String html) {
        boolean okStatus = main.status >= 200 && main.status < 400;
        add(r, "http_status", ScoreCalculator.TECHNICAL, "Página accesible",
                okStatus ? AuditCheck.PASS : AuditCheck.FAIL,
                "HTTP " + main.status, 3, "Corregir el estado HTTP de la página principal.");

        boolean https = r.finalUrl.toLowerCase(Locale.ROOT).startsWith("https://");
        add(r, "https", ScoreCalculator.SECURITY, "HTTPS",
                https ? AuditCheck.PASS : AuditCheck.FAIL,
                https ? "La URL final usa HTTPS" : "La URL final sigue en HTTP", 5,
                "Servir todo el sitio exclusivamente por HTTPS.");

        try {
            URL u = new URL(r.finalUrl);
            String httpUrl = "http://" + u.getAuthority() + (u.getPath().isEmpty() ? "/" : u.getPath());
            FetchResult p = fetch(httpUrl, "GET", 4096, SMALL_TIMEOUT, null);
            boolean forced = p.status > 0 && p.finalUrl.toLowerCase(Locale.ROOT).startsWith("https://");
            add(r, "http_https", ScoreCalculator.SECURITY, "HTTP → HTTPS",
                    forced ? AuditCheck.PASS : AuditCheck.FAIL,
                    p.status == 0 ? "No se pudo verificar" : (forced ? "Redirección efectiva" : "HTTP no fuerza HTTPS"),
                    3, "Forzar redirección 301/308 de HTTP a HTTPS.");
        } catch (Exception e) {
            add(r, "http_https", ScoreCalculator.SECURITY, "HTTP → HTTPS",
                    AuditCheck.UNKNOWN, "No se pudo verificar", 3, "");
        }

        String ctype = main.headers.getOrDefault("content-type", "");
        add(r, "content_type", ScoreCalculator.TECHNICAL, "Content-Type",
                ctype.toLowerCase(Locale.ROOT).contains("text/html") ? AuditCheck.PASS : AuditCheck.WARN,
                ctype.isBlank() ? "Ausente" : ctype, 1, "Servir HTML con Content-Type correcto.");

        boolean charset = Pattern.compile("(?i)charset=").matcher(ctype).find()
                || Pattern.compile("(?is)<meta\\b[^>]*charset\\s*=").matcher(html).find();
        add(r, "charset", ScoreCalculator.TECHNICAL, "Charset",
                charset ? AuditCheck.PASS : AuditCheck.WARN,
                charset ? "Declarado" : "No declarado", 1, "Declarar UTF-8.");

        String enc = main.headers.getOrDefault("content-encoding", "").toLowerCase(Locale.ROOT);
        if (Arrays.asList("gzip", "br", "zstd").contains(enc)) {
            add(r, "compression", ScoreCalculator.PERFORMANCE, "Compresión HTML",
                    AuditCheck.PASS, enc, 2, "");
        } else {
            addInfo(r, "compression", ScoreCalculator.PERFORMANCE, "Compresión HTML",
                    "No observable de forma fiable con HttpURLConnection; no se penaliza.");
        }
    }

    private static void addTlsAndDnsChecks(AuditReport r) {
        try {
            URL u = new URL(r.finalUrl);
            String host = u.getHost();
            InetAddress[] addresses = InetAddress.getAllByName(host);
            int ipv4 = 0, ipv6 = 0;
            List<String> sample = new ArrayList<>();
            for (InetAddress a : addresses) {
                if (a.getHostAddress().contains(":")) ipv6++; else ipv4++;
                if (sample.size() < 3) sample.add(a.getHostAddress());
            }
            add(r, "dns_a", ScoreCalculator.TECHNICAL, "DNS",
                    addresses.length > 0 ? AuditCheck.PASS : AuditCheck.WARN,
                    ipv4 + " IPv4 · " + ipv6 + " IPv6 · " + String.join(", ", sample),
                    1, "Revisar resolución DNS.");
        } catch (Exception e) {
            add(r, "dns_a", ScoreCalculator.TECHNICAL, "DNS", AuditCheck.UNKNOWN,
                    "No verificable: " + shortError(e), 1, "");
        }

        if (!r.finalUrl.toLowerCase(Locale.ROOT).startsWith("https://")) return;
        SSLSocket socket = null;
        try {
            URL u = new URL(r.finalUrl);
            int port = u.getPort() > 0 ? u.getPort() : 443;
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLSocketFactory factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(u.getHost(), port);
            socket.setSoTimeout(SMALL_TIMEOUT);
            socket.startHandshake();
            SSLSession session = socket.getSession();
            r.tlsVersion = session.getProtocol();
            add(r, "tls_protocol", ScoreCalculator.SECURITY, "Versión TLS",
                    ("TLSv1.2".equals(r.tlsVersion) || "TLSv1.3".equals(r.tlsVersion)) ? AuditCheck.PASS : AuditCheck.WARN,
                    r.tlsVersion + " · " + session.getCipherSuite(), 3, "Usar TLS 1.2/1.3.");

            Certificate[] certs = session.getPeerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certs[0];
                cert.checkValidity();
                long days = (cert.getNotAfter().getTime() - System.currentTimeMillis()) / 86_400_000L;
                r.tlsDaysLeft = (int) days;
                String status = days < 0 ? AuditCheck.FAIL : days < 21 ? AuditCheck.WARN : AuditCheck.PASS;
                add(r, "tls_cert", ScoreCalculator.SECURITY, "Certificado TLS", status,
                        "Válido hasta " + cert.getNotAfter() + " · " + days + " días",
                        5, days < 21 ? "Renovar el certificado pronto." : "");
            } else {
                add(r, "tls_cert", ScoreCalculator.SECURITY, "Certificado TLS",
                        AuditCheck.UNKNOWN, "Certificado no interpretable", 5, "");
            }
        } catch (Exception e) {
            add(r, "tls_cert", ScoreCalculator.SECURITY, "Certificado TLS",
                    AuditCheck.FAIL, shortError(e), 5, "Corregir la configuración TLS.");
        } finally {
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
        }
    }

    private static ResourceBundle addRobotsSitemapSeoChecks(AuditReport r, HtmlFacts f, boolean quick) {
        ResourceBundle out = new ResourceBundle();
        try {
            URL base = new URL(r.finalUrl);
            String origin = origin(base);
            out.robots = fetch(origin + "/robots.txt", "GET", 512 * 1024, SMALL_TIMEOUT, null);
            out.robotsText = decode(out.robots.body, out.robots.headers.get("content-type"));
            Matcher sm = Pattern.compile("(?im)^\\s*Sitemap:\\s*(\\S+)").matcher(out.robotsText);
            if (sm.find()) out.sitemapUrl = sm.group(1).trim();
            if (out.sitemapUrl.isBlank()) out.sitemapUrl = origin + "/sitemap.xml";
            out.sitemap = fetch(out.sitemapUrl, "GET", 1024 * 1024, SMALL_TIMEOUT, null);
            out.sitemapText = decode(out.sitemap.body, out.sitemap.headers.get("content-type"));
        } catch (Exception e) {
            out.robots = FetchResult.error(r.finalUrl + "/robots.txt", shortError(e));
            out.sitemap = FetchResult.error(r.finalUrl + "/sitemap.xml", shortError(e));
        }

        String title = f.title;
        if (title.isBlank()) add(r, "seo_title", ScoreCalculator.SEO, "Title", AuditCheck.FAIL, "Falta <title>", 5, "Añadir un title descriptivo y único.");
        else if (title.length() >= 15 && title.length() <= 65) add(r, "seo_title", ScoreCalculator.SEO, "Title", AuditCheck.PASS, title.length() + " caracteres · " + truncate(title, 58), 4, "");
        else add(r, "seo_title", ScoreCalculator.SEO, "Title", AuditCheck.WARN, title.length() + " caracteres · " + truncate(title, 58), 4, "Revisar longitud y claridad.");

        String desc = f.meta("description");
        if (desc.isBlank()) add(r, "seo_desc", ScoreCalculator.SEO, "Meta description", AuditCheck.FAIL, "Falta", 4, "Añadir una meta description útil.");
        else if (desc.length() >= 60 && desc.length() <= 180) add(r, "seo_desc", ScoreCalculator.SEO, "Meta description", AuditCheck.PASS, desc.length() + " caracteres", 3, "");
        else add(r, "seo_desc", ScoreCalculator.SEO, "Meta description", AuditCheck.WARN, desc.length() + " caracteres", 3, "Revisar longitud y contenido.");

        String robotsMeta = f.meta("robots").toLowerCase(Locale.ROOT);
        boolean noindex = robotsMeta.contains("noindex");
        add(r, "seo_index", ScoreCalculator.SEO, "Indexación",
                noindex ? AuditCheck.FAIL : AuditCheck.PASS,
                noindex ? robotsMeta : "No se detectó noindex", 5,
                "Quitar noindex si la página debe aparecer en buscadores.");

        String canonical = f.canonical;
        if (canonical.isBlank()) {
            add(r, "seo_canonical", ScoreCalculator.SEO, "Canonical", AuditCheck.FAIL, "Falta rel=canonical", 4, "Añadir canonical.");
        } else {
            String resolved = resolve(r.finalUrl, canonical);
            boolean same = sameSite(r.finalUrl, resolved);
            add(r, "seo_canonical", ScoreCalculator.SEO, "Canonical",
                    same ? AuditCheck.PASS : AuditCheck.WARN,
                    truncate(resolved, 70), 4, "Revisar canonical hacia otro dominio.");
        }

        int h1 = f.headingCounts[1];
        add(r, "seo_h1", ScoreCalculator.SEO, "H1",
                h1 == 1 ? AuditCheck.PASS : h1 == 0 ? AuditCheck.FAIL : AuditCheck.WARN,
                h1 + " H1", 3, "Usar una jerarquía de headings clara.");

        int jumps = 0, prev = 0;
        for (int level : f.headingSequence) {
            if (prev > 0 && level > prev + 1) jumps++;
            prev = level;
        }
        add(r, "seo_headings", ScoreCalculator.SEO, "Jerarquía headings",
                jumps == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                jumps + " salto(s) de nivel · " + f.headingSequence.size() + " headings",
                2, "Evitar saltos H2→H4, etc.");

        boolean robotsOk = out.robots.status == 200;
        add(r, "robots", ScoreCalculator.SEO, "robots.txt",
                robotsOk ? AuditCheck.PASS : out.robots.status == 404 ? AuditCheck.INFO : AuditCheck.WARN,
                robotsOk ? "Presente" : "HTTP " + out.robots.status, robotsOk ? 2 : 0, "");

        String sl = out.sitemapText.toLowerCase(Locale.ROOT);
        boolean sitemapValid = out.sitemap.status == 200 && (sl.contains("<urlset") || sl.contains("<sitemapindex"));
        int locs = count(Pattern.compile("(?i)<loc>"), out.sitemapText);
        add(r, "sitemap", ScoreCalculator.SEO, "Sitemap",
                sitemapValid ? AuditCheck.PASS : AuditCheck.WARN,
                sitemapValid ? "XML válido · " + locs + " URL(s) visibles" : "HTTP " + out.sitemap.status,
                sitemapValid ? 4 : 2, "Publicar/validar sitemap XML.");

        int jsonLd = f.validJsonLdBlocks;
        add(r, "jsonld", ScoreCalculator.SEO, "Datos estructurados",
                jsonLd > 0 ? AuditCheck.PASS : AuditCheck.WARN,
                jsonLd > 0 ? jsonLd + " bloque(s) JSON-LD" : "No se detectó JSON-LD",
                2, "Añadir schema.org cuando sea pertinente.");

        int og = 0;
        if (!f.metaProperty("og:title").isBlank()) og++;
        if (!f.metaProperty("og:description").isBlank()) og++;
        if (!f.metaProperty("og:image").isBlank()) og++;
        add(r, "open_graph", ScoreCalculator.SEO, "Open Graph",
                og == 3 ? AuditCheck.PASS : AuditCheck.WARN,
                og + "/3 señales clave", 2, "Completar og:title, og:description y og:image.");

        String tw = f.meta("twitter:card");
        add(r, "twitter_card", ScoreCalculator.SEO, "Twitter/X Card",
                tw.isBlank() ? AuditCheck.WARN : AuditCheck.PASS,
                tw.isBlank() ? "No detectada" : tw, 1, "Añadir twitter:card si se comparte en redes.");

        String viewport = f.meta("viewport");
        add(r, "viewport", ScoreCalculator.SEO, "Viewport móvil",
                viewport.isBlank() ? AuditCheck.FAIL : AuditCheck.PASS,
                viewport.isBlank() ? "Falta meta viewport" : truncate(viewport, 70),
                2, "Añadir viewport responsive.");

        if (!quick) {
            try {
                String origin = origin(new URL(r.finalUrl));
                FetchResult nf = fetch(origin + "/__webamo_404_" + System.currentTimeMillis(), "GET", 64 * 1024, SMALL_TIMEOUT, null);
                String status = (nf.status == 404 || nf.status == 410) ? AuditCheck.PASS : nf.status == 200 ? AuditCheck.FAIL : AuditCheck.WARN;
                add(r, "real_404", ScoreCalculator.SEO, "Página 404", status, "HTTP " + nf.status, 3,
                        "Devolver 404/410 real para URLs inexistentes.");
            } catch (Exception e) {
                add(r, "real_404", ScoreCalculator.SEO, "Página 404", AuditCheck.UNKNOWN, "No verificable", 3, "");
            }
        } else {
            add(r, "real_404", ScoreCalculator.SEO, "Página 404", AuditCheck.UNKNOWN, "Omitido en modo rápido", 3, "");
        }
        return out;
    }

    private static AssetBundle inspectAssets(AuditReport r, HtmlFacts f, String html, boolean quick) {
        AssetBundle bundle = new AssetBundle();
        LinkedHashMap<String, String> urls = new LinkedHashMap<>();
        for (TagFact t : f.tags) {
            String name = t.name;
            String raw = "";
            String kind = "";
            if ("script".equals(name)) { raw = t.attr("src"); kind = "js"; }
            else if ("img".equals(name) || "source".equals(name)) { raw = t.attr("src"); kind = "image"; }
            else if ("link".equals(name)) {
                raw = t.attr("href");
                String rel = t.attr("rel").toLowerCase(Locale.ROOT);
                kind = rel.contains("stylesheet") ? "css" : "other";
            }
            if (raw.isBlank() || raw.startsWith("data:") || raw.startsWith("#")) continue;
            String resolved = resolve(r.finalUrl, raw);
            if (resolved.startsWith("http://") || resolved.startsWith("https://")) urls.putIfAbsent(resolved, kind);
        }
        r.assetsDetected = urls.size();

        LinkedHashSet<String> third = new LinkedHashSet<>();
        for (String u : urls.keySet()) if (!sameSite(r.finalUrl, u)) third.add(host(u));
        r.thirdPartyHosts.addAll(third);
        r.thirdPartyHostCount = third.size();

        int limit = quick ? Math.min(8, urls.size()) : Math.min(MAX_ASSETS, urls.size());
        List<Map.Entry<String, String>> sample = new ArrayList<>(urls.entrySet()).subList(0, limit);
        if (!sample.isEmpty()) {
            ExecutorService pool = Executors.newFixedThreadPool(Math.min(6, sample.size()));
            List<Future<AssetFact>> futures = new ArrayList<>();
            for (Map.Entry<String, String> e : sample) {
                futures.add(pool.submit(() -> inspectAsset(e.getKey(), e.getValue())));
            }
            for (Future<AssetFact> future : futures) {
                try {
                    AssetFact a = future.get();
                    bundle.items.add(a);
                    if (a.size > 0) bundle.totalKnownBytes += a.size;
                    if (a.size > bundle.largestBytes) { bundle.largestBytes = a.size; bundle.largestUrl = a.url; }
                    if ("js".equals(a.kind)) bundle.jsBytes += Math.max(0, a.size);
                    if ("css".equals(a.kind)) bundle.cssBytes += Math.max(0, a.size);
                    if ("image".equals(a.kind)) bundle.imageBytes += Math.max(0, a.size);
                    if (a.cacheLong) bundle.cached++;
                    if (a.cacheKnown) bundle.cacheKnown++;
                    if ("js".equals(a.kind) && !a.sampleText.isBlank()) bundle.sampledJs.append('\n').append(a.sampleText);
                } catch (Exception ignored) {}
            }
            pool.shutdownNow();
        }
        r.sampledAssetBytes = bundle.totalKnownBytes;
        return bundle;
    }

    private static AssetFact inspectAsset(String url, String kind) {
        FetchResult head = fetch(url, "HEAD", 0, 3_500, null);
        if (head.status == 0 || head.status == 403 || head.status == 405 || head.status == 501) {
            head = fetch(url, "GET", "js".equals(kind) ? 128 * 1024 : 4096, 3_500, null);
        }
        long size = -1;
        String cl = head.headers.get("content-length");
        if (cl != null) try { size = Long.parseLong(cl); } catch (Exception ignored) {}
        if (size < 0 && head.body.length > 0) size = head.body.length;
        String cc = head.headers.getOrDefault("cache-control", "");
        boolean cacheKnown = !cc.isBlank();
        boolean cacheLong = Pattern.compile("(?i)max-age=(?:[6-9]\\d{4}|[1-9]\\d{5,})").matcher(cc).find();
        String sampleText = "js".equals(kind) ? decode(head.body, head.headers.get("content-type")) : "";
        return new AssetFact(url, kind, head.status, size, cacheKnown, cacheLong, sampleText);
    }

    private static void addPerformanceChecks(AuditReport r, FetchResult main, HtmlFacts f, AssetBundle a) {
        String responseStatus = main.elapsedMs < 800 ? AuditCheck.PASS : main.elapsedMs < 1800 ? AuditCheck.WARN : AuditCheck.FAIL;
        add(r, "ttfb_like", ScoreCalculator.PERFORMANCE, "Respuesta inicial", responseStatus,
                main.elapsedMs + " ms", 4, "Mejorar TTFB/red/origen.");

        String htmlStatus = main.body.length < 150 * 1024 ? AuditCheck.PASS : main.body.length < 500 * 1024 ? AuditCheck.WARN : AuditCheck.FAIL;
        add(r, "html_weight", ScoreCalculator.PERFORMANCE, "HTML transferido", htmlStatus,
                humanBytes(main.body.length), 2, "Reducir HTML excesivo.");

        add(r, "asset_count", ScoreCalculator.PERFORMANCE, "Assets detectados",
                r.assetsDetected > 80 ? AuditCheck.WARN : AuditCheck.PASS,
                r.assetsDetected + " recurso(s) · " + a.items.size() + " medidos",
                2, "Reducir recursos innecesarios.");

        if (!a.items.isEmpty() && a.totalKnownBytes > 0) {
            add(r, "asset_weight", ScoreCalculator.PERFORMANCE, "Peso assets muestra",
                    a.totalKnownBytes > 3L * 1024 * 1024 ? AuditCheck.WARN : AuditCheck.PASS,
                    humanBytes(a.totalKnownBytes), 3, "Optimizar peso total.");
            add(r, "largest_asset", ScoreCalculator.PERFORMANCE, "Asset más pesado",
                    a.largestBytes > 1024 * 1024 ? AuditCheck.WARN : AuditCheck.PASS,
                    humanBytes(a.largestBytes) + " · " + truncate(a.largestUrl, 48),
                    2, "Optimizar el recurso más pesado.");
        } else {
            add(r, "asset_weight", ScoreCalculator.PERFORMANCE, "Peso assets muestra",
                    AuditCheck.UNKNOWN, "Tamaños no verificables", 3, "");
        }

        add(r, "js_weight", ScoreCalculator.PERFORMANCE, "JavaScript muestra",
                a.jsBytes > 2L * 1024 * 1024 ? AuditCheck.FAIL : a.jsBytes > 900 * 1024 ? AuditCheck.WARN : AuditCheck.PASS,
                humanBytes(a.jsBytes), 4, "Reducir/splitear JavaScript.");
        add(r, "css_weight", ScoreCalculator.PERFORMANCE, "CSS muestra",
                a.cssBytes > 500 * 1024 ? AuditCheck.WARN : AuditCheck.PASS,
                humanBytes(a.cssBytes), 2, "Reducir CSS.");
        add(r, "image_weight", ScoreCalculator.PERFORMANCE, "Imágenes muestra",
                a.imageBytes > 2L * 1024 * 1024 ? AuditCheck.WARN : AuditCheck.PASS,
                humanBytes(a.imageBytes), 2, "Optimizar imágenes.");

        int blockingJs = 0, lazyImages = 0, imageCount = 0, noDims = 0;
        for (TagFact t : f.tags) {
            if ("script".equals(t.name) && !t.attr("src").isBlank()
                    && t.attr("async").isBlank() && t.attr("defer").isBlank()
                    && !"module".equalsIgnoreCase(t.attr("type"))) blockingJs++;
            if ("img".equals(t.name)) {
                imageCount++;
                if ("lazy".equalsIgnoreCase(t.attr("loading"))) lazyImages++;
                if (t.attr("width").isBlank() || t.attr("height").isBlank()) noDims++;
            }
        }
        add(r, "blocking_js", ScoreCalculator.PERFORMANCE, "JS bloqueante",
                blockingJs == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                blockingJs + " script(s)", 3, "Usar defer/async/module cuando sea seguro.");
        add(r, "lazy_images", ScoreCalculator.PERFORMANCE, "Lazy imágenes",
                imageCount >= 4 && lazyImages == 0 ? AuditCheck.WARN : AuditCheck.INFO,
                lazyImages + "/" + imageCount, imageCount >= 4 && lazyImages == 0 ? 2 : 0,
                "Usar lazy en imágenes fuera del viewport.");
        add(r, "image_dims", ScoreCalculator.PERFORMANCE, "Dimensiones imágenes",
                imageCount > 0 && noDims > 0 ? AuditCheck.WARN : AuditCheck.PASS,
                noDims + "/" + imageCount + " sin width+height", 2,
                "Definir width/height para reducir layout shifts.");
        add(r, "dom_source", ScoreCalculator.PERFORMANCE, "DOM en HTML",
                f.elementCount > 1500 ? AuditCheck.WARN : AuditCheck.PASS,
                f.elementCount + " elemento(s)", 2, "Reducir DOM excesivo.");

        if (a.cacheKnown > 0) {
            add(r, "asset_cache", ScoreCalculator.PERFORMANCE, "Cache assets",
                    a.cached * 2 >= a.cacheKnown ? AuditCheck.PASS : AuditCheck.WARN,
                    a.cached + "/" + a.cacheKnown + " con cache prolongada", 2,
                    "Configurar caching para assets versionados.");
        } else {
            add(r, "asset_cache", ScoreCalculator.PERFORMANCE, "Cache assets",
                    AuditCheck.UNKNOWN, "No verificable", 2, "");
        }

        add(r, "cwv", ScoreCalculator.PERFORMANCE, "Core Web Vitals",
                AuditCheck.UNKNOWN, "LCP/INP/CLS reales requieren navegador/telemetría de campo", 4, "");
    }

    private static void addAccessibilityChecks(AuditReport r, HtmlFacts f) {
        String lang = f.htmlLang;
        add(r, "a11y_lang", ScoreCalculator.ACCESSIBILITY, "Idioma HTML",
                lang.isBlank() ? AuditCheck.FAIL : AuditCheck.PASS,
                lang.isBlank() ? "Falta lang" : "lang=\"" + lang + "\"", 3, "Añadir lang al elemento html.");

        add(r, "a11y_h1", ScoreCalculator.ACCESSIBILITY, "Estructura H1",
                f.headingCounts[1] == 1 ? AuditCheck.PASS : f.headingCounts[1] == 0 ? AuditCheck.FAIL : AuditCheck.WARN,
                f.headingCounts[1] + " H1", 3, "Revisar jerarquía semántica.");

        int images = 0, missingAlt = 0;
        for (TagFact t : f.tags) if ("img".equals(t.name)) { images++; if (!t.attrs.containsKey("alt")) missingAlt++; }
        add(r, "a11y_alt", ScoreCalculator.ACCESSIBILITY, "Texto alternativo",
                missingAlt == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                missingAlt + "/" + images + " sin alt", 4, "Añadir alt útil; alt=\"\" sólo en decorativas.");

        int buttonBad = 0, buttons = 0;
        Matcher bm = BUTTON.matcher(f.rawHtml);
        while (bm.find()) {
            buttons++;
            Map<String,String> attrs = attrs(bm.group(1));
            String text = stripTags(bm.group(2)).trim();
            if (text.isBlank() && attrs.getOrDefault("aria-label","").isBlank()
                    && attrs.getOrDefault("aria-labelledby","").isBlank()
                    && attrs.getOrDefault("title","").isBlank()) buttonBad++;
        }
        add(r, "a11y_buttons", ScoreCalculator.ACCESSIBILITY, "Botones accesibles",
                buttonBad == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                buttonBad + "/" + buttons + " sin nombre accesible", 3, "Etiquetar botones.");

        int emptyLinks = 0, links = 0;
        Matcher am = ANCHOR.matcher(f.rawHtml);
        while (am.find()) {
            links++;
            Map<String,String> attrs = attrs(am.group(1));
            String text = stripTags(am.group(2)).trim();
            boolean containsImgAlt = Pattern.compile("(?is)<img\\b[^>]*\\balt\\s*=\\s*([\"'])[^\"']+\\1").matcher(am.group(2)).find();
            if (text.isBlank() && attrs.getOrDefault("aria-label","").isBlank()
                    && attrs.getOrDefault("title","").isBlank() && !containsImgAlt) emptyLinks++;
        }
        add(r, "a11y_links", ScoreCalculator.ACCESSIBILITY, "Links accesibles",
                emptyLinks == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                emptyLinks + "/" + links + " sin nombre accesible", 3, "Añadir texto o aria-label.");

        Set<String> labelFor = new HashSet<>();
        for (TagFact t : f.tags) if ("label".equals(t.name) && !t.attr("for").isBlank()) labelFor.add(t.attr("for"));
        int inputs = 0, unlabeled = 0;
        for (TagFact t : f.tags) if ("input".equals(t.name)) {
            String type = t.attr("type").toLowerCase(Locale.ROOT);
            if (Arrays.asList("hidden","submit","button","reset","image").contains(type)) continue;
            inputs++;
            String id = t.attr("id");
            boolean labeled = !t.attr("aria-label").isBlank() || !t.attr("aria-labelledby").isBlank()
                    || (!id.isBlank() && labelFor.contains(id));
            if (!labeled) unlabeled++;
        }
        add(r, "a11y_labels", ScoreCalculator.ACCESSIBILITY, "Inputs con label",
                unlabeled == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                unlabeled + "/" + inputs + " sin label/aria", 3, "Asociar label o nombre accesible.");

        int duplicateIds = f.ids.size() - new HashSet<>(f.ids).size();
        add(r, "a11y_ids", ScoreCalculator.ACCESSIBILITY, "IDs únicos",
                duplicateIds == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                duplicateIds + " duplicado(s)", 2, "Eliminar IDs duplicados.");

        add(r, "a11y_tabindex", ScoreCalculator.ACCESSIBILITY, "tabindex positivo",
                f.positiveTabIndex == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                f.positiveTabIndex + " elemento(s)", 2, "Evitar tabindex > 0.");

        int frames = 0, noTitle = 0;
        for (TagFact t : f.tags) if ("iframe".equals(t.name)) { frames++; if (t.attr("title").isBlank()) noTitle++; }
        add(r, "a11y_iframe", ScoreCalculator.ACCESSIBILITY, "Iframes con title",
                noTitle == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                noTitle + "/" + frames + " sin title", 2, "Añadir title a iframes.");

        String viewport = f.meta("viewport").toLowerCase(Locale.ROOT);
        boolean zoomBlocked = viewport.contains("user-scalable=no")
                || Pattern.compile("maximum-scale\\s*=\\s*1(?:\\.0)?").matcher(viewport).find();
        add(r, "a11y_zoom", ScoreCalculator.ACCESSIBILITY, "Zoom móvil",
                viewport.isBlank() ? AuditCheck.UNKNOWN : zoomBlocked ? AuditCheck.WARN : AuditCheck.PASS,
                viewport.isBlank() ? "Sin viewport" : zoomBlocked ? "Zoom restringido" : "No restringido",
                2, "No impedir zoom del usuario.");

        boolean main = f.tagCounts.getOrDefault("main", 0) > 0 || f.roles.contains("main");
        boolean nav = f.tagCounts.getOrDefault("nav", 0) > 0 || f.roles.contains("navigation");
        add(r, "a11y_main", ScoreCalculator.ACCESSIBILITY, "Landmark main",
                main ? AuditCheck.PASS : AuditCheck.WARN, main ? "Detectado" : "No detectado", 2, "Añadir <main> o role=main.");
        add(r, "a11y_nav", ScoreCalculator.ACCESSIBILITY, "Landmark nav",
                nav ? AuditCheck.PASS : AuditCheck.INFO, nav ? "Detectado" : "No detectado", nav ? 1 : 0, "");

        add(r, "a11y_contrast", ScoreCalculator.ACCESSIBILITY, "Contraste visual",
                AuditCheck.UNKNOWN, "Requiere estilos computados/renderizado", 3, "");
    }

    private static void addPrivacyChecks(AuditReport r, FetchResult main, HtmlFacts f, String html, AssetBundle assets) {
        String combined = html + "\n" + assets.sampledJs;
        LinkedHashSet<String> trackers = detectTrackers(combined);
        r.trackers.addAll(trackers);
        add(r, "trackers", ScoreCalculator.PRIVACY, "Trackers detectados",
                trackers.isEmpty() ? AuditCheck.PASS : AuditCheck.WARN,
                trackers.isEmpty() ? "No detectados en muestra" : String.join(", ", trackers),
                3, "Revisar necesidad, consentimiento y política.");

        add(r, "third_party", ScoreCalculator.PRIVACY, "Hosts terceros",
                r.thirdPartyHostCount > 10 ? AuditCheck.WARN : AuditCheck.PASS,
                r.thirdPartyHostCount + " host(s)" + (r.thirdPartyHosts.isEmpty() ? "" : " · " + String.join(", ", r.thirdPartyHosts.subList(0, Math.min(5, r.thirdPartyHosts.size())))),
                2, "Reducir terceros innecesarios.");

        boolean privacyLink = hasLinkLike(f, "privacy", "privacidad", "datenschutz");
        boolean cookieLink = hasLinkLike(f, "cookie", "cookies");
        boolean relevant = !trackers.isEmpty() || !main.setCookies.isEmpty() || f.tagCounts.getOrDefault("form",0) > 0;
        add(r, "privacy_policy", ScoreCalculator.PRIVACY, "Política privacidad",
                privacyLink ? AuditCheck.PASS : relevant ? AuditCheck.WARN : AuditCheck.INFO,
                privacyLink ? "Enlace detectado" : "No detectado",
                relevant || privacyLink ? 2 : 0, "Añadir/revisar política si se tratan datos personales.");
        add(r, "cookie_policy", ScoreCalculator.PRIVACY, "Política cookies",
                cookieLink ? AuditCheck.PASS : (!trackers.isEmpty() || !main.setCookies.isEmpty()) ? AuditCheck.WARN : AuditCheck.INFO,
                cookieLink ? "Enlace detectado" : "No detectado",
                (!trackers.isEmpty() || !main.setCookies.isEmpty() || cookieLink) ? 1 : 0, "Revisar política/consentimiento de cookies.");

        int noSecure = 0, noHttpOnly = 0, noSameSite = 0;
        for (String cookie : main.setCookies) {
            String low = cookie.toLowerCase(Locale.ROOT);
            if (r.finalUrl.startsWith("https://") && !low.contains("; secure")) noSecure++;
            if (!low.contains("; httponly")) noHttpOnly++;
            if (!low.contains("samesite=")) noSameSite++;
        }
        if (!main.setCookies.isEmpty()) {
            add(r, "cookie_secure", ScoreCalculator.PRIVACY, "Cookie Secure",
                    noSecure == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                    noSecure + "/" + main.setCookies.size() + " sin Secure", 3, "Marcar cookies sensibles Secure.");
            add(r, "cookie_httponly", ScoreCalculator.PRIVACY, "Cookie HttpOnly",
                    noHttpOnly == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                    noHttpOnly + "/" + main.setCookies.size() + " sin HttpOnly", 2, "Usar HttpOnly cuando JS no la necesite.");
            add(r, "cookie_samesite", ScoreCalculator.PRIVACY, "Cookie SameSite",
                    noSameSite == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                    noSameSite + "/" + main.setCookies.size() + " sin SameSite", 2, "Definir SameSite según flujo.");
        } else {
            addInfo(r, "cookies_first", ScoreCalculator.PRIVACY, "Cookies primera carga", "No se observó Set-Cookie.");
        }

        String low = combined.toLowerCase(Locale.ROOT);
        List<String> apis = new ArrayList<>();
        if (low.contains("geolocation.")) apis.add("geolocation");
        if (low.contains("getusermedia")) apis.add("cámara/micrófono");
        if (low.contains("navigator.clipboard")) apis.add("clipboard");
        if (low.contains("notification.requestpermission")) apis.add("notificaciones");
        addInfo(r, "sensitive_apis", ScoreCalculator.PRIVACY, "APIs sensibles", apis.isEmpty() ? "No detectadas en muestra" : String.join(", ", apis));
    }

    private static void addSecurityChecks(AuditReport r, FetchResult main, HtmlFacts f, String html, AssetBundle assets, boolean quick) {
        Map<String,String> h = main.headers;
        String hsts = h.getOrDefault("strict-transport-security", "");
        boolean https = r.finalUrl.startsWith("https://");
        if (https) {
            int age = 0;
            Matcher m = Pattern.compile("(?i)max-age\\s*=\\s*(\\d+)").matcher(hsts);
            if (m.find()) try { age = Integer.parseInt(m.group(1)); } catch (Exception ignored) {}
            add(r, "hsts", ScoreCalculator.SECURITY, "HSTS",
                    hsts.isBlank() ? AuditCheck.FAIL : age >= 15_552_000 ? AuditCheck.PASS : AuditCheck.WARN,
                    hsts.isBlank() ? "Ausente" : truncate(hsts, 70), 4,
                    "Usar Strict-Transport-Security con max-age suficiente.");
        }

        String csp = h.getOrDefault("content-security-policy", "");
        if (csp.isBlank()) {
            add(r, "csp", ScoreCalculator.SECURITY, "Content-Security-Policy",
                    AuditCheck.FAIL, "Ausente", 5, "Implementar CSP progresivamente.");
        } else {
            String low = csp.toLowerCase(Locale.ROOT);
            List<String> weak = new ArrayList<>();
            if (low.contains("'unsafe-eval'")) weak.add("unsafe-eval");
            if (low.contains("'unsafe-inline'")) weak.add("unsafe-inline");
            if (Pattern.compile("(?<![\\w.-])\\*(?![\\w.-])").matcher(low).find()) weak.add("*");
            add(r, "csp", ScoreCalculator.SECURITY, "Content-Security-Policy",
                    weak.isEmpty() ? AuditCheck.PASS : AuditCheck.WARN,
                    weak.isEmpty() ? "Presente" : "Débil: " + String.join(", ", weak), 5, "Endurecer CSP.");
        }

        boolean nosniff = "nosniff".equalsIgnoreCase(h.getOrDefault("x-content-type-options", ""));
        add(r, "nosniff", ScoreCalculator.SECURITY, "X-Content-Type-Options",
                nosniff ? AuditCheck.PASS : AuditCheck.FAIL,
                nosniff ? "nosniff" : "Ausente", 3, "Usar X-Content-Type-Options: nosniff.");

        String rp = h.getOrDefault("referrer-policy", "");
        add(r, "referrer", ScoreCalculator.SECURITY, "Referrer-Policy",
                rp.isBlank() ? AuditCheck.WARN : AuditCheck.PASS,
                rp.isBlank() ? "Ausente" : rp, 2, "Definir Referrer-Policy.");

        String pp = h.getOrDefault("permissions-policy", "");
        add(r, "permissions_policy", ScoreCalculator.SECURITY, "Permissions-Policy",
                pp.isBlank() ? AuditCheck.WARN : AuditCheck.PASS,
                pp.isBlank() ? "Ausente" : truncate(pp, 70), 2, "Limitar APIs del navegador no usadas.");

        boolean frame = !h.getOrDefault("x-frame-options","").isBlank() || csp.toLowerCase(Locale.ROOT).contains("frame-ancestors");
        add(r, "clickjacking", ScoreCalculator.SECURITY, "Clickjacking",
                frame ? AuditCheck.PASS : AuditCheck.FAIL,
                frame ? "Protección detectada" : "Sin X-Frame-Options ni frame-ancestors", 4,
                "Usar CSP frame-ancestors o X-Frame-Options.");

        int mixed = 0, externalActive = 0, sri = 0;
        for (TagFact t : f.tags) {
            String raw = "";
            boolean active = false;
            if ("script".equals(t.name)) { raw = t.attr("src"); active = true; }
            else if ("link".equals(t.name) && t.attr("rel").toLowerCase(Locale.ROOT).contains("stylesheet")) { raw = t.attr("href"); active = true; }
            else if ("img".equals(t.name) || "iframe".equals(t.name)) raw = t.attr("src");
            if (raw.startsWith("http://") && https) mixed++;
            if (active && !raw.isBlank()) {
                String u = resolve(r.finalUrl, raw);
                if (!sameSite(r.finalUrl, u)) {
                    externalActive++;
                    if (!t.attr("integrity").isBlank()) sri++;
                }
            }
        }
        add(r, "mixed", ScoreCalculator.SECURITY, "Contenido mixto",
                mixed == 0 ? AuditCheck.PASS : AuditCheck.FAIL,
                mixed + " subrecurso(s) HTTP", 4, "Migrar subrecursos a HTTPS.");
        add(r, "sri", ScoreCalculator.SECURITY, "SRI terceros",
                externalActive == 0 ? AuditCheck.INFO : sri == externalActive ? AuditCheck.PASS : AuditCheck.INFO,
                sri + "/" + externalActive + " JS/CSS externos con integrity", sri == externalActive && externalActive > 0 ? 1 : 0,
                "Usar SRI en recursos estáticos externos/versionados cuando sea compatible.");

        String powered = h.getOrDefault("x-powered-by", "");
        add(r, "powered", ScoreCalculator.SECURITY, "X-Powered-By",
                powered.isBlank() ? AuditCheck.PASS : AuditCheck.WARN,
                powered.isBlank() ? "No expuesto" : powered, 1, "Quitar X-Powered-By si no es necesario.");
        String server = h.getOrDefault("server","");
        boolean versionLeak = Pattern.compile("\\d+\\.\\d+").matcher(server).find();
        add(r, "server_version", ScoreCalculator.SECURITY, "Server identificado",
                versionLeak ? AuditCheck.WARN : AuditCheck.INFO,
                server.isBlank() ? "No expuesto" : server, versionLeak ? 1 : 0, "Ocultar versión exacta cuando sea posible.");

        try {
            Map<String,String> hdr = new HashMap<>();
            hdr.put("Origin", "https://webamo.invalid");
            FetchResult cors = fetch(r.finalUrl, "GET", 1024, SMALL_TIMEOUT, hdr);
            String acao = cors.headers.getOrDefault("access-control-allow-origin","");
            String acac = cors.headers.getOrDefault("access-control-allow-credentials","");
            if ("https://webamo.invalid".equalsIgnoreCase(acao) && "true".equalsIgnoreCase(acac)) {
                add(r, "cors", ScoreCalculator.SECURITY, "CORS", AuditCheck.FAIL,
                        "Refleja origen externo + credentials=true", 5, "Restringir CORS a allowlist explícita.");
            } else if ("*".equals(acao)) {
                add(r, "cors", ScoreCalculator.SECURITY, "CORS", AuditCheck.WARN,
                        "Access-Control-Allow-Origin: *", 3, "Confirmar que sólo aplica a recursos públicos.");
            } else {
                add(r, "cors", ScoreCalculator.SECURITY, "CORS", AuditCheck.PASS,
                        acao.isBlank() ? "Sin permiso cross-origin global detectable" : truncate(acao, 60), 2, "");
            }
        } catch (Exception e) {
            add(r, "cors", ScoreCalculator.SECURITY, "CORS", AuditCheck.UNKNOWN, "No verificable", 3, "");
        }

        String combined = html + "\n" + assets.sampledJs;
        List<String> secrets = secretTypes(combined);
        add(r, "secrets", ScoreCalculator.SECURITY, "Secretos aparentes frontend",
                secrets.isEmpty() ? AuditCheck.PASS : AuditCheck.FAIL,
                secrets.isEmpty() ? "No detectados en muestra" : String.join(", ", secrets),
                5, "Rotar/revocar secretos reales y retirarlos del frontend.");

        Matcher cm = COMMENT.matcher(html);
        boolean debug = false;
        while (cm.find() && !debug) {
            String x = cm.group(1).toLowerCase(Locale.ROOT);
            debug = x.contains("todo") || x.contains("fixme") || x.contains("debug") || x.contains("localhost");
        }
        add(r, "debug", ScoreCalculator.SECURITY, "Indicadores debug/dev",
                debug ? AuditCheck.WARN : AuditCheck.PASS,
                debug ? "Comentarios/señales detectadas" : "No detectados", 1, "Revisar referencias de desarrollo.");

        try {
            String secUrl = origin(new URL(r.finalUrl)) + "/.well-known/security.txt";
            FetchResult sec = fetch(secUrl, "GET", 128 * 1024, SMALL_TIMEOUT, null);
            String text = decode(sec.body, sec.headers.get("content-type"));
            boolean valid = sec.status == 200
                    && Pattern.compile("(?im)^Contact:\\s*\\S+").matcher(text).find()
                    && Pattern.compile("(?im)^Expires:\\s*\\S+").matcher(text).find();
            add(r, "security_txt", ScoreCalculator.SECURITY, "security.txt",
                    valid ? AuditCheck.PASS : sec.status == 200 ? AuditCheck.WARN : AuditCheck.INFO,
                    sec.status == 200 ? (valid ? "Presente · Contact + Expires" : "Presente pero incompleto") : "No encontrado",
                    valid ? 1 : 0, "Completar formato RFC 9116.");
        } catch (Exception e) {
            addInfo(r, "security_txt", ScoreCalculator.SECURITY, "security.txt", "No verificable.");
        }

        if (quick) add(r, "exposure", ScoreCalculator.SECURITY, "Exposición pública conservadora",
                AuditCheck.UNKNOWN, "Omitida en modo rápido", 4, "");
        else addExposureProbes(r);
    }

    private static void addExposureProbes(AuditReport r) {
        String[] paths = {"/.env", "/.git/config", "/backup.zip", "/config.php~"};
        int exposed = 0;
        List<String> names = new ArrayList<>();
        try {
            String origin = origin(new URL(r.finalUrl));
            for (String path : paths) {
                FetchResult f = fetch(origin + path, "GET", 32 * 1024, 3_500, null);
                if (f.status != 200) continue;
                String t = decode(f.body, f.headers.get("content-type"));
                boolean confirmed = false;
                if ("/.env".equals(path)) confirmed = Pattern.compile("(?m)^[A-Z][A-Z0-9_]{2,}\\s*=").matcher(t).find();
                else if ("/.git/config".equals(path)) confirmed = t.contains("[core]") && t.contains("repositoryformatversion");
                else if ("/backup.zip".equals(path)) confirmed = f.body.length >= 4 && f.body[0] == 'P' && f.body[1] == 'K';
                else if ("/config.php~".equals(path)) confirmed = t.contains("<?php");
                if (confirmed) { exposed++; names.add(path); }
            }
            add(r, "exposure", ScoreCalculator.SECURITY, "Exposición pública conservadora",
                    exposed > 0 ? AuditCheck.FAIL : AuditCheck.PASS,
                    exposed > 0 ? String.join(", ", names) : "No confirmada en rutas conservadoras",
                    4, "Retirar archivos sensibles públicos y rotar secretos si corresponde.");
        } catch (Exception e) {
            add(r, "exposure", ScoreCalculator.SECURITY, "Exposición pública conservadora",
                    AuditCheck.UNKNOWN, "No verificable", 4, "");
        }
    }

    private static void addTechnicalAndAiChecks(AuditReport r, FetchResult main, HtmlFacts f, String html,
                                                ResourceBundle resources, AssetBundle assets, boolean quick) {
        addInfo(r, "platform", ScoreCalculator.TECHNICAL, "Plataforma", r.platform);
        addInfo(r, "stack", ScoreCalculator.TECHNICAL, "Framework/stack", r.stack);
        addInfo(r, "render", ScoreCalculator.TECHNICAL, "Render", r.renderMode);
        addInfo(r, "cdn", ScoreCalculator.TECHNICAL, "CDN/proxy", r.cdn);
        addInfo(r, "server", ScoreCalculator.TECHNICAL, "Server", r.server.isBlank() ? "No expuesto" : r.server);

        String cache = main.headers.getOrDefault("cache-control", "");
        addInfo(r, "cache_html", ScoreCalculator.TECHNICAL, "Cache-Control HTML", cache.isBlank() ? "No declarado" : cache);
        addInfo(r, "etag", ScoreCalculator.TECHNICAL, "ETag / Last-Modified",
                main.headers.containsKey("etag") ? "ETag" : main.headers.containsKey("last-modified") ? "Last-Modified" : "No detectado");

        String low = (html + "\n" + assets.sampledJs).toLowerCase(Locale.ROOT);
        List<String> libraries = new ArrayList<>();
        if (low.contains("react") || low.contains("__next_data__")) libraries.add("React");
        if (low.contains("vue")) libraries.add("Vue");
        if (low.contains("jquery")) libraries.add("jQuery");
        if (low.contains("bootstrap")) libraries.add("Bootstrap");
        if (low.contains("tailwind")) libraries.add("Tailwind");
        addInfo(r, "libs", ScoreCalculator.TECHNICAL, "Librerías detectadas",
                libraries.isEmpty() ? "No identificadas en muestra" : String.join(", ", libraries));

        Matcher um = URL_IN_TEXT.matcher(low);
        Set<String> found = new LinkedHashSet<>();
        while (um.find() && found.size() < 20) {
            String u = um.group();
            if (u.contains("/api/") || u.contains("graphql") || u.contains("/v1/") || u.contains("/v2/")) found.add(u);
        }
        addInfo(r, "api_visible", ScoreCalculator.TECHNICAL, "Endpoints API visibles", found.size() + " detectado(s)");

        boolean manifest = f.linksByRel("manifest") > 0;
        boolean sw = low.contains("serviceworker.register") || low.contains("navigator.serviceworker");
        addInfo(r, "pwa", ScoreCalculator.TECHNICAL, "PWA",
                "manifest=" + (manifest ? "sí" : "no") + " · service worker=" + (sw ? "señal" : "no detectado"));
        addInfo(r, "theme", ScoreCalculator.TECHNICAL, "Theme color",
                f.meta("theme-color").isBlank() ? "No declarado" : f.meta("theme-color"));

        if (resources.robots.status == 200) {
            List<String> blocked = new ArrayList<>();
            for (String bot : new String[]{"OAI-SearchBot","GPTBot","ClaudeBot","PerplexityBot"}) {
                if (robotsBlocks(resources.robotsText, bot)) blocked.add(bot);
            }
            addInfo(r, "ai_robots", ScoreCalculator.TECHNICAL, "Crawlers IA",
                    blocked.isEmpty() ? "Sin bloqueos explícitos detectados" : "Bloqueados: " + String.join(", ", blocked));
        }
        try {
            String origin = origin(new URL(r.finalUrl));
            FetchResult llms = fetch(origin + "/llms.txt", "GET", 64 * 1024, SMALL_TIMEOUT, null);
            addInfo(r, "llms", ScoreCalculator.TECHNICAL, "llms.txt", llms.status == 200 ? "Presente" : "No encontrado (opcional/propuesta)");
        } catch (Exception ignored) {}

        add(r, "browser_layer", ScoreCalculator.TECHNICAL, "Capa navegador",
                AuditCheck.UNKNOWN, "WebAMO 0.1.1 no ejecuta JS/render completo; CWV y contraste quedan N/V", 0, "");
    }

    private static void addMiniCrawlChecks(AuditReport r, HtmlFacts f, ResourceBundle resources) {
        List<String> links = new ArrayList<>();
        for (TagFact t : f.tags) if ("a".equals(t.name)) {
            String href = t.attr("href");
            if (href.isBlank() || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")
                    || href.startsWith("javascript:")) continue;
            String u = resolve(r.finalUrl, href);
            if (sameSite(r.finalUrl, u) && !links.contains(u)) links.add(u);
            if (links.size() >= MAX_CRAWL) break;
        }
        if (links.isEmpty()) {
            addInfo(r, "crawl", ScoreCalculator.SEO, "Mini-crawl", "Sin enlaces internos suficientes.");
            return;
        }

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(4, links.size()));
        List<Future<CrawlFact>> futures = new ArrayList<>();
        for (String link : links) futures.add(pool.submit(() -> crawlOne(link)));
        List<CrawlFact> pages = new ArrayList<>();
        for (Future<CrawlFact> future : futures) try { pages.add(future.get()); } catch (Exception ignored) {}
        pool.shutdownNow();

        r.crawlPages = pages.size();
        int errors = 0, missingH1 = 0, missingCanonical = 0, noindex = 0;
        Map<String,Integer> titles = new HashMap<>();
        Map<String,Integer> descs = new HashMap<>();
        for (CrawlFact p : pages) {
            if (p.status == 0 || p.status >= 400) errors++;
            if (p.h1 == 0) missingH1++;
            if (p.canonical.isBlank()) missingCanonical++;
            if (p.noindex) noindex++;
            if (!p.title.isBlank()) titles.put(p.title, titles.getOrDefault(p.title,0)+1);
            if (!p.description.isBlank()) descs.put(p.description, descs.getOrDefault(p.description,0)+1);
        }
        int dupTitles = 0, dupDescs = 0;
        for (int n : titles.values()) if (n > 1) dupTitles++;
        for (int n : descs.values()) if (n > 1) dupDescs++;

        add(r, "crawl", ScoreCalculator.SEO, "Mini-crawl",
                errors == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                pages.size() + " página(s) · " + errors + " error(es)", 3, "Revisar errores internos.");
        add(r, "crawl_titles", ScoreCalculator.SEO, "Titles duplicados",
                dupTitles == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                dupTitles + " grupo(s)", 2, "Hacer titles únicos.");
        add(r, "crawl_desc", ScoreCalculator.SEO, "Descriptions duplicadas",
                dupDescs == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                dupDescs + " grupo(s)", 2, "Hacer descriptions únicas.");
        add(r, "crawl_h1", ScoreCalculator.SEO, "H1 entre páginas",
                missingH1 == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                missingH1 + "/" + pages.size() + " sin H1", 2, "Añadir H1 donde corresponda.");
        add(r, "crawl_canon", ScoreCalculator.SEO, "Canonical entre páginas",
                missingCanonical == 0 ? AuditCheck.PASS : AuditCheck.WARN,
                missingCanonical + "/" + pages.size() + " sin canonical", 2, "Añadir canonical.");
        addInfo(r, "crawl_noindex", ScoreCalculator.SEO, "Noindex entre páginas", noindex + "/" + pages.size());
    }

    private static CrawlFact crawlOne(String url) {
        FetchResult f = fetch(url, "GET", 512 * 1024, SMALL_TIMEOUT, null);
        String html = decode(f.body, f.headers.get("content-type"));
        HtmlFacts p = parseHtml(html, f.finalUrl);
        return new CrawlFact(url, f.status, p.title, p.meta("description"), p.canonical,
                p.headingCounts[1], p.meta("robots").toLowerCase(Locale.ROOT).contains("noindex"));
    }

    private static void fingerprint(AuditReport r, FetchResult main, String html, HtmlFacts f) {
        String host = host(r.finalUrl).toLowerCase(Locale.ROOT);
        String low = html.toLowerCase(Locale.ROOT);
        String server = main.headers.getOrDefault("server","").toLowerCase(Locale.ROOT);

        if (host.endsWith(".netlify.app") || main.headers.containsKey("x-nf-request-id")) { r.platform = "Netlify"; r.cdn = "Netlify CDN"; }
        else if (host.endsWith(".vercel.app") || main.headers.containsKey("x-vercel-id")) { r.platform = "Vercel"; r.cdn = "Vercel Edge"; }
        else if (host.endsWith(".pages.dev") || "cloudflare".equals(server) || main.headers.containsKey("cf-ray")) { r.platform = "Cloudflare"; r.cdn = "Cloudflare"; }
        else if (host.endsWith(".github.io")) r.platform = "GitHub Pages";
        else r.platform = "Hosting propio/otro";

        if (main.headers.containsKey("x-amz-cf-id")) r.cdn = "AWS CloudFront";
        else if (main.headers.getOrDefault("via","").toLowerCase(Locale.ROOT).contains("fastly")) r.cdn = "Fastly";

        if (low.contains("__next_data__") || low.contains("/_next/")) r.stack = "Next.js / React";
        else if (low.contains("__nuxt__") || low.contains("/_nuxt/")) r.stack = "Nuxt / Vue";
        else if (low.contains("wp-content") || f.meta("generator").toLowerCase(Locale.ROOT).contains("wordpress")) r.stack = "WordPress";
        else if (low.contains("cdn.shopify.com") || f.meta("generator").toLowerCase(Locale.ROOT).contains("shopify")) r.stack = "Shopify";
        else if (low.contains("webflow")) r.stack = "Webflow";
        else if (low.contains("wixstatic.com")) r.stack = "Wix";
        else if (low.contains("astro-island")) r.stack = "Astro";
        else if (low.contains("/_app/immutable/")) r.stack = "SvelteKit";
        else if (low.contains("ng-version=")) r.stack = "Angular";
        else if (low.contains("id=\"root\"") || low.contains("id='root'")) r.stack = "SPA JS (probable)";
        else r.stack = "HTML/JS no identificado";

        String visible = stripTags(removeScriptsStyles(html));
        r.renderMode = visible.length() < 220 && f.tagCounts.getOrDefault("script",0) > 0
                ? "SPA / HTML inicial pobre"
                : visible.length() > 900 ? "SSR/SSG/MPA con contenido HTML" : "Mixto / HTML moderado";
    }

    private static FetchResult fetch(String rawUrl, String method, int limit, int timeout, Map<String,String> extraHeaders) {
        long started = System.nanoTime();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(rawUrl).openConnection();
            c.setInstanceFollowRedirects(true);
            c.setConnectTimeout(timeout);
            c.setReadTimeout(timeout);
            c.setRequestMethod(method);
            c.setRequestProperty("User-Agent", UA);
            c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            if (extraHeaders != null) for (Map.Entry<String,String> e : extraHeaders.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
            int status = c.getResponseCode();
            Map<String,String> headers = headers(c);
            List<String> setCookies = headerValues(c, "Set-Cookie");
            byte[] body = new byte[0];
            if (!"HEAD".equals(method) && limit > 0) {
                InputStream stream = status >= 400 ? c.getErrorStream() : c.getInputStream();
                body = readLimited(stream, limit);
            }
            long ms = Math.max(1, (System.nanoTime() - started) / 1_000_000L);
            return new FetchResult(rawUrl, c.getURL().toString(), status, headers, body, ms, "", setCookies);
        } catch (Exception e) {
            long ms = Math.max(1, (System.nanoTime() - started) / 1_000_000L);
            return new FetchResult(rawUrl, rawUrl, 0, new LinkedHashMap<>(), new byte[0], ms, shortError(e), new ArrayList<>());
        } finally {
            if (c != null) c.disconnect();
        }
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

    private static Map<String,String> headers(HttpURLConnection c) {
        LinkedHashMap<String,String> out = new LinkedHashMap<>();
        for (Map.Entry<String,List<String>> e : c.getHeaderFields().entrySet()) {
            if (e.getKey() == null || e.getValue() == null || e.getValue().isEmpty()) continue;
            out.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().get(0));
        }
        return out;
    }

    private static List<String> headerValues(HttpURLConnection c, String name) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String,List<String>> e : c.getHeaderFields().entrySet()) {
            if (e.getKey() != null && name.equalsIgnoreCase(e.getKey()) && e.getValue() != null) out.addAll(e.getValue());
        }
        return out;
    }

    private static List<String> cookieNames(List<String> raw) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String cookie : raw) {
            int eq = cookie.indexOf('=');
            String name = (eq > 0 ? cookie.substring(0, eq) : cookie).trim();
            if (!name.isBlank()) out.add(name);
        }
        return new ArrayList<>(out);
    }

    private static String decode(byte[] body, String contentType) {
        Charset charset = StandardCharsets.UTF_8;
        if (contentType != null) {
            Matcher m = Pattern.compile("(?i)charset=([^;\\s]+)").matcher(contentType);
            if (m.find()) try { charset = Charset.forName(m.group(1).replace("\"","").replace("'","")); } catch (Exception ignored) {}
        }
        return new String(body, charset);
    }

    private static HtmlFacts parseHtml(String html, String baseUrl) {
        HtmlFacts f = new HtmlFacts();
        f.rawHtml = html == null ? "" : html;
        Matcher title = TITLE.matcher(f.rawHtml);
        if (title.find()) f.title = stripTags(title.group(1)).trim();

        Matcher tm = TAG.matcher(f.rawHtml);
        while (tm.find()) {
            String name = tm.group(1).toLowerCase(Locale.ROOT);
            Map<String,String> attrs = attrs(tm.group(2));
            TagFact t = new TagFact(name, attrs);
            f.tags.add(t);
            f.elementCount++;
            f.tagCounts.put(name, f.tagCounts.getOrDefault(name,0)+1);
            String id = t.attr("id"); if (!id.isBlank()) f.ids.add(id);
            String role = t.attr("role"); if (!role.isBlank()) f.roles.addAll(Arrays.asList(role.toLowerCase(Locale.ROOT).split("\\s+")));
            String tabindex = t.attr("tabindex");
            if (!tabindex.isBlank()) try { if (Integer.parseInt(tabindex) > 0) f.positiveTabIndex++; } catch (Exception ignored) {}
            if ("html".equals(name)) f.htmlLang = t.attr("lang");
            if ("meta".equals(name)) {
                String key = !t.attr("name").isBlank() ? t.attr("name") : t.attr("property");
                if (!key.isBlank()) {
                    if (!t.attr("name").isBlank()) f.metas.put(key.toLowerCase(Locale.ROOT), t.attr("content"));
                    else f.metaProperties.put(key.toLowerCase(Locale.ROOT), t.attr("content"));
                }
            }
            if ("link".equals(name) && t.attr("rel").toLowerCase(Locale.ROOT).contains("canonical")) f.canonical = t.attr("href");
        }

        Matcher hm = H.matcher(f.rawHtml);
        while (hm.find()) {
            int level = Integer.parseInt(hm.group(1));
            f.headingCounts[level]++;
            f.headingSequence.add(level);
        }

        Matcher jm = JSON_LD.matcher(f.rawHtml);
        while (jm.find()) {
            String body = jm.group(4).trim();
            if ((body.startsWith("{") && body.endsWith("}")) || (body.startsWith("[") && body.endsWith("]"))) f.validJsonLdBlocks++;
        }
        return f;
    }

    private static Map<String,String> attrs(String raw) {
        LinkedHashMap<String,String> out = new LinkedHashMap<>();
        Matcher m = ATTR.matcher(raw == null ? "" : raw);
        while (m.find()) {
            String value = m.group(3) != null ? m.group(3) : m.group(4) != null ? m.group(4) : "";
            out.put(m.group(1).toLowerCase(Locale.ROOT), value.trim());
        }
        for (String flag : new String[]{"async","defer","autoplay","muted","controls","required","disabled"}) {
            if (!out.containsKey(flag) && Pattern.compile("(?i)(?:^|\\s)" + flag + "(?:\\s|$|=)").matcher(raw == null ? "" : raw).find()) out.put(flag, flag);
        }
        return out;
    }

    private static LinkedHashSet<String> detectTrackers(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        LinkedHashMap<String,String[]> signatures = new LinkedHashMap<>();
        signatures.put("Google Analytics", new String[]{"google-analytics.com","googletagmanager.com/gtag","gtag("});
        signatures.put("Google Tag Manager", new String[]{"googletagmanager.com/gtm","gtm.js"});
        signatures.put("Google Ads / DoubleClick", new String[]{"doubleclick.net","googleadservices.com"});
        signatures.put("Meta Pixel", new String[]{"connect.facebook.net","fbq("});
        signatures.put("Hotjar", new String[]{"hotjar.com","hj("});
        signatures.put("Microsoft Clarity", new String[]{"clarity.ms/tag","clarity("});
        signatures.put("TikTok Pixel", new String[]{"analytics.tiktok.com","ttq."});
        signatures.put("LinkedIn Insight", new String[]{"snap.licdn.com","linkedin.com/insight"});
        signatures.put("Matomo", new String[]{"matomo.js","piwik.js"});
        signatures.put("Plausible", new String[]{"plausible.io/js"});
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (Map.Entry<String,String[]> e : signatures.entrySet()) {
            for (String s : e.getValue()) if (low.contains(s)) { out.add(e.getKey()); break; }
        }
        return out;
    }

    private static List<String> secretTypes(String text) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").matcher(text).find()) out.add("private-key");
        if (Pattern.compile("\\bsk_live_[A-Za-z0-9]{16,}\\b").matcher(text).find()) out.add("stripe-live-secret");
        if (Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{30,}\\b").matcher(text).find()) out.add("github-token");
        if (Pattern.compile("\\bxox[baprs]-[A-Za-z0-9-]{20,}\\b").matcher(text).find()) out.add("slack-token");
        if (Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b").matcher(text).find()) out.add("aws-access-key-id");
        return new ArrayList<>(out);
    }

    private static boolean hasLinkLike(HtmlFacts f, String... needles) {
        for (TagFact t : f.tags) if ("a".equals(t.name)) {
            String href = t.attr("href").toLowerCase(Locale.ROOT);
            for (String n : needles) if (href.contains(n)) return true;
        }
        return false;
    }

    private static boolean robotsBlocks(String text, String bot) {
        boolean applies = false;
        for (String line : text.split("\\r?\\n")) {
            String clean = line.split("#",2)[0].trim();
            if (clean.toLowerCase(Locale.ROOT).startsWith("user-agent:")) {
                String current = clean.substring(clean.indexOf(':')+1).trim();
                applies = "*".equals(current) || bot.equalsIgnoreCase(current);
            } else if (applies && clean.toLowerCase(Locale.ROOT).startsWith("disallow:")) {
                String path = clean.substring(clean.indexOf(':')+1).trim();
                if ("/".equals(path)) return true;
            }
        }
        return false;
    }

    private static String normalizeUrl(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) throw new IllegalArgumentException("Escribí una URL.");
        if (!value.matches("(?i)^https?://.*")) value = "https://" + value;
        try {
            URL u = new URL(value);
            if (u.getHost() == null || u.getHost().isBlank()) throw new Exception();
            return u.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException("La URL no es válida.");
        }
    }

    private static String resolve(String base, String raw) {
        try { return new URL(new URL(base), raw).toString(); } catch (Exception e) { return raw; }
    }

    private static String origin(URL u) {
        int port = u.getPort();
        return u.getProtocol() + "://" + u.getHost() + (port > 0 && port != u.getDefaultPort() ? ":" + port : "");
    }

    private static String host(String url) {
        try { return new URL(url).getHost().toLowerCase(Locale.ROOT); } catch (Exception e) { return ""; }
    }

    private static boolean sameSite(String a, String b) {
        String ha = host(a), hb = host(b);
        if (ha.startsWith("www.")) ha = ha.substring(4);
        if (hb.startsWith("www.")) hb = hb.substring(4);
        return !ha.isBlank() && ha.equals(hb);
    }

    private static String stripTags(String text) {
        return text == null ? "" : text.replaceAll("(?is)<[^>]+>", " ").replace("&nbsp;"," ").replaceAll("\\s+"," ");
    }

    private static String removeScriptsStyles(String html) {
        return html.replaceAll("(?is)<script\\b.*?</script>", " ").replaceAll("(?is)<style\\b.*?</style>", " ");
    }

    private static int count(Pattern p, String text) {
        int n = 0; Matcher m = p.matcher(text); while (m.find()) n++; return n;
    }

    private static String truncate(String text, int max) {
        if (text == null) return "";
        String clean = text.replaceAll("\\s+"," ").trim();
        return clean.length() <= max ? clean : clean.substring(0, Math.max(0,max-1)) + "…";
    }

    private static String humanBytes(long n) {
        if (n < 0) return "N/V";
        if (n < 1024) return n + " B";
        if (n < 1024L * 1024) return Math.round(n / 1024f) + " KB";
        return String.format(Locale.ROOT, "%.2f MB", n / (1024f * 1024f));
    }

    private static String shortError(Throwable e) {
        String msg = e.getMessage();
        return e.getClass().getSimpleName() + (msg == null || msg.isBlank() ? "" : ": " + truncate(msg, 80));
    }

    private static void add(AuditReport r, String id, String category, String label, String status,
                            String detail, int weight, String recommendation) {
        r.checks.add(AuditCheck.of(id, category, label, status, detail, weight, recommendation));
    }

    private static void addInfo(AuditReport r, String id, String category, String label, String detail) {
        r.checks.add(AuditCheck.info(id, category, label, detail));
    }

    private static final class FetchResult {
        final String url, finalUrl;
        final int status;
        final Map<String,String> headers;
        final byte[] body;
        final long elapsedMs;
        final String error;
        final List<String> setCookies;
        FetchResult(String url, String finalUrl, int status, Map<String,String> headers, byte[] body,
                    long elapsedMs, String error, List<String> setCookies) {
            this.url=url; this.finalUrl=finalUrl; this.status=status; this.headers=headers; this.body=body;
            this.elapsedMs=elapsedMs; this.error=error; this.setCookies=setCookies;
        }
        static FetchResult error(String url, String error) {
            return new FetchResult(url,url,0,new LinkedHashMap<>(),new byte[0],0,error,new ArrayList<>());
        }
    }

    private static final class TagFact {
        final String name;
        final Map<String,String> attrs;
        TagFact(String name, Map<String,String> attrs) { this.name=name; this.attrs=attrs; }
        String attr(String k) { return attrs.getOrDefault(k.toLowerCase(Locale.ROOT),""); }
    }

    private static final class HtmlFacts {
        String rawHtml="", title="", canonical="", htmlLang="";
        int elementCount, positiveTabIndex, validJsonLdBlocks;
        int[] headingCounts = new int[7];
        final List<Integer> headingSequence = new ArrayList<>();
        final List<TagFact> tags = new ArrayList<>();
        final List<String> ids = new ArrayList<>();
        final List<String> roles = new ArrayList<>();
        final Map<String,Integer> tagCounts = new HashMap<>();
        final Map<String,String> metas = new HashMap<>();
        final Map<String,String> metaProperties = new HashMap<>();
        String meta(String key) { return metas.getOrDefault(key.toLowerCase(Locale.ROOT),""); }
        String metaProperty(String key) { return metaProperties.getOrDefault(key.toLowerCase(Locale.ROOT),""); }
        int linksByRel(String rel) {
            int n=0; for (TagFact t: tags) if ("link".equals(t.name) && t.attr("rel").toLowerCase(Locale.ROOT).contains(rel.toLowerCase(Locale.ROOT))) n++; return n;
        }
    }

    private static final class ResourceBundle {
        FetchResult robots = FetchResult.error("", "");
        FetchResult sitemap = FetchResult.error("", "");
        String robotsText="", sitemapText="", sitemapUrl="";
    }

    private static final class AssetFact {
        final String url, kind, sampleText;
        final int status;
        final long size;
        final boolean cacheKnown, cacheLong;
        AssetFact(String url, String kind, int status, long size, boolean cacheKnown, boolean cacheLong, String sampleText) {
            this.url=url; this.kind=kind; this.status=status; this.size=size; this.cacheKnown=cacheKnown; this.cacheLong=cacheLong; this.sampleText=sampleText;
        }
    }

    private static final class AssetBundle {
        final List<AssetFact> items = new ArrayList<>();
        final StringBuilder sampledJs = new StringBuilder();
        long totalKnownBytes, largestBytes, jsBytes, cssBytes, imageBytes;
        String largestUrl="";
        int cacheKnown, cached;
    }

    private static final class CrawlFact {
        final String url, title, description, canonical;
        final int status, h1;
        final boolean noindex;
        CrawlFact(String url, int status, String title, String description, String canonical, int h1, boolean noindex) {
            this.url=url; this.status=status; this.title=title; this.description=description; this.canonical=canonical; this.h1=h1; this.noindex=noindex;
        }
    }
}
