package com.desarrollamo.webamo;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(5, 11, 20);
    private static final int CARD = Color.rgb(11, 24, 40);
    private static final int CARD_2 = Color.rgb(8, 19, 32);
    private static final int BORDER = Color.rgb(25, 50, 73);
    private static final int TEXT = Color.rgb(235, 245, 255);
    private static final int MUTED = Color.rgb(142, 163, 184);
    private static final int CYAN = Color.rgb(56, 189, 248);
    private static final int GREEN = Color.rgb(52, 211, 153);
    private static final int ORANGE = Color.rgb(245, 158, 11);
    private static final int RED = Color.rgb(248, 113, 113);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private EditText urlInput;
    private CheckBox quickCheck;
    private Button auditButton;
    private Button shareButton;
    private Button copyReportButton;
    private Button copyButton;
    private Button allChecksButton;
    private ProgressBar loading;
    private ScoreRingView scoreRing;
    private TextView scoreGrade;
    private TextView scoreMeta;
    private TextView riskPill;
    private TextView coveragePill;
    private TextView fingerprintText;
    private TextView scopeText;
    private TextView historyText;
    private LinearLayout categoryContainer;
    private LinearLayout priorityContainer;
    private TextView signalsText;
    private TextView allChecksText;
    private AuditReport lastReport;
    private boolean checksVisible;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        setContentView(buildUi());
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(36));
        scroll.addView(root, new ScrollView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout brandRow = new LinearLayout(this);
        brandRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView badge = pill("DESARROLLAMO", ORANGE, Color.rgb(38, 24, 4));
        brandRow.addView(badge);
        TextView version = text("WebAMO · v0.1.2", 12, MUTED, Typeface.BOLD);
        LinearLayout.LayoutParams vp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        vp.leftMargin = dp(10);
        brandRow.addView(version, vp);
        root.addView(brandRow);

        TextView title = text("Auditoría web que explica qué pasa", 30, TEXT, Typeface.BOLD);
        title.setPadding(0, dp(12), 0, 0);
        root.addView(title);
        TextView subtitle = text("Más señales, cobertura real y prioridades claras. Sin exploits ni backend propio.", 15, MUTED, Typeface.NORMAL);
        subtitle.setPadding(0, dp(4), 0, dp(16));
        root.addView(subtitle);

        LinearLayout inputCard = card(CARD);
        inputCard.addView(text("URL a revisar", 13, TEXT, Typeface.BOLD));

        urlInput = new EditText(this);
        urlInput.setHint("desarrollamo.com.ar");
        urlInput.setHintTextColor(Color.rgb(86, 107, 127));
        urlInput.setTextColor(TEXT);
        urlInput.setSingleLine(true);
        urlInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        urlInput.setPadding(dp(14), dp(11), dp(14), dp(11));
        urlInput.setBackground(roundRect(CARD_2, CYAN, 1, 12));
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50));
        inputParams.topMargin = dp(9);
        inputCard.addView(urlInput, inputParams);

        quickCheck = new CheckBox(this);
        quickCheck.setText("Modo rápido (omite mini-crawl y probes extra)");
        quickCheck.setTextColor(MUTED);
        quickCheck.setTextSize(12);
        quickCheck.setButtonTintList(ColorStateList.valueOf(CYAN));
        LinearLayout.LayoutParams qp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qp.topMargin = dp(8);
        inputCard.addView(quickCheck, qp);

        auditButton = button("Auditar ahora", CYAN, Color.rgb(2, 14, 25));
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50));
        ap.topMargin = dp(8);
        inputCard.addView(auditButton, ap);
        auditButton.setOnClickListener(v -> startAudit());

        loading = new ProgressBar(this);
        loading.setVisibility(View.GONE);
        loading.setIndeterminateTintList(ColorStateList.valueOf(CYAN));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(34), dp(34));
        lp.gravity = Gravity.CENTER_HORIZONTAL;
        lp.topMargin = dp(9);
        inputCard.addView(loading, lp);

        TextView scope = text("Seguridad · SEO · rendimiento · privacidad · accesibilidad · TLS/DNS · assets · mini-crawl · IA/PWA", 11, MUTED, Typeface.NORMAL);
        scope.setPadding(0, dp(9), 0, 0);
        inputCard.addView(scope);
        root.addView(inputCard, spaced());

        root.addView(sectionLabel("RESUMEN EJECUTIVO"));

        LinearLayout scoreCard = card(CARD);
        LinearLayout scoreRow = new LinearLayout(this);
        scoreRow.setOrientation(LinearLayout.HORIZONTAL);
        scoreRow.setGravity(Gravity.CENTER_VERTICAL);

        scoreRing = new ScoreRingView(this);
        scoreRing.setScore(0);
        scoreRow.addView(scoreRing, new LinearLayout.LayoutParams(dp(150), dp(150)));

        LinearLayout scoreInfo = new LinearLayout(this);
        scoreInfo.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams sip = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        sip.leftMargin = dp(16);
        scoreRow.addView(scoreInfo, sip);

        scoreGrade = text("Esperando auditoría", 21, TEXT, Typeface.BOLD);
        scoreInfo.addView(scoreGrade);
        scoreMeta = text("Ingresá una URL para comenzar.", 13, MUTED, Typeface.NORMAL);
        scoreMeta.setPadding(0, dp(5), 0, dp(10));
        scoreInfo.addView(scoreMeta);

        LinearLayout pills = new LinearLayout(this);
        pills.setOrientation(LinearLayout.HORIZONTAL);
        riskPill = pill("RIESGO —", MUTED, Color.rgb(18, 31, 45));
        coveragePill = pill("COB —", CYAN, Color.rgb(5, 35, 50));
        pills.addView(riskPill);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cp.leftMargin = dp(7);
        pills.addView(coveragePill, cp);
        scoreInfo.addView(pills);

        scoreCard.addView(scoreRow);
        root.addView(scoreCard, spaced());

        root.addView(sectionLabel("ÁREAS"));
        categoryContainer = new LinearLayout(this);
        categoryContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(categoryContainer);
        buildEmptyCategories();

        root.addView(sectionLabel("PRIORIDADES"));
        LinearLayout priorityCard = card(CARD);
        priorityCard.addView(text("Qué conviene corregir primero", 17, TEXT, Typeface.BOLD));
        priorityContainer = new LinearLayout(this);
        priorityContainer.setOrientation(LinearLayout.VERTICAL);
        priorityContainer.setPadding(0, dp(8), 0, 0);
        priorityCard.addView(priorityContainer);
        priorityContainer.addView(text("Todavía sin resultados.", 13, MUTED, Typeface.NORMAL));
        root.addView(priorityCard, spaced());

        root.addView(sectionLabel("MAPA TÉCNICO"));
        LinearLayout mapCard = card(CARD);
        fingerprintText = text("Plataforma, stack, CDN y TLS aparecerán acá.", 13, MUTED, Typeface.NORMAL);
        fingerprintText.setLineSpacing(0, 1.18f);
        mapCard.addView(fingerprintText);
        scopeText = text("Alcance: —", 13, MUTED, Typeface.NORMAL);
        scopeText.setPadding(0, dp(9), 0, 0);
        mapCard.addView(scopeText);
        root.addView(mapCard, spaced());

        root.addView(sectionLabel("PRIVACIDAD Y TERCEROS"));
        LinearLayout signalsCard = card(CARD);
        signalsText = text("Todavía sin señales.", 13, MUTED, Typeface.NORMAL);
        signalsText.setLineSpacing(0, 1.18f);
        signalsCard.addView(signalsText);
        root.addView(signalsCard, spaced());

        root.addView(sectionLabel("HISTORIAL"));
        LinearLayout historyCard = card(CARD);
        historyText = text("La primera auditoría de cada dominio crea el baseline local.", 13, MUTED, Typeface.NORMAL);
        historyText.setLineSpacing(0, 1.18f);
        historyCard.addView(historyText);
        root.addView(historyCard, spaced());

        root.addView(sectionLabel("TODOS LOS CONTROLES"));
        LinearLayout checksCard = card(CARD);
        allChecksButton = button("Mostrar auditoría completa", Color.rgb(25, 52, 72), TEXT);
        checksCard.addView(allChecksButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46)));
        allChecksText = text("", 12, MUTED, Typeface.NORMAL);
        allChecksText.setLineSpacing(0, 1.15f);
        allChecksText.setPadding(0, dp(10), 0, 0);
        allChecksText.setVisibility(View.GONE);
        checksCard.addView(allChecksText);
        allChecksButton.setEnabled(false);
        allChecksButton.setOnClickListener(v -> toggleChecks());
        root.addView(checksCard, spaced());

        LinearLayout actions = card(CARD);
        shareButton = button("Compartir informe", ORANGE, Color.rgb(34, 20, 2));
        copyReportButton = button("Copiar informe", CYAN, Color.rgb(2, 14, 25));
        copyButton = button("Copiar JSON completo", Color.rgb(25, 52, 72), TEXT);
        shareButton.setEnabled(false);
        copyReportButton.setEnabled(false);
        copyButton.setEnabled(false);
        actions.addView(shareButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)));
        LinearLayout.LayoutParams reportP = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        reportP.topMargin = dp(9);
        actions.addView(copyReportButton, reportP);
        LinearLayout.LayoutParams copyP = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        copyP.topMargin = dp(9);
        actions.addView(copyButton, copyP);
        shareButton.setOnClickListener(v -> shareReport());
        copyReportButton.setOnClickListener(v -> copyReport());
        copyButton.setOnClickListener(v -> copyJson());
        root.addView(actions, spaced());

        TextView disclaimer = text("WebAMO sólo realiza lecturas públicas y no destructivas. N/V significa que una señal necesita navegador renderizado, interacción o acceso autorizado; no se inventa un resultado para completar el 100%.", 11, MUTED, Typeface.NORMAL);
        disclaimer.setPadding(dp(3), dp(5), dp(3), 0);
        root.addView(disclaimer);

        return scroll;
    }

    private void startAudit() {
        String raw = urlInput.getText().toString();
        if (raw.trim().isEmpty()) {
            urlInput.setError("Escribí una URL");
            return;
        }
        setBusy(true);
        scoreGrade.setText("Auditando…");
        scoreMeta.setText("Leyendo señales públicas desde tu dispositivo.");
        executor.execute(() -> {
            try {
                AuditReport report = AuditEngine.audit(raw, quickCheck.isChecked());
                HistoryStore.compareAndSave(this, report);
                runOnUiThread(() -> showReport(report));
            } catch (Exception error) {
                runOnUiThread(() -> showError(error));
            }
        });
    }

    private void showReport(AuditReport report) {
        lastReport = report;
        setBusy(false);
        scoreRing.setScore(report.overallScore);
        scoreGrade.setText(report.grade + " · " + report.overallScore + "/100");
        scoreMeta.setText("HTTP " + report.statusCode + " · " + report.elapsedMs + " ms · " + humanBytes(report.bodyBytes));
        setPill(riskPill, "RIESGO " + report.risk,
                "BAJO".equals(report.risk) ? GREEN : "MEDIO".equals(report.risk) ? ORANGE : RED);
        setPill(coveragePill, "COB " + report.overallCoverage + "%", CYAN);

        renderCategories(report);
        renderPriorities(report);

        fingerprintText.setText(
                "Plataforma  " + report.platform + "\n" +
                "Stack       " + report.stack + "\n" +
                "Render      " + report.renderMode + "\n" +
                "CDN         " + report.cdn + "\n" +
                "TLS         " + (report.tlsVersion.isBlank() ? "N/V" : report.tlsVersion +
                (report.tlsDaysLeft == Integer.MIN_VALUE ? "" : " · " + report.tlsDaysLeft + " días")) + "\n" +
                "Server      " + (report.server.isBlank() ? "no expuesto" : report.server)
        );
        scopeText.setText("Alcance: " + report.crawlPages + " pág. mini-crawl · " +
                report.assetsDetected + " assets · " + report.thirdPartyHostCount + " hosts terceros · " +
                report.knownScoredChecks() + "/" + report.scoredChecks() + " controles conocidos");

        StringBuilder privacy = new StringBuilder();
        privacy.append("Trackers: ").append(report.trackers.isEmpty() ? "no detectados en muestra" : String.join(", ", report.trackers)).append('\n');
        privacy.append("Cookies: ").append(report.cookies.isEmpty() ? "sin Set-Cookie inicial" : String.join(", ", report.cookies)).append('\n');
        privacy.append("Terceros: ").append(report.thirdPartyHosts.isEmpty() ? "ninguno detectado" :
                String.join(", ", report.thirdPartyHosts.subList(0, Math.min(8, report.thirdPartyHosts.size()))));
        signalsText.setText(privacy.toString());

        if (report.previousScore == null) {
            historyText.setText("Baseline creado para este dominio. La próxima auditoría mostrará mejoras y regresiones.");
        } else {
            String delta = (report.scoreDelta != null && report.scoreDelta >= 0 ? "+" : "") + report.scoreDelta;
            historyText.setText("Anterior " + report.previousScore + " → ahora " + report.overallScore + " (" + delta + ")\n" +
                    "Regresiones " + report.regressions + " · resueltas " + report.resolved);
        }

        allChecksText.setText(formatAllChecks(report));
        allChecksButton.setEnabled(true);
        shareButton.setEnabled(true);
        copyReportButton.setEnabled(true);
        copyButton.setEnabled(true);
    }

    private void renderCategories(AuditReport report) {
        categoryContainer.removeAllViews();
        for (Map.Entry<String, Integer> e : report.categoryScores.entrySet()) {
            int coverage = report.categoryCoverage.getOrDefault(e.getKey(), 100);
            categoryContainer.addView(categoryRow(e.getKey(), e.getValue(), coverage), spaced());
        }
    }

    private void buildEmptyCategories() {
        categoryContainer.removeAllViews();
        for (String name : new String[]{
                ScoreCalculator.SECURITY, ScoreCalculator.SEO, ScoreCalculator.PERFORMANCE,
                ScoreCalculator.PRIVACY, ScoreCalculator.ACCESSIBILITY
        }) categoryContainer.addView(categoryRow(name, 0, 0), spaced());
    }

    private View categoryRow(String name, int score, int coverage) {
        LinearLayout card = card(CARD);
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        TextView label = text(name, 15, TEXT, Typeface.BOLD);
        top.addView(label, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        int color = score >= 80 ? GREEN : score >= 60 ? ORANGE : RED;
        TextView value = text(score + "/100", 17, color, Typeface.BOLD);
        top.addView(value);
        card.addView(top);

        ProgressBar bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(100);
        bar.setProgress(score);
        bar.setProgressTintList(ColorStateList.valueOf(color));
        bar.setProgressBackgroundTintList(ColorStateList.valueOf(Color.rgb(25, 43, 60)));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(8));
        bp.topMargin = dp(9);
        card.addView(bar, bp);

        TextView cov = text("Cobertura " + coverage + "%", 11, MUTED, Typeface.NORMAL);
        cov.setPadding(0, dp(7), 0, 0);
        card.addView(cov);
        return card;
    }

    private void renderPriorities(AuditReport report) {
        priorityContainer.removeAllViews();
        List<AuditCheck> problems = report.problems();
        if (problems.isEmpty()) {
            priorityContainer.addView(text("✓ No se detectaron problemas puntuables en lo verificable.", 13, GREEN, Typeface.NORMAL));
            return;
        }
        int max = Math.min(7, problems.size());
        for (int i = 0; i < max; i++) {
            AuditCheck c = problems.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, i == 0 ? 0 : dp(10), 0, dp(7));

            int color = "CRÍTICA".equals(c.severity) || "ALTA".equals(c.severity) ? RED :
                    "MEDIA".equals(c.severity) ? ORANGE : CYAN;
            TextView head = text((i + 1) + ". " + c.label + " · " + c.severity, 13, color, Typeface.BOLD);
            row.addView(head);
            TextView detail = text(c.detail, 12, TEXT, Typeface.NORMAL);
            detail.setPadding(0, dp(2), 0, 0);
            row.addView(detail);
            if (!c.recommendation.isBlank()) {
                TextView rec = text("→ " + c.recommendation, 12, MUTED, Typeface.NORMAL);
                rec.setPadding(0, dp(2), 0, 0);
                row.addView(rec);
            }
            priorityContainer.addView(row);
            if (i < max - 1) priorityContainer.addView(divider());
        }
    }

    private String formatAllChecks(AuditReport report) {
        StringBuilder out = new StringBuilder();
        String current = "";
        for (AuditCheck c : report.checks) {
            if (!c.category.equals(current)) {
                current = c.category;
                if (out.length() > 0) out.append('\n');
                int s = report.categoryScores.getOrDefault(current, -1);
                int cov = report.categoryCoverage.getOrDefault(current, -1);
                out.append("── ").append(current);
                if (s >= 0) out.append(" · ").append(s).append("/100 · cob ").append(cov).append("%");
                out.append(" ──\n");
            }
            String symbol = AuditCheck.PASS.equals(c.status) ? "✓" :
                    AuditCheck.FAIL.equals(c.status) ? "✕" :
                    AuditCheck.WARN.equals(c.status) ? "!" :
                    AuditCheck.UNKNOWN.equals(c.status) ? "?" : "•";
            out.append(symbol).append(' ').append(c.label).append(": ").append(c.detail);
            if (c.isProblem() && !c.recommendation.isBlank()) out.append("\n   → ").append(c.recommendation);
            out.append('\n');
        }
        return out.toString();
    }

    private void toggleChecks() {
        checksVisible = !checksVisible;
        allChecksText.setVisibility(checksVisible ? View.VISIBLE : View.GONE);
        allChecksButton.setText(checksVisible ? "Ocultar auditoría completa" : "Mostrar auditoría completa");
    }

    private void showError(Exception error) {
        setBusy(false);
        scoreRing.setScore(0);
        scoreGrade.setText("No se pudo auditar");
        String message = error.getMessage();
        if (message == null || message.isBlank()) message = error.getClass().getSimpleName();
        scoreMeta.setText(message);
        Toast.makeText(this, "WebAMO no pudo leer esa URL", Toast.LENGTH_LONG).show();
    }

    private void setBusy(boolean busy) {
        loading.setVisibility(busy ? View.VISIBLE : View.GONE);
        auditButton.setEnabled(!busy);
        urlInput.setEnabled(!busy);
        quickCheck.setEnabled(!busy);
        if (busy) {
            shareButton.setEnabled(false);
            copyReportButton.setEnabled(false);
            copyButton.setEnabled(false);
            allChecksButton.setEnabled(false);
        }
    }

    private void shareReport() {
        if (lastReport == null) return;
        try {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_SUBJECT, "WebAMO 0.1.2 · " + lastReport.target);
            intent.putExtra(Intent.EXTRA_TEXT, lastReport.shareText());
            startActivity(Intent.createChooser(intent, "Compartir informe WebAMO"));
        } catch (Exception e) {
            Toast.makeText(this, "No se pudo compartir", Toast.LENGTH_SHORT).show();
        }
    }

    private void copyReport() {
        if (lastReport == null) return;
        try {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("WebAMO informe", lastReport.shareText()));
            Toast.makeText(this, "Informe copiado", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "No se pudo copiar el informe", Toast.LENGTH_SHORT).show();
        }
    }

    private void copyJson() {
        if (lastReport == null) return;
        try {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("WebAMO JSON", lastReport.toJson().toString(2)));
            Toast.makeText(this, "JSON completo copiado", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "No se pudo copiar el JSON", Toast.LENGTH_SHORT).show();
        }
    }

    private TextView sectionLabel(String label) {
        TextView view = text(label, 11, CYAN, Typeface.BOLD);
        view.setLetterSpacing(0.08f);
        view.setPadding(dp(3), dp(8), 0, dp(7));
        return view;
    }

    private TextView pill(String value, int foreground, int background) {
        TextView view = text(value, 10, foreground, Typeface.BOLD);
        view.setPadding(dp(9), dp(5), dp(9), dp(5));
        view.setBackground(roundRect(background, background, 0, 999));
        return view;
    }

    private void setPill(TextView view, String text, int color) {
        view.setText(text);
        view.setTextColor(color);
        view.setBackground(roundRect(withAlpha(color, 32), withAlpha(color, 60), 1, 999));
    }

    private int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private View divider() {
        View v = new View(this);
        v.setBackgroundColor(Color.rgb(22, 43, 61));
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        return v;
    }

    private LinearLayout card(int fill) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(15), dp(15), dp(15), dp(15));
        card.setBackground(roundRect(fill, BORDER, 1, 18));
        return card;
    }

    private LinearLayout.LayoutParams spaced() {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.bottomMargin = dp(11);
        return p;
    }

    private Button button(String label, int background, int foreground) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(14);
        b.setTextColor(foreground);
        b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        b.setGravity(Gravity.CENTER);
        b.setBackground(roundRect(background, background, 0, 13));
        return b;
    }

    private TextView text(String value, int sp, int color, int style) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setTypeface(Typeface.DEFAULT, style);
        return view;
    }

    private GradientDrawable roundRect(int fill, int stroke, int strokeWidthDp, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        if (strokeWidthDp > 0) drawable.setStroke(dp(strokeWidthDp), stroke);
        return drawable;
    }

    private String humanBytes(long n) {
        if (n < 1024) return n + " B HTML";
        if (n < 1024L * 1024) return Math.round(n / 1024f) + " KB HTML";
        return String.format(Locale.ROOT, "%.1f MB HTML", n / (1024f * 1024f));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
