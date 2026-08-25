package com.desarrollamo.webamo;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(5, 11, 20);
    private static final int CARD = Color.rgb(11, 24, 40);
    private static final int TEXT = Color.rgb(235, 245, 255);
    private static final int MUTED = Color.rgb(142, 163, 184);
    private static final int CYAN = Color.rgb(56, 189, 248);
    private static final int ORANGE = Color.rgb(245, 158, 11);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private EditText urlInput;
    private Button auditButton;
    private Button shareButton;
    private Button copyButton;
    private ProgressBar progress;
    private TextView scoreText;
    private TextView statusText;
    private TextView securityText;
    private TextView seoText;
    private TextView performanceText;
    private TextView privacyText;
    private TextView accessibilityText;
    private TextView findingsText;
    private TextView trackersText;
    private TextView cookiesText;
    private AuditReport lastReport;

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
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(22), dp(20), dp(36));
        scroll.addView(root, new ScrollView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView brand = text("DesarrollAMO · utilidad local", 12, ORANGE, Typeface.BOLD);
        root.addView(brand);

        TextView title = text("WebAMO", 34, TEXT, Typeface.BOLD);
        title.setPadding(0, dp(4), 0, 0);
        root.addView(title);

        TextView subtitle = text("Auditor web rápido, entendible y no intrusivo.", 16, MUTED, Typeface.NORMAL);
        subtitle.setPadding(0, dp(2), 0, dp(18));
        root.addView(subtitle);

        LinearLayout inputCard = card();
        TextView prompt = text("¿Qué web querés revisar?", 14, TEXT, Typeface.BOLD);
        inputCard.addView(prompt);

        urlInput = new EditText(this);
        urlInput.setHint("ejemplo.com");
        urlInput.setHintTextColor(Color.rgb(92, 113, 134));
        urlInput.setTextColor(TEXT);
        urlInput.setSingleLine(true);
        urlInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        urlInput.setPadding(dp(14), dp(12), dp(14), dp(12));
        urlInput.setBackground(roundRect(Color.rgb(7, 17, 30), CYAN, 1, 12));
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        inputParams.topMargin = dp(10);
        inputCard.addView(urlInput, inputParams);

        auditButton = button("Auditar ahora", CYAN, Color.rgb(2, 14, 25));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50));
        buttonParams.topMargin = dp(12);
        inputCard.addView(auditButton, buttonParams);
        auditButton.setOnClickListener(v -> startAudit());

        progress = new ProgressBar(this);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        LinearLayout.LayoutParams progressParams = new LinearLayout.LayoutParams(dp(36), dp(36));
        progressParams.gravity = Gravity.CENTER_HORIZONTAL;
        progressParams.topMargin = dp(12);
        inputCard.addView(progress, progressParams);

        TextView scope = text("HTTPS · headers · SEO · rendimiento · accesibilidad básica · trackers · cookies", 12, MUTED, Typeface.NORMAL);
        scope.setPadding(0, dp(12), 0, 0);
        inputCard.addView(scope);
        root.addView(inputCard, spaced());

        LinearLayout scoreCard = card();
        TextView scoreLabel = text("PUNTAJE TÉCNICO", 12, CYAN, Typeface.BOLD);
        scoreCard.addView(scoreLabel);
        scoreText = text("—", 52, TEXT, Typeface.BOLD);
        scoreText.setPadding(0, dp(2), 0, 0);
        scoreCard.addView(scoreText);
        statusText = text("Ingresá una URL para comenzar.", 14, MUTED, Typeface.NORMAL);
        scoreCard.addView(statusText);
        root.addView(scoreCard, spaced());

        securityText = categoryCard(root, "Seguridad", "HTTPS, CSP y headers defensivos");
        seoText = categoryCard(root, "SEO técnico", "title, description, canonical, H1, robots y sitemap");
        performanceText = categoryCard(root, "Rendimiento", "tiempo de respuesta y peso HTML observado");
        privacyText = categoryCard(root, "Privacidad · señales", "trackers y cookies visibles en la respuesta");
        accessibilityText = categoryCard(root, "Accesibilidad básica", "idioma, H1, title y alt de imágenes");

        findingsText = detailCard(root, "Hallazgos");
        trackersText = detailCard(root, "Rastreadores detectados");
        cookiesText = detailCard(root, "Cookies observadas");

        LinearLayout actions = card();
        shareButton = button("Compartir informe", ORANGE, Color.rgb(30, 18, 2));
        shareButton.setEnabled(false);
        copyButton = button("Copiar JSON", Color.rgb(25, 52, 72), TEXT);
        copyButton.setEnabled(false);
        actions.addView(shareButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)));
        LinearLayout.LayoutParams copyParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        copyParams.topMargin = dp(10);
        actions.addView(copyButton, copyParams);
        shareButton.setOnClickListener(v -> shareReport());
        copyButton.setOnClickListener(v -> copyJson());
        root.addView(actions, spaced());

        TextView disclaimer = text("WebAMO hace lecturas públicas y no destructivas desde tu teléfono. No ejecuta exploits ni reemplaza un pentest, Lighthouse o una evaluación legal de privacidad.", 12, MUTED, Typeface.NORMAL);
        disclaimer.setPadding(dp(4), dp(6), dp(4), 0);
        root.addView(disclaimer);
        return scroll;
    }

    private TextView categoryCard(LinearLayout root, String title, String description) {
        LinearLayout card = card();
        TextView heading = text(title, 17, TEXT, Typeface.BOLD);
        card.addView(heading);
        TextView score = text("—/100", 28, CYAN, Typeface.BOLD);
        score.setPadding(0, dp(4), 0, 0);
        card.addView(score);
        TextView help = text(description, 12, MUTED, Typeface.NORMAL);
        card.addView(help);
        root.addView(card, spaced());
        return score;
    }

    private TextView detailCard(LinearLayout root, String title) {
        LinearLayout card = card();
        card.addView(text(title, 17, TEXT, Typeface.BOLD));
        TextView body = text("Todavía sin datos.", 14, MUTED, Typeface.NORMAL);
        body.setPadding(0, dp(8), 0, 0);
        body.setLineSpacing(0, 1.18f);
        card.addView(body);
        root.addView(card, spaced());
        return body;
    }

    private void startAudit() {
        String raw = urlInput.getText().toString();
        if (raw.trim().isEmpty()) {
            urlInput.setError("Escribí una URL");
            return;
        }
        setBusy(true);
        statusText.setText("Leyendo la web desde tu dispositivo…");
        lastReport = null;
        executor.execute(() -> {
            try {
                AuditReport report = AuditEngine.audit(raw);
                runOnUiThread(() -> showReport(report));
            } catch (Exception error) {
                runOnUiThread(() -> showError(error));
            }
        });
    }

    private void showReport(AuditReport report) {
        lastReport = report;
        setBusy(false);
        scoreText.setText(report.overallScore + "/100");
        statusText.setText("HTTP " + report.statusCode + " · " + report.elapsedMs + " ms · " + humanBytes(report.bodyBytes));
        securityText.setText(report.securityScore + "/100");
        seoText.setText(report.seoScore + "/100");
        performanceText.setText(report.performanceScore + "/100");
        privacyText.setText(report.privacyScore + "/100");
        accessibilityText.setText(report.accessibilityScore + "/100");
        findingsText.setText(bullets(report.findings));
        trackersText.setText(report.trackers.isEmpty() ? "No se detectaron firmas conocidas en el HTML recibido." : bullets(report.trackers));
        cookiesText.setText(report.cookies.isEmpty() ? "No se observaron cabeceras Set-Cookie en esta respuesta." : bullets(report.cookies));
        shareButton.setEnabled(true);
        copyButton.setEnabled(true);
    }

    private void showError(Exception error) {
        setBusy(false);
        scoreText.setText("—");
        String message = error.getMessage();
        if (message == null || message.isBlank()) message = error.getClass().getSimpleName();
        statusText.setText("No se pudo auditar: " + message);
        Toast.makeText(this, "WebAMO no pudo leer esa URL", Toast.LENGTH_LONG).show();
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        auditButton.setEnabled(!busy);
        urlInput.setEnabled(!busy);
        if (busy) {
            shareButton.setEnabled(false);
            copyButton.setEnabled(false);
        }
    }

    private void shareReport() {
        if (lastReport == null) return;
        try {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_SUBJECT, "WebAMO · " + lastReport.target);
            intent.putExtra(Intent.EXTRA_TEXT, lastReport.shareText() + "\n\nJSON:\n" + lastReport.toJson().toString(2));
            startActivity(Intent.createChooser(intent, "Compartir informe WebAMO"));
        } catch (Exception error) {
            Toast.makeText(this, "No se pudo preparar el informe", Toast.LENGTH_SHORT).show();
        }
    }

    private void copyJson() {
        if (lastReport == null) return;
        try {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("WebAMO JSON", lastReport.toJson().toString(2)));
            Toast.makeText(this, "JSON copiado", Toast.LENGTH_SHORT).show();
        } catch (Exception error) {
            Toast.makeText(this, "No se pudo copiar el JSON", Toast.LENGTH_SHORT).show();
        }
    }

    private String bullets(Iterable<String> items) {
        StringBuilder out = new StringBuilder();
        for (String item : items) {
            if (out.length() > 0) out.append('\n');
            out.append("• ").append(item);
        }
        return out.length() == 0 ? "Sin hallazgos." : out.toString();
    }

    private String humanBytes(int bytes) {
        if (bytes < 1024) return bytes + " B HTML";
        if (bytes < 1024 * 1024) return Math.round(bytes / 1024f) + " KB HTML";
        return String.format(java.util.Locale.ROOT, "%.1f MB HTML", bytes / (1024f * 1024f));
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.setBackground(roundRect(CARD, Color.rgb(24, 50, 73), 1, 18));
        return card;
    }

    private LinearLayout.LayoutParams spaced() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(12);
        return params;
    }

    private Button button(String label, int background, int foreground) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(15);
        button.setTextColor(foreground);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setAllCaps(false);
        button.setGravity(Gravity.CENTER);
        button.setBackground(roundRect(background, background, 0, 14));
        return button;
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

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
