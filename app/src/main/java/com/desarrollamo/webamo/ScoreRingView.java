package com.desarrollamo.webamo;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.view.View;

public final class ScoreRingView extends View {
    private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arc = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint scorePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private int score;

    public ScoreRingView(Context context) {
        super(context);
        track.setStyle(Paint.Style.STROKE);
        track.setStrokeWidth(dp(13));
        track.setStrokeCap(Paint.Cap.ROUND);
        track.setColor(Color.rgb(25, 50, 73));

        arc.setStyle(Paint.Style.STROKE);
        arc.setStrokeWidth(dp(13));
        arc.setStrokeCap(Paint.Cap.ROUND);

        scorePaint.setColor(Color.rgb(238, 247, 255));
        scorePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        scorePaint.setTextAlign(Paint.Align.CENTER);
        scorePaint.setTextSize(dp(32));

        labelPaint.setColor(Color.rgb(142, 163, 184));
        labelPaint.setTextAlign(Paint.Align.CENTER);
        labelPaint.setTextSize(dp(10));
    }

    public void setScore(int value) {
        score = Math.max(0, Math.min(100, value));
        if (score >= 80) arc.setColor(Color.rgb(52, 211, 153));
        else if (score >= 60) arc.setColor(Color.rgb(245, 158, 11));
        else arc.setColor(Color.rgb(248, 113, 113));
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float pad = dp(16);
        RectF oval = new RectF(pad, pad, getWidth() - pad, getHeight() - pad);
        canvas.drawArc(oval, -90, 360, false, track);
        canvas.drawArc(oval, -90, 360f * score / 100f, false, arc);
        float cx = getWidth() / 2f;
        float cy = getHeight() / 2f;
        Paint.FontMetrics fm = scorePaint.getFontMetrics();
        canvas.drawText(String.valueOf(score), cx, cy - (fm.ascent + fm.descent) / 2f - dp(4), scorePaint);
        canvas.drawText("/ 100", cx, cy + dp(28), labelPaint);
    }

    private float dp(float value) {
        return value * getResources().getDisplayMetrics().density;
    }
}
