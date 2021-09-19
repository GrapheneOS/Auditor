package app.attestation.auditor;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.text.TextPaint;
import android.util.AttributeSet;
import android.view.View;

public class QROverlay extends View {

    private static final String TAG = "QROverlay";

    private Paint bPaint;
    private TextPaint tPaint;
    private Paint fPaint;
    private final float T_SIZE = 24;
    private int size = 256;
    private int frameSideSize = 3;
    private int frameSideLength = 42;

    private final float SIZE_FACTOR = 0.6f;

    public QROverlay(Context context, AttributeSet attrs) {
        super(context, attrs);
        initPaints();
    }

    private void initPaints() {
        frameSideSize *= getResources().getDisplayMetrics().density;
        frameSideLength *= getResources().getDisplayMetrics().density;

        bPaint = new Paint();
        bPaint.setColor(Color.parseColor("#A6000000"));
        bPaint.setStrokeWidth(10);
        bPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC));

        tPaint = new TextPaint();
        tPaint.setColor(Color.parseColor("#ffffff"));

        fPaint = new Paint();
        fPaint.setColor(Color.parseColor("#8BC34A")); // green500
        fPaint.setStrokeWidth(frameSideSize);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        final int width = getWidth();
        final int height = getHeight();

        final int dim = Math.min(width, height);

        size = (int) (dim * SIZE_FACTOR);
        tPaint.setTextSize(T_SIZE * SIZE_FACTOR * getResources().getDisplayMetrics().density);

        final int verticalHeight = (height - size) / 2;
        final int horizontalWidth = (width - size) / 2;

        // Drawing the background
        canvas.drawRect(0, 0, width, verticalHeight, bPaint);
        canvas.drawRect(0, 0, horizontalWidth, height, bPaint);
        canvas.drawRect(horizontalWidth + size, 0, width, height, bPaint);
        canvas.drawRect(0, verticalHeight + size, width, height, bPaint);

        final String text = getContext().getString(R.string.scanner_label);
        final int textX = horizontalWidth + size / 2;
        final int textY = verticalHeight + size + frameSideSize * 4;

        int xPos = textX - (int)(tPaint.
                measureText(text) / 2);
        int yPos = (int) (textY - ((tPaint.descent() + tPaint.ascent()) / 2)) ;

        canvas.drawText(text, xPos, yPos, tPaint);

        // Drawing the frame

        final int halfFrameSideSize = frameSideSize / 2;

        int x1 = width - horizontalWidth;
        int y1 = height - verticalHeight;

        // Top left
        canvas.drawLine(horizontalWidth, verticalHeight + halfFrameSideSize,
                horizontalWidth + frameSideLength, verticalHeight + halfFrameSideSize,
                fPaint);
        canvas.drawLine(horizontalWidth + halfFrameSideSize, verticalHeight,
                horizontalWidth + halfFrameSideSize, verticalHeight + frameSideLength,
                fPaint);

        // Top right
        canvas.drawLine(x1, verticalHeight + halfFrameSideSize,
                x1 - frameSideLength, verticalHeight + halfFrameSideSize,
                fPaint);

        canvas.drawLine(x1 - halfFrameSideSize, verticalHeight,
                x1 - halfFrameSideSize, verticalHeight + frameSideLength,
                fPaint);

        // Bottom left
        canvas.drawLine(horizontalWidth, y1 - halfFrameSideSize,
                horizontalWidth + frameSideLength, y1 - halfFrameSideSize,
                fPaint);

        canvas.drawLine(horizontalWidth + halfFrameSideSize, y1,
                horizontalWidth + halfFrameSideSize, y1 - frameSideLength,
                fPaint);

        // Bottom right
        canvas.drawLine(x1 - halfFrameSideSize, y1,
                x1 - halfFrameSideSize, y1 - frameSideLength,
                fPaint);

        canvas.drawLine(x1, y1 - halfFrameSideSize,
                x1 - frameSideLength, y1 - halfFrameSideSize,
                fPaint);
    }

    public int getSize() {
        return size;
    }
}
