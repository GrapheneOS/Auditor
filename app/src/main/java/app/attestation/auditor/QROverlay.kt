package app.attestation.auditor

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.text.TextPaint
import android.util.AttributeSet
import android.view.View
import kotlin.math.min

class QROverlay(context: Context, attrs: AttributeSet?) : View(context, attrs) {
    companion object {
        private const val TAG = "QROverlay"
        private const val T_SIZE = 24f
        const val SIZE_FACTOR = 0.6f
    }

    private var bPaint: Paint
    private var tPaint: TextPaint
    private var fPaint: Paint
    var size = 256
        private set
    private var frameSideSize = 3
    private var frameSideLength = 42

    init {
        frameSideSize *= resources.displayMetrics.density.toInt()
        frameSideLength *= resources.displayMetrics.density.toInt()
        bPaint = Paint()
        bPaint.color = Color.parseColor("#A6000000")
        bPaint.strokeWidth = 10f
        bPaint.xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC)
        tPaint = TextPaint()
        tPaint.color = Color.parseColor("#ffffff")
        fPaint = Paint()
        fPaint.color = Color.parseColor("#8BC34A") // green500
        fPaint.strokeWidth = frameSideSize.toFloat()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val dim = min(width, height)
        size = (dim * SIZE_FACTOR).toInt()
        tPaint.textSize = T_SIZE * SIZE_FACTOR * resources.displayMetrics.density

        val verticalHeight = (height - size) / 2
        val horizontalWidth = (width - size) / 2

        // Drawing the background
        canvas.drawRect(0f, 0f, width.toFloat(), verticalHeight.toFloat(), bPaint)
        canvas.drawRect(0f, 0f, horizontalWidth.toFloat(), height.toFloat(), bPaint)
        canvas.drawRect(
            (horizontalWidth + size).toFloat(),
            0f,
            width.toFloat(),
            height.toFloat(),
            bPaint
        )
        canvas.drawRect(
            0f,
            (verticalHeight + size).toFloat(),
            width.toFloat(),
            height.toFloat(),
            bPaint
        )

        val text = context.getString(R.string.scanner_label)
        val textX = horizontalWidth + size / 2
        val textY = verticalHeight + size + frameSideSize * 4

        val xPos = textX - (tPaint.measureText(text) / 2).toInt()
        val yPos = (textY - (tPaint.descent() + tPaint.ascent())).toInt()

        canvas.drawText(text, xPos.toFloat(), yPos.toFloat(), tPaint)

        // Drawing the frame
        val halfFrameSideSize = frameSideSize / 2
        val x1 = width - horizontalWidth
        val y1 = height - verticalHeight

        // Top left
        canvas.drawLine(
            horizontalWidth.toFloat(),
            (verticalHeight + halfFrameSideSize).toFloat(),
            (horizontalWidth + frameSideLength).toFloat(),
            (verticalHeight + halfFrameSideSize).toFloat(),
            fPaint
        )
        canvas.drawLine(
            (horizontalWidth + halfFrameSideSize).toFloat(),
            verticalHeight.toFloat(),
            (horizontalWidth + halfFrameSideSize).toFloat(),
            (verticalHeight + frameSideLength).toFloat(),
            fPaint
        )

        // Top right
        canvas.drawLine(
            x1.toFloat(), (verticalHeight + halfFrameSideSize).toFloat(),
            (x1 - frameSideLength).toFloat(), (verticalHeight + halfFrameSideSize).toFloat(),
            fPaint
        )
        canvas.drawLine(
            (x1 - halfFrameSideSize).toFloat(), verticalHeight.toFloat(),
            (x1 - halfFrameSideSize).toFloat(), (verticalHeight + frameSideLength).toFloat(),
            fPaint
        )

        // Bottom left
        canvas.drawLine(
            horizontalWidth.toFloat(), (y1 - halfFrameSideSize).toFloat(),
            (horizontalWidth + frameSideLength).toFloat(), (y1 - halfFrameSideSize).toFloat(),
            fPaint
        )
        canvas.drawLine(
            (horizontalWidth + halfFrameSideSize).toFloat(), y1.toFloat(),
            (horizontalWidth + halfFrameSideSize).toFloat(), (y1 - frameSideLength).toFloat(),
            fPaint
        )

        // Bottom right
        canvas.drawLine(
            (x1 - halfFrameSideSize).toFloat(), y1.toFloat(),
            (x1 - halfFrameSideSize).toFloat(), (y1 - frameSideLength).toFloat(),
            fPaint
        )
        canvas.drawLine(
            x1.toFloat(), (y1 - halfFrameSideSize).toFloat(),
            (x1 - frameSideLength).toFloat(), (y1 - halfFrameSideSize).toFloat(),
            fPaint
        )
    }
}
