package app.attestation.auditor

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View

class FocusView : View {
    private val color = Color.parseColor("#C1000000")
    private var mSemiBlackPaint: Paint = Paint()
    private val path = Path()

    constructor(context: Context?)
            : super(context) {
        initPaints()
    }

    constructor(context: Context?, attrs: AttributeSet?)
            : super(context, attrs) {
        initPaints()
    }

    constructor(context: Context?, attrs: AttributeSet?, defStyleAttr: Int)
            : super(context, attrs, defStyleAttr) {
        initPaints()
    }

    private fun initPaints() {
        mSemiBlackPaint.color = Color.TRANSPARENT
        mSemiBlackPaint.strokeWidth = 10f
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val left = width / 2 - 450
        val top = height / 2 - 450
        val right = left + 900
        val bottom = top + 900
        path.reset()
        path.fillType = Path.FillType.INVERSE_EVEN_ODD
        path.addRect(
            left.toFloat(), top.toFloat(), right.toFloat(),
            bottom.toFloat(), Path.Direction.CW
        )
        canvas.drawPath(path, mSemiBlackPaint)
        canvas.clipPath(path)
        canvas.drawColor(color)
    }
}