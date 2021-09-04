package app.attestation.auditor

import android.content.Context
import android.content.res.Resources
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.util.TypedValue
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

    private val Number.dpToPx get() = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        this.toFloat(),
        Resources.getSystem().displayMetrics)

    private val Int.half : Number get() {
        return this / 2
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        //this value decide how big the size should be
        val sizeInDp = 280

        val left = width / 2 - sizeInDp.half.dpToPx
        val top = height / 2 - sizeInDp.half.dpToPx
        val right = left + sizeInDp.dpToPx
        val bottom = top + sizeInDp.dpToPx

        path.reset()
        path.fillType = Path.FillType.INVERSE_EVEN_ODD
        path.addRect(left, top, right, bottom, Path.Direction.CW)
        canvas.drawPath(path, mSemiBlackPaint)
        canvas.clipPath(path)
        canvas.drawColor(color)
    }
}