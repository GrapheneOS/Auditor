package app.attestation.auditor

import android.util.Log
import androidx.camera.core.ImageAnalysis.Analyzer
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.ReaderException
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.EnumMap
import kotlin.math.roundToInt

class QRCodeImageAnalyzer(private val mActivity: QRScannerActivity, private val listener: (qrCode: String?) -> Unit): Analyzer {

    private val TAG = "QRCodeImageAnalyzer"

    private var frameCounter = 0
    private var lastFpsTimestamp = System.currentTimeMillis()

    private val reader = MultiFormatReader()
    private var imageData = ByteArray(0)

    init {
        val supportedHints: MutableMap<DecodeHintType, Any> = EnumMap(
            DecodeHintType::class.java
        )
        supportedHints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
        reader.setHints(supportedHints)
    }

    override fun analyze(image: ImageProxy) {
        val byteBuffer = image.planes[0].buffer

        if (imageData.size != byteBuffer.capacity()) {
            imageData = ByteArray(byteBuffer.capacity())
        }
        byteBuffer[imageData]

        val widthPercent = mActivity.getOverlayView().size.toFloat() / mActivity.getOverlayView().getWidth()
        val size = (widthPercent * image.width).roundToInt();
        val left = (image.width - size) / 2
        val top = (image.height - size) / 2

        val source = PlanarYUVLuminanceSource(
            imageData,
            image.width, image.height,
            left, top,
            size, size,
            false
        )

        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        try {
            val result = reader.decodeWithState(binaryBitmap)
            listener.invoke(result.text)
        } catch (e: ReaderException) {
        } finally {
            reader.reset()
        }

        // Compute the FPS of the entire pipeline
        val frameCount = 10
        if (++frameCounter % frameCount == 0) {
            frameCounter = 0
            val now = System.currentTimeMillis()
            val delta = now - lastFpsTimestamp
            val fps = 1000 * frameCount.toFloat() / delta
            Log.d(TAG, "Analysis FPS: ${"%.02f".format(fps)}")
            lastFpsTimestamp = now
        }

        image.close()
    }
}
