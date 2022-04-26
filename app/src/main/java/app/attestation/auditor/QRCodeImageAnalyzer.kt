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

class QRCodeImageAnalyzer(
    private val mActivity: QRScannerActivity,
    private val listener: (qrCode: String) -> Unit
) : Analyzer {
    companion object {
        private const val TAG = "QRCodeImageAnalyzer"
    }

    private var frameCounter = 0
    private var lastFpsTimestamp = System.nanoTime()

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
        val plane = image.planes[0]
        val byteBuffer = plane.buffer
        val rotationDegrees = image.imageInfo.rotationDegrees

        if (imageData.size != byteBuffer.capacity()) {
            imageData = ByteArray(byteBuffer.capacity())
        }
        byteBuffer.get(imageData)

        val previewWidth: Int
        val previewHeight: Int

        if (rotationDegrees == 0 || rotationDegrees == 180) {
            previewWidth = mActivity.contentFrame.width
            previewHeight = mActivity.contentFrame.height
        } else {
            previewWidth = mActivity.contentFrame.height
            previewHeight = mActivity.contentFrame.width
        }

        val iFact = if (previewWidth < previewHeight) {
            image.width / previewWidth.toFloat()
        } else {
            image.height / previewHeight.toFloat()
        }

        val size = mActivity.getOverlayView().size * iFact

        val left = (image.width - size) / 2
        val top = (image.height - size) / 2

        val source = PlanarYUVLuminanceSource(
            imageData,
            plane.rowStride, image.height,
            left.roundToInt(), top.roundToInt(),
            size.roundToInt(), size.roundToInt(),
            false
        )

        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        try {
            reader.decodeWithState(binaryBitmap).text?.let {
                listener.invoke(it)
            }
        } catch (e: ReaderException) {
        } finally {
            reader.reset()
        }

        // Compute the FPS of the entire pipeline
        val frameCount = 10
        if (++frameCounter % frameCount == 0) {
            frameCounter = 0
            val now = System.nanoTime()
            val delta = now - lastFpsTimestamp
            val fps = 1_000_000_000 * frameCount.toFloat() / delta
            Log.d(TAG, "Analysis FPS: ${"%.02f".format(fps)}")
            lastFpsTimestamp = now
        }

        image.close()
    }
}
