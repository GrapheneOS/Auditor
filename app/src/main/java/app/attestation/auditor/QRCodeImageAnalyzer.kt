package app.attestation.auditor

import android.graphics.ImageFormat
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

class QRCodeImageAnalyzer(private val listener: (qrCode: String?) -> Unit) : Analyzer {

    private val reader = MultiFormatReader()

    init {
        val supportedHints: MutableMap<DecodeHintType, Any> = EnumMap(
            DecodeHintType::class.java
        )
        supportedHints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
        reader.setHints(supportedHints)
    }

    override fun analyze(image: ImageProxy) {
        val byteBuffer = image.planes[0].buffer
        val imageData = ByteArray(byteBuffer.capacity())
        byteBuffer[imageData]
        val source = PlanarYUVLuminanceSource(
            imageData,
            image.width, image.height,
            0, 0,
            image.width, image.height,
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

        image.close()
    }
}
