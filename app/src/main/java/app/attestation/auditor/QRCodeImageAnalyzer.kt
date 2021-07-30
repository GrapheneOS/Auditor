package app.attestation.auditor

import android.graphics.ImageFormat
import androidx.camera.core.ImageAnalysis.Analyzer
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.FormatException
import com.google.zxing.ChecksumException
import com.google.zxing.NotFoundException
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.EnumMap

class QRCodeImageAnalyzer(private val listener: (qrCode: String?) -> Unit) : Analyzer {

    override fun analyze(image: ImageProxy) {

        if (image.format == ImageFormat.YUV_420_888
            || image.format == ImageFormat.YUV_422_888
            || image.format == ImageFormat.YUV_444_888
        ) {

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
                val supportedHints: MutableMap<DecodeHintType, Any> = EnumMap(
                    DecodeHintType::class.java
                )
                supportedHints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
                val result = MultiFormatReader().decode(
                    binaryBitmap,
                    supportedHints
                )
                listener.invoke(result.text)
            } catch (e: FormatException) {
                e.fillInStackTrace()
            } catch (e: ChecksumException) {
                e.fillInStackTrace()
            } catch (e: NotFoundException) {
                e.fillInStackTrace()
            }catch (e : ArrayIndexOutOfBoundsException) {
                e.fillInStackTrace()
            }
        }
        image.close()
    }
}