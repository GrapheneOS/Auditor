package app.attestation.auditor

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Size
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

class QRScannerActivity : AppCompatActivity() {

    private val executor = Executors.newSingleThreadExecutor()

    public override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(R.layout.activity_qrscanner)
        startCamera()
    }

    public override fun onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }

    private fun startCamera() {
        val contentFrame = findViewById<PreviewView>(R.id.content_frame)
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

        val cameraController = LifecycleCameraController(this)
        cameraController.bindToLifecycle(this)
        cameraController.cameraSelector = cameraSelector

        cameraProviderFuture.addListener(
            {
                val cameraProvider: ProcessCameraProvider = cameraProviderFuture.get()

                val preview = Preview.Builder()
                    .build()
                    .also {
                        it.setSurfaceProvider(contentFrame.surfaceProvider)
                    }

                val imageAnalysis = ImageAnalysis.Builder()
                    .setTargetResolution(Size(1280, 720))
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                imageAnalysis.setAnalyzer(
                    executor,
                    QRCodeImageAnalyzer { response ->
                        if (response != null) {
                            handleResult(response)
                        }
                    }
                )
                try {
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        this,
                        cameraSelector,
                        preview,
                        imageAnalysis
                    )

                } catch (exc: Exception) {
                }

            },
            ContextCompat.getMainExecutor(this)
        )
    }

    private fun handleResult(rawResult : String) {
        val result = Intent()
        result.putExtra(EXTRA_SCAN_RESULT, rawResult)
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    companion object {
        const val EXTRA_SCAN_RESULT = "app.attestation.auditor.SCAN_RESULT"
    }
}
