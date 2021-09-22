package app.attestation.auditor

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Size
import android.view.ViewTreeObserver
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.MeteringPointFactory
import androidx.camera.core.Preview
import androidx.camera.core.SurfaceOrientedMeteringPointFactory
import androidx.camera.core.CameraInfoUnavailableException
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

class QRScannerActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_SCAN_RESULT = "app.attestation.auditor.SCAN_RESULT"
        private val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
        private val autoCenterFocusDuration = 2000L
    }

    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()

    private lateinit var overlayView: QROverlay
    private lateinit var camera: Camera
    lateinit var contentFrame: PreviewView

    private val runnable = Runnable {
        val factory: MeteringPointFactory = SurfaceOrientedMeteringPointFactory(
            contentFrame.width.toFloat(), contentFrame.height.toFloat()
        )

        val autoFocusPoint = factory.createPoint(contentFrame.width / 2.0f,
            contentFrame.height / 2.0f, overlayView.size.toFloat())

        camera.cameraControl.startFocusAndMetering(
            FocusMeteringAction.Builder(autoFocusPoint).disableAutoCancel().build()
        )

        startFocusTimer()
    }

    private fun startFocusTimer() {
        handler.postDelayed(runnable, autoCenterFocusDuration)
    }

    private fun cancelFocusTimer() {
        handler.removeCallbacks(runnable)
    }

    public override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(R.layout.activity_qrscanner)

        contentFrame = findViewById(R.id.content_frame)
        contentFrame.setScaleType(PreviewView.ScaleType.FIT_CENTER)

        overlayView = findViewById(R.id.overlay)
        overlayView.viewTreeObserver.addOnGlobalLayoutListener(object : ViewTreeObserver.OnGlobalLayoutListener {
            override fun onGlobalLayout() {
                overlayView.viewTreeObserver.removeOnGlobalLayoutListener(this)
                startCamera()
            }
        })

        val cameraController = LifecycleCameraController(this)
        cameraController.bindToLifecycle(this)
        cameraController.cameraSelector = cameraSelector
        cameraController.setEnabledUseCases(CameraController.IMAGE_ANALYSIS)
    }

    override fun onResume() {
        super.onResume()
        startFocusTimer()
    }

    override fun onPause() {
        super.onPause()
        cancelFocusTimer()
    }

    public override fun onDestroy() {
        super.onDestroy()
        executor.shutdown()
    }

    fun getOverlayView(): QROverlay {
        return overlayView
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener(
            {
                val cameraProvider = cameraProviderFuture.get()

                val preview = Preview.Builder()
                    .build()
                    .also {
                        it.setSurfaceProvider(contentFrame.surfaceProvider)
                    }

                val imageAnalysis = ImageAnalysis.Builder()
                    .setTargetResolution(Size(960, 960))
                    .build()

                imageAnalysis.setAnalyzer(
                    executor,
                    QRCodeImageAnalyzer (this) { response ->
                        if (response != null) {
                            handleResult(response)
                        }
                    }
                )

                cameraProvider.unbindAll()
                camera = cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
            },
            ContextCompat.getMainExecutor(this)
        )
    }

    private fun handleResult(rawResult: String) {
        val result = Intent()
        result.putExtra(EXTRA_SCAN_RESULT, rawResult)
        setResult(Activity.RESULT_OK, result)
        finish()
    }
}
