package app.attestation.auditor

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Size
import android.view.ViewTreeObserver
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.Camera
import androidx.camera.core.CameraProvider
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.MeteringPointFactory
import androidx.camera.core.Preview
import androidx.camera.core.SurfaceOrientedMeteringPointFactory
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import app.attestation.auditor.databinding.ActivityQrscannerBinding
import com.google.android.material.snackbar.Snackbar
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors

class QRScannerActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_SCAN_RESULT = "app.attestation.auditor.SCAN_RESULT"
        private const val autoCenterFocusDuration = 2000L
    }

    private var cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
    private lateinit var cameraController: LifecycleCameraController

    // Public as it is referenced in QRCodeImageAnalyzer
    lateinit var binding: ActivityQrscannerBinding

    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()

    private var focusTimerActive = false

    private lateinit var camera: Camera

    private val runnable = Runnable {
        val factory: MeteringPointFactory = SurfaceOrientedMeteringPointFactory(
            binding.contentFrame.width.toFloat(), binding.contentFrame.height.toFloat()
        )

        val autoFocusPoint = factory.createPoint(
            binding.contentFrame.width / 2.0f,
            binding.contentFrame.height / 2.0f, QROverlay.SIZE_FACTOR
        )

        camera.cameraControl.startFocusAndMetering(
            FocusMeteringAction.Builder(autoFocusPoint).disableAutoCancel().build()
        )

        startFocusTimer()
    }

    private fun startFocusTimer() {
        focusTimerActive = handler.postDelayed(runnable, autoCenterFocusDuration)
    }

    private fun cancelFocusTimer() {
        handler.removeCallbacks(runnable)
        focusTimerActive = false
    }

    public override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        binding = ActivityQrscannerBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)

        val insetsController = WindowCompat.getInsetsController(window, window.decorView)
        insetsController.isAppearanceLightStatusBars = false
        insetsController.isAppearanceLightNavigationBars = false

        binding.contentFrame.scaleType = PreviewView.ScaleType.FIT_CENTER

        cameraController = LifecycleCameraController(this)
        cameraController.bindToLifecycle(this)
        cameraController.cameraSelector = cameraSelector
        cameraController.setEnabledUseCases(CameraController.IMAGE_ANALYSIS)

        binding.overlay.viewTreeObserver.addOnGlobalLayoutListener(object :
            ViewTreeObserver.OnGlobalLayoutListener {
            override fun onGlobalLayout() {
                binding.overlay.viewTreeObserver.removeOnGlobalLayoutListener(this)
                startCamera()
            }
        })
    }

    override fun onResume() {
        super.onResume()
        if (::camera.isInitialized && !focusTimerActive) {
            startFocusTimer()
        }
    }

    override fun onPause() {
        super.onPause()
        if (focusTimerActive) {
            cancelFocusTimer()
        }
    }

    public override fun onDestroy() {
        super.onDestroy()
        executor.shutdown()
    }

    fun getOverlayView(): QROverlay {
        return binding.overlay
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener(fun() {
                val cameraProvider: CameraProvider
                try {
                    cameraProvider = cameraProviderFuture.get()
                } catch (exception: ExecutionException) {
                    Snackbar.make(binding.overlay, R.string.camera_provider_init_failure, Snackbar.LENGTH_LONG).show()
                    return
                }

                val preview = Preview.Builder()
                    .build()
                    .also {
                        it.setSurfaceProvider(binding.contentFrame.surfaceProvider)
                    }

                val strategy = ResolutionStrategy(Size(960, 960),
                    ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER)

                val imageAnalysis = ImageAnalysis.Builder().setResolutionSelector(
                    ResolutionSelector.Builder().setResolutionStrategy(strategy).build()).build()

                imageAnalysis.setAnalyzer(
                    executor,
                    QRCodeImageAnalyzer(this) { response ->
                        handleResult(response)
                    }
                )

                // Fallback to using front camera if rear camera is not available
                cameraSelector = if (cameraProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                    CameraSelector.DEFAULT_BACK_CAMERA
                } else {
                    CameraSelector.DEFAULT_FRONT_CAMERA
                }

                cameraController.cameraSelector = cameraSelector

                cameraProvider.unbindAll()
                try {
                    camera =
                        cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
                } catch (exception: IllegalArgumentException) {
                    Snackbar.make(binding.overlay, R.string.bind_failure, Snackbar.LENGTH_LONG).show()
                    return
                }
                startFocusTimer()
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
