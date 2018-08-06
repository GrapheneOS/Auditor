// Based on https://github.com/dm77/barcodescanner/blob/1.9.8/zxing-sample/src/main/java/me/dm7/barcodescanner/zxing/sample/CustomViewFinderScannerActivity.java
//
// Copyright notice for reference code (not everything in this file):
//
// Copyright (c) 2014 Dushyanth Maguluru
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app.attestation.auditor;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Bundle;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ViewGroup;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.Result;

import java.util.Collections;

import me.dm7.barcodescanner.core.IViewFinder;
import me.dm7.barcodescanner.core.ViewFinderView;
import me.dm7.barcodescanner.zxing.ZXingScannerView;

public class QRScannerActivity extends Activity implements ZXingScannerView.ResultHandler {
    static final String EXTRA_SCAN_RESULT = "app.attestation.auditor.SCAN_RESULT";

    private ZXingScannerView scannerView;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_qrscanner);
        final ViewGroup contentFrame = findViewById(R.id.content_frame);
        scannerView = new ZXingScannerView(this) {
            @Override
            protected IViewFinder createViewFinderView(Context context) {
                return new SquareViewFinderView(context);
            }
        };
        contentFrame.addView(scannerView);
        scannerView.setFormats(Collections.singletonList(BarcodeFormat.QR_CODE));
    }

    @Override
    public void onResume() {
        super.onResume();
        scannerView.setResultHandler(this);
        scannerView.startCamera();
    }

    @Override
    public void onPause() {
        super.onPause();
        scannerView.stopCamera();
    }

    @Override
    public void handleResult(Result rawResult) {
        final Intent result = new Intent();
        result.putExtra(EXTRA_SCAN_RESULT, rawResult.getText());
        setResult(Activity.RESULT_OK, result);
        scannerView.stopCamera();
        finish();
    }

    private static class SquareViewFinderView extends ViewFinderView {
        private static final int LABEL_TEXT_SIZE_SP = 14;
        private final Paint paint = new Paint();
        private String labelText;

        public SquareViewFinderView(final Context context) {
            super(context);
            init(context);
        }

        public SquareViewFinderView(final Context context, final AttributeSet attrs) {
            super(context, attrs);
            init(context);
        }

        private void init(final Context context) {
            labelText = context.getString(R.string.scanner_label);
            paint.setColor(Color.WHITE);
            paint.setAntiAlias(true);
            final float textPixelSize = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP,
                    LABEL_TEXT_SIZE_SP, getResources().getDisplayMetrics());
            paint.setTextSize(textPixelSize);
            setSquareViewFinder(true);
        }

        @Override
        public void onDraw(final Canvas canvas) {
            super.onDraw(canvas);
            drawLabel(canvas);
        }

        private void drawLabel(final Canvas canvas) {
            final Rect framingRect = getFramingRect();
            final float labelTop;
            final float labelLeft;
            if (framingRect != null) {
                labelTop = framingRect.bottom + paint.getTextSize() + 10;
                labelLeft = framingRect.left;
            } else {
                labelTop = 10;
                labelLeft = canvas.getHeight() - paint.getTextSize() - 10;
            }
            canvas.drawText(labelText, labelLeft, labelTop, paint);
        }
    }
}
