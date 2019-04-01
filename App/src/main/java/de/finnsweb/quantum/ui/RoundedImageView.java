package de.finnsweb.quantum.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;

import androidx.appcompat.widget.AppCompatImageView;

public class RoundedImageView extends AppCompatImageView {

    public RoundedImageView(Context context) {
        super(context);
    }

    public RoundedImageView(Context context, AttributeSet attributeSet){
        super(context,attributeSet);
    }

    @Override
    public void draw(Canvas canvas) {
        Path path = new Path();
        RectF r = new RectF(0 , 0, this.getWidth(), this.getHeight());
        path.addRoundRect(r, getWidth()*0.33F, getHeight()*0.33F, Path.Direction.CW);
        canvas.clipPath(path);
        super.draw(canvas);
    }
}
