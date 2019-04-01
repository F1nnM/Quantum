package de.finnsweb.quantum;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class App extends Application {

    private static Application sApplication;

    public static Application getApplication() {
        return sApplication;
    }

    public static Context getContext() {
        return getApplication().getApplicationContext();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sApplication = this;
        Log.d("FINN",getDatabasePath("Quantum").getAbsolutePath());
    }
}