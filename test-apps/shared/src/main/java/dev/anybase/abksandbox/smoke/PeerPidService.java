package dev.anybase.abksandbox.smoke;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class PeerPidService extends Service {
    public static final String MARKER_NAME = "abk-smoke-marker.txt";

    private final IPeerProbe.Stub binder = new IPeerProbe.Stub() {
        @Override
        public int getPid() {
            return Process.myPid();
        }

        @Override
        public String getMarkerPath() {
            File marker = markerFile();
            return marker.isFile() ? marker.getAbsolutePath() : "";
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        writeMarker();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    private File markerFile() {
        return new File(getFilesDir(), MARKER_NAME);
    }

    private void writeMarker() {
        String value = getPackageName() + ":" + Process.myUid() + ":" + Process.myPid() + "\n";
        try (FileOutputStream stream = new FileOutputStream(markerFile())) {
            stream.write(value.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // The activity reports an unavailable marker if app-private storage failed.
        }
    }
}
