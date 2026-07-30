package dev.anybase.abksandbox.smoke;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.system.Os;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public abstract class ProbeActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile PeerTarget peer = PeerTarget.unavailable();
    private volatile boolean peerBound;
    private TextView peerStatus;
    private TextView output;
    private Button runButton;

    private final ServiceConnection peerConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            try {
                IPeerProbe probe = IPeerProbe.Stub.asInterface(service);
                peer = new PeerTarget(probe.getPid(), probe.getMarkerPath());
                String markerStatus = peer.markerAvailable() ? "marker=ready" : "marker=unavailable";
                peerStatus.setText("Peer ready: " + name.getPackageName() + " pid=" + peer.pid()
                        + " " + markerStatus);
            } catch (Exception exception) {
                peer = PeerTarget.unavailable();
                peerStatus.setText("Peer unavailable: " + exception.getClass().getSimpleName());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            peer = PeerTarget.unavailable();
            peerStatus.setText("Peer disconnected: " + name.getPackageName());
        }
    };

    protected abstract SuRunner createRunner();

    protected abstract String peerPackageName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ensureOwnMarker();
        setContentView(createContentView());
        bindPeer();
    }

    @Override
    protected void onDestroy() {
        if (peerBound) {
            unbindService(peerConnection);
        }
        worker.shutdownNow();
        super.onDestroy();
    }

    private LinearLayout createContentView() {
        int padding = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText(getApplicationInfo().loadLabel(getPackageManager()));
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        peerStatus = new TextView(this);
        peerStatus.setText("Peer: connecting to " + peerPackageName());
        peerStatus.setPadding(0, dp(8), 0, dp(8));
        root.addView(peerStatus, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        runButton = new Button(this);
        runButton.setText("Run probes");
        runButton.setOnClickListener(view -> runProbes());
        root.addView(runButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        output = new TextView(this);
        output.setText("No probe run yet.");
        output.setTextIsSelectable(true);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(12);
        output.setPadding(0, dp(12), 0, 0);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1);
        root.addView(scroll, scrollParams);
        return root;
    }

    private void bindPeer() {
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(peerPackageName(), PeerPidService.class.getName()));
        try {
            peerBound = bindService(intent, peerConnection, Context.BIND_AUTO_CREATE);
            if (!peerBound) {
                peerStatus.setText("Peer unavailable: install and launch " + peerPackageName());
            }
        } catch (SecurityException exception) {
            peerStatus.setText("Peer bind denied: " + exception.getMessage());
        }
    }

    private void runProbes() {
        runButton.setEnabled(false);
        output.setText("Running...\n");
        PeerTarget peerSnapshot = peer;
        worker.execute(() -> {
            String result;
            try {
                String script = ProbeScript.build(
                        Process.myUid(),
                        Os.getgid(),
                        getDataDir().getAbsolutePath(),
                        Os.readlink("/proc/self/ns/mnt"),
                        readStatusValue("Seccomp"),
                        peerSnapshot);
                CommandResult command = createRunner().run(script);
                result = "launcher_exit=" + command.exitCode() + "\n" + command.output();
            } catch (Exception exception) {
                result = "LAUNCH_ERROR " + exception.getClass().getSimpleName() + ": "
                        + exception.getMessage() + "\n";
            }
            String finalResult = result;
            runOnUiThread(() -> {
                output.setText(finalResult);
                runButton.setEnabled(true);
            });
        });
    }

    private String readStatusValue(String key) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String prefix = key + ":";
            for (String line; (line = reader.readLine()) != null; ) {
                if (line.startsWith(prefix)) {
                    return line.substring(prefix.length()).trim();
                }
            }
        }
        return "missing";
    }

    private void ensureOwnMarker() {
        File marker = new File(getFilesDir(), PeerPidService.MARKER_NAME);
        String value = getPackageName() + ":" + Process.myUid() + ":" + Process.myPid() + "\n";
        try (FileOutputStream stream = new FileOutputStream(marker)) {
            stream.write(value.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // The peer binding status makes a missing marker visible during the run.
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
