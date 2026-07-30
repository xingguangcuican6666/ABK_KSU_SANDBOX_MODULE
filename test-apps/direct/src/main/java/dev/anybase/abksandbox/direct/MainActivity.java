package dev.anybase.abksandbox.direct;

import dev.anybase.abksandbox.smoke.ProbeActivity;
import dev.anybase.abksandbox.smoke.SuRunner;

public final class MainActivity extends ProbeActivity {
    @Override
    protected SuRunner createRunner() {
        return new DirectSuRunner();
    }

    @Override
    protected String peerPackageName() {
        return "dev.anybase.abksandbox.libsu";
    }
}
