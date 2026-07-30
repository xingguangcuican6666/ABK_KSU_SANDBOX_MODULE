package dev.anybase.abksandbox.libsu;

import dev.anybase.abksandbox.smoke.ProbeActivity;
import dev.anybase.abksandbox.smoke.SuRunner;

public final class MainActivity extends ProbeActivity {
    @Override
    protected SuRunner createRunner() {
        return new LibsuRunner();
    }

    @Override
    protected String peerPackageName() {
        return "dev.anybase.abksandbox.direct";
    }
}
