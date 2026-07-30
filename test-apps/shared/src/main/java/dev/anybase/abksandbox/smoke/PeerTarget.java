package dev.anybase.abksandbox.smoke;

public final class PeerTarget {
    private final int pid;
    private final String markerPath;

    public PeerTarget(int pid, String markerPath) {
        this.pid = pid;
        this.markerPath = markerPath;
    }

    public static PeerTarget unavailable() {
        return new PeerTarget(-1, "");
    }

    public int pid() {
        return pid;
    }

    public String markerPath() {
        return markerPath;
    }

    public boolean available() {
        return processAvailable() && markerAvailable();
    }

    public boolean processAvailable() {
        return pid > 0;
    }

    public boolean markerAvailable() {
        return markerPath != null && !markerPath.isEmpty();
    }
}
