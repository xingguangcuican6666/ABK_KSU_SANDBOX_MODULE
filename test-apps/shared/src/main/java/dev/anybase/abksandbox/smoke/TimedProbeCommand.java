package dev.anybase.abksandbox.smoke;

public final class TimedProbeCommand {
    public static final long COMMAND_TIMEOUT_SECONDS = 45;
    public static final long LAUNCHER_TIMEOUT_SECONDS = 50;

    private static final String SHELL = "/system/bin/sh";
    private static final String TOYBOX = "/system/bin/toybox";

    private TimedProbeCommand() {}

    public static String wrap(String script) {
        StringBuilder wrapper = new StringBuilder(script.length() + 512);
        wrapper.append("abk_probe=''; abk_watchdog=''; ");
        wrapper.append("abk_cleanup() { ");
        wrapper.append("[ -z \"$abk_probe\" ] || ").append(TOYBOX)
                .append(" kill -KILL -\"$abk_probe\" 2>/dev/null; ");
        wrapper.append("[ -z \"$abk_watchdog\" ] || ").append(TOYBOX)
                .append(" kill -KILL -\"$abk_watchdog\" 2>/dev/null; ");
        wrapper.append("}; ");
        wrapper.append("trap 'exit 143' HUP INT TERM; trap 'abk_cleanup' EXIT; ");
        wrapper.append(TOYBOX).append(" setsid ").append(SHELL).append(" -c ")
                .append(shellQuote(script)).append(" & abk_probe=$!; ");
        StringBuilder watchdog = new StringBuilder(192);
        watchdog.append("sleep ").append(COMMAND_TIMEOUT_SECONDS).append("; ");
        watchdog.append(TOYBOX).append(" kill -TERM -\"$1\" 2>/dev/null")
                .append(" || exit 0; sleep 2; ");
        watchdog.append(TOYBOX).append(" kill -KILL -\"$1\" 2>/dev/null");
        wrapper.append(TOYBOX).append(" setsid ").append(SHELL).append(" -c ")
                .append(shellQuote(watchdog.toString()))
                .append(" abk-watchdog \"$abk_probe\" & abk_watchdog=$!; ");
        wrapper.append("wait \"$abk_probe\"; abk_rc=$?; exit \"$abk_rc\"");
        return SHELL + " -c " + shellQuote(wrapper.toString());
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
