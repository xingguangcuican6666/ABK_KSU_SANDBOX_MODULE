package dev.anybase.abksandbox.smoke;

public final class CommandResult {
    private final int exitCode;
    private final String output;

    public CommandResult(int exitCode, String output) {
        this.exitCode = exitCode;
        this.output = output;
    }

    public int exitCode() {
        return exitCode;
    }

    public String output() {
        return output;
    }
}
