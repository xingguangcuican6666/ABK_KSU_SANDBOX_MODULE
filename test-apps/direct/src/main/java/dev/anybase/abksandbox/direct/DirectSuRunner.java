package dev.anybase.abksandbox.direct;

import dev.anybase.abksandbox.smoke.CommandResult;
import dev.anybase.abksandbox.smoke.SuRunner;
import dev.anybase.abksandbox.smoke.TimedProbeCommand;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class DirectSuRunner implements SuRunner {
    private static final long TERMINATION_GRACE_SECONDS = 2;
    private static final long OUTPUT_DRAIN_MILLIS = 2_000;
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;

    @Override
    public CommandResult run(String script) throws Exception {
        Process process = new ProcessBuilder("su", "-c", TimedProbeCommand.wrap(script))
                .redirectErrorStream(true)
                .start();
        OutputCollector collector = new OutputCollector(process.getInputStream());
        Thread reader = new Thread(collector, "abk-direct-su-output");
        reader.setDaemon(true);
        reader.start();

        try {
            if (!process.waitFor(TimedProbeCommand.LAUNCHER_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                boolean terminated = terminate(process);
                finishReader(reader, process.getInputStream());
                String suffix = terminated
                        ? "su launcher fallback timed out after 50 seconds\n"
                        : "su launcher fallback timed out after 50 seconds; termination unconfirmed\n";
                return new CommandResult(124, appendLine(collector.output(), suffix));
            }

            if (!finishReader(reader, process.getInputStream())) {
                return new CommandResult(125, appendLine(
                        collector.output(), "su output drain timed out after process exit\n"));
            }
            IOException readFailure = collector.failure();
            if (readFailure != null) {
                throw readFailure;
            }
            return new CommandResult(process.exitValue(), collector.output());
        } catch (InterruptedException exception) {
            terminate(process);
            reader.interrupt();
            Thread.currentThread().interrupt();
            throw exception;
        } finally {
            closeQuietly(process.getInputStream());
            closeQuietly(process.getOutputStream());
        }
    }

    private static boolean terminate(Process process) {
        closeQuietly(process.getOutputStream());
        process.destroy();
        try {
            if (process.waitFor(TERMINATION_GRACE_SECONDS, TimeUnit.SECONDS)) {
                return true;
            }
            process.destroyForcibly();
            return process.waitFor(TERMINATION_GRACE_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            return false;
        } finally {
            closeQuietly(process.getErrorStream());
        }
    }

    private static boolean finishReader(Thread reader, InputStream input)
            throws InterruptedException {
        reader.join(OUTPUT_DRAIN_MILLIS);
        if (!reader.isAlive()) {
            return true;
        }
        closeQuietly(input);
        reader.join(OUTPUT_DRAIN_MILLIS);
        if (reader.isAlive()) {
            reader.interrupt();
        }
        return false;
    }

    private static String appendLine(String output, String line) {
        if (output.isEmpty() || output.endsWith("\n")) {
            return output + line;
        }
        return output + "\n" + line;
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
            // Best-effort process cleanup.
        }
    }

    private static final class OutputCollector implements Runnable {
        private final InputStream input;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final AtomicReference<IOException> failure = new AtomicReference<>();
        private long discardedBytes;

        private OutputCollector(InputStream input) {
            this.input = input;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[4096];
            try {
                for (int count; (count = input.read(buffer)) != -1; ) {
                    synchronized (output) {
                        int retained = Math.min(count, MAX_OUTPUT_BYTES - output.size());
                        if (retained > 0) {
                            output.write(buffer, 0, retained);
                        }
                        discardedBytes += count - retained;
                    }
                }
            } catch (IOException exception) {
                failure.set(exception);
            }
        }

        private String output() {
            synchronized (output) {
                String retained = new String(output.toByteArray(), StandardCharsets.UTF_8);
                if (discardedBytes == 0) {
                    return retained;
                }
                return appendLine(retained, "[output truncated; discarded " + discardedBytes
                        + " bytes]\n");
            }
        }

        private IOException failure() {
            return failure.get();
        }
    }
}
