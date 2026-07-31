package dev.anybase.abksandbox.libsu;

import com.topjohnwu.superuser.Shell;

import dev.anybase.abksandbox.smoke.CommandResult;
import dev.anybase.abksandbox.smoke.SuRunner;
import dev.anybase.abksandbox.smoke.TimedProbeCommand;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

final class LibsuRunner implements SuRunner {
    private static final long TERMINATION_GRACE_SECONDS = 2;

    @Override
    public CommandResult run(String script) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "abk-libsu-command");
            thread.setDaemon(true);
            return thread;
        });
        AtomicReference<Shell> activeShell = new AtomicReference<>();
        Future<CommandResult> command = executor.submit(() -> runInDedicatedShell(script, activeShell));
        try {
            return command.get(TimedProbeCommand.LAUNCHER_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException exception) {
            command.cancel(true);
            closeActiveShell(activeShell);
            executor.shutdownNow();
            boolean terminated = awaitTermination(executor);
            String output = terminated
                    ? "libsu launcher fallback timed out after 50 seconds\n"
                    : "libsu launcher fallback timed out after 50 seconds; termination unconfirmed\n";
            return new CommandResult(124, output);
        } catch (InterruptedException exception) {
            command.cancel(true);
            closeActiveShell(activeShell);
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            throw exception;
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new RuntimeException(cause);
        } finally {
            closeActiveShell(activeShell);
            executor.shutdownNow();
        }
    }

    private static CommandResult runInDedicatedShell(
            String script,
            AtomicReference<Shell> activeShell) throws Exception {
        Shell shell = Shell.Builder.create()
                .setFlags(Shell.FLAG_REDIRECT_STDERR)
                .setTimeout(20)
                .build("/system/bin/su");
        activeShell.set(shell);
        try {
            if (!shell.isRoot()) {
                throw new IOException(
                        "KernelSU root shell unavailable; refusing non-root fallback");
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("libsu probe cancelled during shell startup");
            }
            Shell.Result result = shell.newJob()
                    .add(TimedProbeCommand.wrap(script))
                    .to(new ArrayList<>())
                    .exec();
            return toCommandResult(result);
        } finally {
            activeShell.compareAndSet(shell, null);
            closeQuietly(shell);
        }
    }

    private static CommandResult toCommandResult(Shell.Result result) {
        List<String> output = new ArrayList<>(result.getOut());
        output.addAll(result.getErr());
        String joined = String.join("\n", output);
        if (!joined.isEmpty()) {
            joined += "\n";
        }
        return new CommandResult(result.getCode(), joined);
    }

    private static void closeActiveShell(AtomicReference<Shell> activeShell) {
        Shell shell = activeShell.getAndSet(null);
        if (shell != null) {
            closeQuietly(shell);
        }
    }

    private static boolean awaitTermination(ExecutorService executor) {
        try {
            return executor.awaitTermination(TERMINATION_GRACE_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void closeQuietly(Shell shell) {
        try {
            shell.close();
        } catch (IOException ignored) {
            // The runner reports the command or timeout result; a dedicated shell is disposable.
        }
    }
}
