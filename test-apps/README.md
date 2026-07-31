# ABK KSU Sandbox device smoke apps

These two deliberately small Android applications exercise the two supported `su`
entry paths:

- `direct` starts `ProcessBuilder("/system/bin/su", "-c", script)` directly.
- `libsu` explicitly opens `/system/bin/su` through
  `com.github.topjohnwu.libsu` and rejects its non-root shell fallback.

They are validation fixtures, not production applications. The exported peer service,
plain-text diagnostics, fixed package names, and intentionally hostile syscall probes
are appropriate only for a disposable test device.

## Workflow build

`.github/workflows/android-smoke-apps.yml` is the supported build path. Changes below
`test-apps/` trigger it automatically, and maintainers can also run **Android smoke
apps** with `workflow_dispatch`. The pinned workflow installs JDK 17, Gradle 8.9,
and Android SDK 35; assembles both debug APKs; verifies their signatures and ZIP
structure; records SHA-256 hashes; and uploads a 14-day
`abk-sandbox-smoke-apks-<commit>` artifact.

Extract that workflow artifact, then install both APKs:

```sh
adb install -r direct/build/outputs/apk/debug/direct-debug.apk
adb install -r libsu/build/outputs/apk/debug/libsu-debug.apk
```

If Android reports a debug-signature mismatch with an older workflow artifact,
uninstall both old fixtures, install the new APKs, and authorize them again in
KernelSU.

The workflow resolves libsu `5.2.2` from JitPack; that repository is content-filtered
to the `com.github.topjohnwu.libsu` group. No application dependency is shared
between the two modules; only the local probe code and AIDL interface are shared
through `shared/src/main`.

## Device acceptance run

Use an arm64 Android 12-16 device with a supported built-in KernelSU variant and the
ABK module installed. In KernelSU, authorize both test package names. Keep SELinux in
enforcing mode.

1. Launch both applications once. Each application binds the other application's
   peer service; wait until each header says `Peer ready`.
2. Tap **Run probes** in the direct application, then in the libsu application.
3. Save both complete outputs. A successful launch ends with `ABK_SMOKE_DONE` and
   `launcher_exit=0`.
4. Treat every `FAIL` line as a module failure. An `INFO cross-app-data-denied` or
   `INFO cross-app-process-denied` line means only that individual peer check was
   inconclusive; relaunch both apps and repeat it.
5. Revoke one app in KernelSU while its sandbox shell is active during an extended
   manual run. Confirm its sandbox tasks are killed, then re-authorize it and rerun.

The probes report and check:

- effective identity plus `/proc/self/status` UID, GID, supplementary groups, and all
  capability sets;
- the exact dynamic SELinux domain from `/proc/self/attr/current`;
- the runtime LSM list ends in `abk_ksu_sandbox`, or in
  `abk_ksu_sandbox,ksu` only for the installer-validated ReSukiSU
  5.10-6.6/SUSFS compatibility path, when the list is readable;
- mount namespace inode separation and preservation of the app's seccomp mode;
- a permitted 1 MiB tmpfs mount below the caller's own cache directory;
- rejection of lazy unmount while normal cleanup remains permitted;
- rejection of a bind mount whose source is `/dev`;
- rejection of reads from the peer application's private marker and `/proc/<pid>`.

Both launchers use Android Toybox `setsid` to put the probe in a dedicated session.
A watchdog signals the whole process group after 45 seconds and sends `SIGKILL` two
seconds later if needed; this avoids the process-group behavior difference between
the Android 12-13 and Android 14+ Toybox `timeout` implementations. A separate
50-second total launcher deadline is the final fallback and includes shell startup.
The libsu application creates a disposable shell for each run rather than sharing
its global cached shell. A watchdog timeout normally exits as `143` (`SIGTERM`) or
`137` (`SIGKILL`); launcher fallback uses `124`. Direct output is retained up to
1 MiB and then drained with an explicit truncation marker. The credential checks
require real/saved/fs UID/GID to remain the application identity while only effective
UID/GID become zero. Supplementary groups are read from the `Groups:` field in
`/proc/self/status`; `id -G` also prints the primary/effective group and is not a
valid empty-supplementary-group check. Tmpfs options use the original UID and GID
independently.

For a manual Termux check, run `/system/bin/su` explicitly. A bare `su` can report
`not found` because Termux's PATH does not necessarily include `/system/bin`; that
message alone does not show whether KernelSU accepted or rejected the request.

The legal mount is always unmounted before the probe exits. If an invalid bind mount
unexpectedly succeeds, the test reports `FAIL` and immediately attempts to unmount it
inside the sandbox's private mount namespace.
