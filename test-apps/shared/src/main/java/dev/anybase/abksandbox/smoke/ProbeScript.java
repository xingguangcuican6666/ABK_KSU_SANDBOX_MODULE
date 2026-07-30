package dev.anybase.abksandbox.smoke;

public final class ProbeScript {
    private ProbeScript() {}

    public static String build(
            int uid,
            int gid,
            String ownDataPath,
            String appMountNamespace,
            String appSeccomp,
            PeerTarget peer) {
        int appId = uid % 100000;
        String own = shellQuote(ownDataPath);
        String peerMarker = shellQuote(peer.markerPath());
        String appNamespace = shellQuote(appMountNamespace);
        String expectedSeccomp = shellQuote(appSeccomp);
        StringBuilder script = new StringBuilder(8192);

        script.append("pass() { printf 'PASS %s\\n' \"$1\"; }\n");
        script.append("fail() { printf 'FAIL %s :: %s\\n' \"$1\" \"$2\"; }\n");
        script.append("info() { printf 'INFO %s :: %s\\n' \"$1\" \"$2\"; }\n");
        script.append("uid=").append(uid).append("\n");
        script.append("gid=").append(gid).append("\n");
        script.append("appid=").append(appId).append("\n");
        script.append("own=").append(own).append("\n");
        script.append("app_ns=").append(appNamespace).append("\n");
        script.append("app_seccomp=").append(expectedSeccomp).append("\n");
        script.append("peer_pid=").append(peer.pid()).append("\n");
        script.append("peer_marker=").append(peerMarker).append("\n");
        script.append("printf 'ABK_SMOKE_V1 uid=%s gid=%s appid=%s\\n' \"$uid\" \"$gid\" \"$appid\"\n");

        script.append("identity=$(id 2>&1); info identity \"$identity\"\n");
        script.append("[ \"$(id -u)\" = 0 ] && pass euid-root || fail euid-root \"$(id -u)\"\n");
        script.append("[ \"$(id -g)\" = 0 ] && pass egid-root || fail egid-root \"$(id -g)\"\n");
        script.append("primary_groups=$(id -G 2>/dev/null); [ \"$primary_groups\" = 0 ] && pass supplementary-groups-empty || fail supplementary-groups-empty \"$primary_groups\"\n");

        script.append("ctx=$(cat /proc/self/attr/current 2>&1); info selinux-context \"$ctx\"\n");
        script.append("case \"$ctx\" in u:r:anybase_kernel_sandbox_${appid}:*) pass sandbox-context ;; *) fail sandbox-context \"$ctx\" ;; esac\n");
        script.append("if [ -r /sys/kernel/security/lsm ]; then lsm_list=$(cat /sys/kernel/security/lsm 2>&1); info active-lsms \"$lsm_list\"; case \"$lsm_list\" in abk_ksu_sandbox|*,abk_ksu_sandbox) pass sandbox-lsm-last ;; *) fail sandbox-lsm-last \"$lsm_list\" ;; esac; else info sandbox-lsm-last \"/sys/kernel/security/lsm unreadable\"; fi\n");

        script.append("uid_line=$(grep '^Uid:' /proc/self/status); gid_line=$(grep '^Gid:' /proc/self/status); info credential-uids \"$uid_line\"; info credential-gids \"$gid_line\"\n");
        script.append("set -- $uid_line; [ \"$2:$3:$4:$5\" = \"$uid:0:$uid:$uid\" ] && pass uid-shape-locked || fail uid-shape-locked \"$uid_line\"\n");
        script.append("set -- $gid_line; [ \"$2:$3:$4:$5\" = \"$gid:0:$gid:$gid\" ] && pass gid-shape-locked || fail gid-shape-locked \"$gid_line\"\n");

        script.append("caps=$(grep '^Cap\\(Inh\\|Prm\\|Eff\\|Bnd\\|Amb\\):' /proc/self/status); info capabilities \"$(printf '%s' \"$caps\" | tr '\\n' ';')\"\n");
        script.append("if printf '%s\\n' \"$caps\" | grep -Evq '^[^:]*:[[:space:]]*0000000000000000$'; then fail capabilities-empty \"non-zero capability set\"; else pass capabilities-empty; fi\n");

        script.append("sandbox_ns=$(readlink /proc/self/ns/mnt 2>&1); info mount-namespace \"$sandbox_ns (app=$app_ns)\"\n");
        script.append("[ \"$sandbox_ns\" != \"$app_ns\" ] && pass mount-namespace-private || fail mount-namespace-private \"namespace did not change\"\n");
        script.append("sandbox_seccomp=$(awk '/^Seccomp:/ { print $2 }' /proc/self/status); info seccomp \"$sandbox_seccomp (app=$app_seccomp)\"\n");
        script.append("[ \"$sandbox_seccomp\" = \"$app_seccomp\" ] && pass seccomp-preserved || fail seccomp-preserved \"app=$app_seccomp sandbox=$sandbox_seccomp\"\n");

        script.append("legal=\"$own/cache/abk-smoke/legal\"; mkdir -p \"$legal\"\n");
        script.append("if mount -t tmpfs -o \"size=1048576,uid=$uid,gid=$gid,mode=0700,nosuid,nodev\" tmpfs \"$legal\" 2>/dev/null; then if printf smoke > \"$legal/probe\" 2>/dev/null; then pass legal-tmpfs-mount; else fail legal-tmpfs-mount \"mounted but write failed\"; fi; umount \"$legal\" >/dev/null 2>&1 || fail legal-tmpfs-cleanup \"umount failed\"; else fail legal-tmpfs-mount \"mount rejected\"; fi\n");
        script.append("detach=\"$own/cache/abk-smoke/detach\"; mkdir -p \"$detach\"; if mount -t tmpfs -o \"size=1048576,uid=$uid,gid=$gid,mode=0700,nosuid,nodev\" tmpfs \"$detach\" 2>/dev/null; then if umount -l \"$detach\" 2>/dev/null; then fail lazy-umount-denied \"lazy detach unexpectedly succeeded\"; else pass lazy-umount-denied; umount \"$detach\" >/dev/null 2>&1 || fail lazy-umount-cleanup \"normal umount failed\"; fi; else fail lazy-umount-denied \"setup mount rejected\"; fi\n");
        script.append("invalid=\"$own/cache/abk-smoke/invalid\"; mkdir -p \"$invalid\"\n");
        script.append("if mount -o bind /dev \"$invalid\" 2>/dev/null; then fail invalid-bind-denied \"/dev bind unexpectedly succeeded\"; umount \"$invalid\" >/dev/null 2>&1; else pass invalid-bind-denied; fi\n");

        script.append("if [ -n \"$peer_marker\" ]; then if cat \"$peer_marker\" >/dev/null 2>&1; then fail cross-app-data-denied \"peer marker readable\"; else pass cross-app-data-denied; fi; else info cross-app-data-denied \"peer marker unavailable\"; fi\n");
        script.append("if [ \"$peer_pid\" -gt 0 ]; then if cat \"/proc/$peer_pid/status\" >/dev/null 2>&1; then fail cross-app-process-denied \"peer /proc status readable\"; else pass cross-app-process-denied; fi; else info cross-app-process-denied \"peer process unavailable\"; fi\n");
        script.append("printf 'ABK_SMOKE_DONE\\n'\n");
        return script.toString();
    }

    private static String shellQuote(String value) {
        if (value == null) {
            return "''";
        }
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
