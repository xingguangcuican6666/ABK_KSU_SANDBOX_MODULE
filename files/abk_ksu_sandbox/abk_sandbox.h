/* SPDX-License-Identifier: GPL-3.0-only */
/* ABK_KSU_SANDBOX_V1 */
#ifndef __KSU_ABK_SANDBOX_H
#define __KSU_ABK_SANDBOX_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/types.h>

#define ABK_SANDBOX_DOMAIN_PREFIX "anybase_kernel_sandbox_"
#define ABK_SANDBOX_ANDROID_UID_RANGE 100000U
#define ABK_SANDBOX_APPID_MIN 10000U
#define ABK_SANDBOX_APPID_MAX 19999U
#define ABK_SANDBOX_MAX_INSTANCES 256U
#define ABK_SANDBOX_MAX_MOUNTS 128U
#define ABK_SANDBOX_TMPFS_LIMIT (1ULL << 30)

struct policydb;

int abk_sandbox_try_escape(bool *handled);
void abk_sandbox_revoke_uid_async(uid_t uid);
bool abk_sandbox_lsm_ready(void);

int abk_sandbox_policy_ensure(uid_t appid, const char *mls, char *context,
			      size_t context_size);
int abk_sandbox_policy_reapply(struct policydb *db);

int abk_sandbox_join_or_create_namespace(kuid_t origin_uid, u32 sid);
void abk_sandbox_entry_complete(kuid_t origin_uid, u32 sid);
void abk_sandbox_revoke_namespace_async(kuid_t origin_uid);
bool abk_sandbox_namespace_matches(kuid_t origin_uid);
bool abk_sandbox_identity_matches(kuid_t origin_uid, u32 sid);
int abk_sandbox_mount_reserve(kuid_t origin_uid, u64 bytes);
void abk_sandbox_mount_result(const struct path *path, int error);
int abk_sandbox_umount_validate(const struct path *path, int flags);
void abk_sandbox_umount_result(const struct path *path, int error);
bool abk_sandbox_mount_is_tracked(kuid_t origin_uid,
				  const struct vfsmount *mnt);

bool abk_sandbox_current(kuid_t *origin_uid, uid_t *appid);
int abk_sandbox_context_is_eligible(char **mls_out);
bool abk_sandbox_path_is_own_data(const struct path *path, kuid_t origin_uid);
bool abk_sandbox_path_is_readonly_system(const struct path *path);

/* Thin-callsite API implemented by this directory and exposed to common code. */
bool abk_ksu_sandbox_seccomp_allow_syscall(int nr);
bool abk_ksu_sandbox_may_mount(void);
int abk_ksu_sandbox_bind_validate(const struct path *source,
				  const struct path *target, bool recursive);
bool abk_ksu_sandbox_may_ptrace(const struct cred *target);
bool abk_ksu_sandbox_may_ptrace_task(const struct task_struct *target);
bool abk_ksu_sandbox_may_signal(const struct task_struct *target);
void abk_ksu_sandbox_mount_result(const struct path *path, int error);
int abk_ksu_sandbox_umount_validate(const struct path *path, int flags);
void abk_ksu_sandbox_umount_result(const struct path *path, int error);

#endif /* __KSU_ABK_SANDBOX_H */
