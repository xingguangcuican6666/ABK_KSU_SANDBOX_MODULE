/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _LINUX_ABK_KSU_SANDBOX_H
#define _LINUX_ABK_KSU_SANDBOX_H

/* ABK_KSU_SANDBOX_V1 */

#include <linux/cred.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/types.h>

#ifdef CONFIG_KSU_ABK_SANDBOX
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
#else
static inline bool abk_ksu_sandbox_seccomp_allow_syscall(int nr)
{
	return false;
}

static inline bool abk_ksu_sandbox_may_mount(void)
{
	return false;
}

static inline int abk_ksu_sandbox_bind_validate(const struct path *source,
					 const struct path *target, bool recursive)
{
	return 0;
}

static inline bool abk_ksu_sandbox_may_ptrace(const struct cred *target)
{
	return false;
}

static inline bool
abk_ksu_sandbox_may_ptrace_task(const struct task_struct *target)
{
	return false;
}

static inline bool abk_ksu_sandbox_may_signal(const struct task_struct *target)
{
	return false;
}

static inline void abk_ksu_sandbox_mount_result(const struct path *path,
						 int error)
{
}

static inline int abk_ksu_sandbox_umount_validate(const struct path *path,
						   int flags)
{
	return 0;
}

static inline void abk_ksu_sandbox_umount_result(const struct path *path,
						  int error)
{
}
#endif

#endif /* _LINUX_ABK_KSU_SANDBOX_H */
