// SPDX-License-Identifier: GPL-3.0-only
/* ABK_KSU_SANDBOX_V1 */

#include <asm/unistd.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/ratelimit.h>
#include <linux/security.h>
#include <linux/securebits.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <net/sock.h>
#include <uapi/linux/mount.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <uapi/linux/lsm.h>
#endif

#include "objsec.h"
#include "security.h"

#include "abk_sandbox.h"
#include "lsm_build_config.h"
#include "lsm_order.h"

#define ABK_TMPFS_DATA_MAX PAGE_SIZE

static bool abk_lsm_ready __ro_after_init;

bool abk_sandbox_lsm_ready(void)
{
	return READ_ONCE(abk_lsm_ready);
}

static bool abk_cred_is_sandbox_peer(const struct cred *cred,
				     kuid_t origin_uid)
{
	const struct task_security_struct *tsec;

	if (!cred || !uid_eq(cred->uid, origin_uid) ||
	    !uid_eq(cred->suid, origin_uid) ||
	    !uid_eq(cred->euid, GLOBAL_ROOT_UID) ||
	    !uid_eq(cred->fsuid, origin_uid) ||
	    !gid_eq(cred->gid, cred->fsgid) ||
	    !gid_eq(cred->sgid, cred->fsgid) ||
	    !gid_eq(cred->egid, GLOBAL_ROOT_GID))
		return false;
	tsec = selinux_cred(cred);
	return tsec && abk_sandbox_identity_matches(origin_uid, tsec->sid);
}

bool abk_ksu_sandbox_may_ptrace(const struct cred *target)
{
	kuid_t origin_uid;

	if (!target || !abk_sandbox_current(&origin_uid, NULL))
		return false;
	return abk_cred_is_sandbox_peer(target, origin_uid);
}

bool abk_ksu_sandbox_may_ptrace_task(const struct task_struct *target)
{
	const struct cred *cred;
	bool allowed;

	if (!target)
		return false;
	rcu_read_lock();
	cred = __task_cred(target);
	allowed = abk_ksu_sandbox_may_ptrace(cred);
	rcu_read_unlock();
	return allowed;
}

bool abk_ksu_sandbox_may_signal(const struct task_struct *target)
{
	return abk_ksu_sandbox_may_ptrace_task(target);
}

bool abk_ksu_sandbox_seccomp_allow_syscall(int nr)
{
	if (!abk_sandbox_current(NULL, NULL))
		return false;
#ifdef __NR_mount
	if (nr == __NR_mount)
		return true;
#endif
#ifdef __NR_umount2
	if (nr == __NR_umount2)
		return true;
#endif
	return false;
}

bool abk_ksu_sandbox_may_mount(void)
{
	kuid_t origin_uid;

	return abk_sandbox_current(&origin_uid, NULL) &&
		abk_sandbox_namespace_matches(origin_uid);
}

static int abk_path_context(const struct path *path, char **context_out,
			    u32 *length_out)
{
	struct inode_security_struct *isec;
	struct inode *inode;

	if (!path || !path->dentry)
		return -EINVAL;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return -ENOENT;
	isec = selinux_inode(inode);
	if (!isec || READ_ONCE(isec->initialized) != LABEL_INITIALIZED)
		return -EACCES;
	return security_secid_to_secctx(READ_ONCE(isec->sid), context_out,
					length_out);
}

static bool abk_context_has_type(const char *context, u32 length,
				 const char *expected)
{
	const char *end = context + length;
	const char *first;
	const char *second;
	const char *third;
	size_t expected_length = strlen(expected);

	first = memchr(context, ':', end - context);
	if (!first)
		return false;
	second = memchr(first + 1, ':', end - first - 1);
	if (!second)
		return false;
	third = memchr(second + 1, ':', end - second - 1);
	if (!third)
		return false;
	return third - second - 1 == expected_length &&
		!strncmp(second + 1, expected, expected_length);
}

static bool abk_path_has_type(const struct path *path, const char *type)
{
	char *context;
	u32 length;
	bool matches;

	if (abk_path_context(path, &context, &length))
		return false;
	matches = abk_context_has_type(context, length, type);
	security_release_secctx(context, length);
	return matches;
}

bool abk_sandbox_path_is_own_data(const struct path *path, kuid_t origin_uid)
{
	struct inode *inode;

	if (!path || !path->dentry)
		return false;
	inode = d_backing_inode(path->dentry);
	if (!inode || !uid_eq(inode->i_uid, origin_uid))
		return false;
	return abk_path_has_type(path, "app_data_file");
}

bool abk_sandbox_path_is_readonly_system(const struct path *path)
{
	if (!path || !path->mnt || !(path->mnt->mnt_flags & MNT_READONLY))
		return false;
	return abk_path_has_type(path, "system_file") ||
		abk_path_has_type(path, "vendor_file");
}

static int abk_validate_bind_request(const char *source_name,
				     const struct path *target,
				     unsigned long flags, kuid_t origin_uid)
{
	const unsigned long allowed_flags = MS_BIND | MS_REC | MS_RDONLY |
		MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SILENT | MS_NOATIME |
		MS_NODIRATIME | MS_RELATIME;

	if (!source_name || flags & ~allowed_flags)
		return -EPERM;
	if (!abk_sandbox_path_is_own_data(target, origin_uid))
		return -EACCES;
	return 0;
}

int abk_ksu_sandbox_bind_validate(const struct path *source,
				  const struct path *target, bool recursive)
{
	struct inode *inode;
	kuid_t origin_uid;
	bool own_data;
	bool readonly_system;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!abk_sandbox_namespace_matches(origin_uid) || !source || !target)
		return -EACCES;
	if (!abk_sandbox_path_is_own_data(target, origin_uid))
		return -EACCES;

	inode = d_backing_inode(source->dentry);
	if (!inode || S_ISBLK(inode->i_mode)) {
		return -EACCES;
	}
	own_data = abk_sandbox_path_is_own_data(source, origin_uid);
	readonly_system = abk_sandbox_path_is_readonly_system(source);
	if (!own_data && !readonly_system)
		return -EACCES;
	/* A recursive clone could carry writable submounts below a read-only
	 * system mount.  Keep rbind limited to the caller's own data tree.
	 */
	if (recursive && readonly_system)
		return -EACCES;
	return abk_sandbox_mount_reserve(origin_uid, 0);
}

struct abk_tmpfs_options {
	bool have_size;
	bool have_uid;
	bool have_gid;
	bool have_mode;
	u64 size;
	u32 uid;
	u32 gid;
	unsigned int mode;
};

static int abk_parse_tmpfs_options(const void *data,
				   struct abk_tmpfs_options *options)
{
	char *copy;
	char *cursor;
	char *token;
	char *end;
	int error = 0;

	if (!data || strnlen(data, ABK_TMPFS_DATA_MAX) == ABK_TMPFS_DATA_MAX)
		return -EINVAL;
	copy = kstrdup(data, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	cursor = copy;
	while ((token = strsep(&cursor, ",")) != NULL) {
		if (!*token)
			continue;
		if (!strncmp(token, "size=", 5) && !options->have_size) {
			options->size = memparse(token + 5, &end);
			options->have_size = true;
			if (*end)
				error = -EINVAL;
		} else if (!strncmp(token, "uid=", 4) && !options->have_uid) {
			error = kstrtou32(token + 4, 10, &options->uid);
			options->have_uid = !error;
		} else if (!strncmp(token, "gid=", 4) && !options->have_gid) {
			error = kstrtou32(token + 4, 10, &options->gid);
			options->have_gid = !error;
		} else if (!strncmp(token, "mode=", 5) && !options->have_mode) {
			error = kstrtouint(token + 5, 8, &options->mode);
			options->have_mode = !error;
		} else if (strcmp(token, "nosuid") && strcmp(token, "nodev")) {
			error = -EINVAL;
		}
		if (error)
			break;
	}
	kfree(copy);
	return error;
}

static int abk_validate_tmpfs(const struct path *target, unsigned long flags,
			      const void *data, kuid_t origin_uid)
{
	const unsigned long allowed_flags = MS_NOSUID | MS_NODEV | MS_SILENT |
		MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
	struct abk_tmpfs_options options = { };
	int error;

	if (flags & ~allowed_flags)
		return -EPERM;
	if ((flags & (MS_NOSUID | MS_NODEV)) != (MS_NOSUID | MS_NODEV))
		return -EPERM;
	if (!abk_sandbox_path_is_own_data(target, origin_uid))
		return -EACCES;

	error = abk_parse_tmpfs_options(data, &options);
	if (error)
		return error;
	if (!options.have_size || !options.have_uid || !options.have_gid ||
	    !options.have_mode || !options.size ||
	    options.size > ABK_SANDBOX_TMPFS_LIMIT ||
	    options.uid != __kuid_val(origin_uid) ||
	    options.gid != __kgid_val(current_fsgid()) || options.mode != 0700)
		return -EINVAL;
	return abk_sandbox_mount_reserve(origin_uid, options.size);
}

static int abk_sb_mount(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data)
{
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!abk_sandbox_namespace_matches(origin_uid))
		return -EACCES;
	if (flags & MS_BIND)
		return abk_validate_bind_request(dev_name, path, flags, origin_uid);
	if (type && !strcmp(type, "tmpfs"))
		return abk_validate_tmpfs(path, flags, data, origin_uid);
	return -EPERM;
}

static int abk_sb_umount(struct vfsmount *mnt, int flags)
{
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!abk_sandbox_namespace_matches(origin_uid) ||
	    flags & ~UMOUNT_NOFOLLOW)
		return -EPERM;
	return abk_sandbox_mount_is_tracked(origin_uid, mnt) ? 0 : -EPERM;
}

static int abk_socket_create(int family, int type, int protocol, int kern)
{
	int base_type = type & SOCK_TYPE_MASK;

	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	if (family == AF_UNIX && !protocol &&
	    (base_type == SOCK_STREAM || base_type == SOCK_DGRAM))
		return 0;
	if (family == AF_INET || family == AF_INET6) {
		if (base_type == SOCK_STREAM &&
		    (!protocol || protocol == IPPROTO_TCP))
			return 0;
		if (base_type == SOCK_DGRAM &&
		    (!protocol || protocol == IPPROTO_UDP))
			return 0;
	}
	return -EAFNOSUPPORT;
}

static int abk_ptrace_access_check(struct task_struct *child,
				   unsigned int mode)
{
	const struct cred *cred;
	bool allowed;

	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	rcu_read_lock();
	cred = __task_cred(child);
	allowed = abk_ksu_sandbox_may_ptrace(cred);
	rcu_read_unlock();
	return allowed ? 0 : -EPERM;
}

static int abk_task_kill(struct task_struct *target,
			 struct kernel_siginfo *info, int sig,
			 const struct cred *cred)
{
	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	return abk_ksu_sandbox_may_signal(target) ? 0 : -EPERM;
}

static int abk_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	return uid_eq(new->uid, old->uid) && uid_eq(new->euid, old->euid) &&
		uid_eq(new->suid, old->suid) && uid_eq(new->fsuid, old->fsuid) ?
		0 : -EPERM;
}

static int abk_task_fix_setgid(struct cred *new, const struct cred *old,
			       int flags)
{
	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	return gid_eq(new->gid, old->gid) && gid_eq(new->egid, old->egid) &&
		gid_eq(new->sgid, old->sgid) && gid_eq(new->fsgid, old->fsgid) ?
		0 : -EPERM;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int abk_task_fix_setgroups(struct cred *new, const struct cred *old)
{
	if (!abk_sandbox_current(NULL, NULL))
		return 0;
	return new->group_info->ngroups == 0 ? 0 : -EPERM;
}
#endif

static int abk_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!bprm || !bprm->cred)
		return -EACCES;
	bprm->cred->fsuid = origin_uid;
	bprm->cred->fsgid = current_fsgid();
	bprm->cred->cap_inheritable = CAP_EMPTY_SET;
	bprm->cred->cap_permitted = CAP_EMPTY_SET;
	bprm->cred->cap_effective = CAP_EMPTY_SET;
	bprm->cred->cap_bset = CAP_EMPTY_SET;
	bprm->cred->cap_ambient = CAP_EMPTY_SET;
	return 0;
}

static int abk_bprm_check_security(struct linux_binprm *bprm)
{
	const struct task_security_struct *new_tsec;
	const struct task_security_struct *old_tsec;
	const struct cred *old;
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!bprm || !bprm->cred)
		return -EACCES;
	old = current_cred();
	if (!uid_eq(bprm->cred->uid, old->uid) ||
	    !uid_eq(bprm->cred->euid, old->euid) ||
	    !uid_eq(bprm->cred->suid, old->suid) ||
	    !uid_eq(bprm->cred->fsuid, origin_uid) ||
	    !gid_eq(bprm->cred->gid, old->gid) ||
	    !gid_eq(bprm->cred->egid, old->egid) ||
	    !gid_eq(bprm->cred->sgid, old->sgid) ||
	    !gid_eq(bprm->cred->fsgid, old->fsgid) ||
	    !bprm->cred->group_info || bprm->cred->group_info->ngroups != 0 ||
	    bprm->cred->securebits != old->securebits ||
	    !cap_isclear(bprm->cred->cap_inheritable) ||
	    !cap_isclear(bprm->cred->cap_permitted) ||
	    !cap_isclear(bprm->cred->cap_effective) ||
	    !cap_isclear(bprm->cred->cap_bset) ||
	    !cap_isclear(bprm->cred->cap_ambient))
		return -EPERM;
	old_tsec = selinux_cred(old);
	new_tsec = selinux_cred(bprm->cred);
	return old_tsec && new_tsec && old_tsec->sid == new_tsec->sid ? 0 : -EPERM;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static void abk_bprm_committing_creds(const struct linux_binprm *bprm)
#else
static void abk_bprm_committing_creds(struct linux_binprm *bprm)
#endif
{
	struct cred *cred;
	kuid_t origin_uid;
	kgid_t origin_gid;

	if (!bprm || !bprm->cred ||
	    !abk_sandbox_current(&origin_uid, NULL))
		return;
	cred = bprm->cred;
	origin_gid = current_fsgid();
	cred->uid = origin_uid;
	cred->suid = origin_uid;
	cred->euid = GLOBAL_ROOT_UID;
	cred->fsuid = origin_uid;
	cred->gid = origin_gid;
	cred->sgid = origin_gid;
	cred->egid = GLOBAL_ROOT_GID;
	cred->fsgid = origin_gid;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_EMPTY_SET;
	cred->cap_effective = CAP_EMPTY_SET;
	cred->cap_bset = CAP_EMPTY_SET;
	cred->cap_ambient = CAP_EMPTY_SET;
	cred->securebits = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
		SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |
		SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
		SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
}

static struct security_hook_list abk_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(sb_mount, abk_sb_mount),
	LSM_HOOK_INIT(sb_umount, abk_sb_umount),
	LSM_HOOK_INIT(socket_create, abk_socket_create),
	LSM_HOOK_INIT(ptrace_access_check, abk_ptrace_access_check),
	LSM_HOOK_INIT(task_kill, abk_task_kill),
	LSM_HOOK_INIT(task_fix_setuid, abk_task_fix_setuid),
	LSM_HOOK_INIT(task_fix_setgid, abk_task_fix_setgid),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	LSM_HOOK_INIT(task_fix_setgroups, abk_task_fix_setgroups),
#endif
	LSM_HOOK_INIT(bprm_creds_for_exec, abk_bprm_creds_for_exec),
	LSM_HOOK_INIT(bprm_check_security, abk_bprm_check_security),
	LSM_HOOK_INIT(bprm_committing_creds, abk_bprm_committing_creds),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static const struct lsm_id abk_lsm_id = {
	.name = "abk_ksu_sandbox",
	.id = LSM_ID_UNDEF,
};
#endif

static int __init abk_lsm_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	security_add_hooks(abk_hooks, ARRAY_SIZE(abk_hooks), &abk_lsm_id);
#else
	security_add_hooks(abk_hooks, ARRAY_SIZE(abk_hooks), "abk_ksu_sandbox");
#endif
	pr_info("ABK KSU Sandbox: LSM hooks registered\n");
	return 0;
}

static bool __init abk_lsm_list_contains(const char *list, const char *name)
{
	const char *match;
	size_t length;

	if (!list || !name)
		return false;
	length = strlen(name);
	match = list;
	while ((match = strstr(match, name)) != NULL) {
		if ((match == list || match[-1] == ',') &&
		    (match[length] == '\0' || match[length] == ','))
			return true;
		match += length;
	}
	return false;
}

static int __init abk_lsm_finalize(void)
{
	if (!lsm_names || !abk_lsm_list_contains(lsm_names, "selinux")) {
		pr_err("ABK KSU Sandbox: SELinux LSM is not active; sandbox entry disabled\n");
		return 0;
	}
	if (!abk_lsm_order_is_safe(lsm_names,
				   ABK_KSU_ALLOW_RUNTIME_KSU_TAIL)) {
		pr_err("ABK KSU Sandbox: unsafe LSM tail; expected sandbox%s (active=%s)\n",
#if ABK_KSU_ALLOW_RUNTIME_KSU_TAIL
		       "[,ksu]",
#else
		       "",
#endif
		       lsm_names);
		return 0;
	}
	WRITE_ONCE(abk_lsm_ready, true);
	pr_info("ABK KSU Sandbox: LSM mediation enabled (runtime_ksu_tail=%d)\n",
		ABK_KSU_ALLOW_RUNTIME_KSU_TAIL);
	return 0;
}
late_initcall(abk_lsm_finalize);

DEFINE_LSM(abk_ksu_sandbox) = {
	.name = "abk_ksu_sandbox",
	.order = LSM_ORDER_MUTABLE,
	.init = abk_lsm_init,
};
