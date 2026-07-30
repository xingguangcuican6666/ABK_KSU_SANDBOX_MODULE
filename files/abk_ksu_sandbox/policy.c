// SPDX-License-Identifier: GPL-3.0-only
/* ABK_KSU_SANDBOX_V1 */

#include <linux/bitmap.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/version.h>

#include "security.h"
#include "ss/services.h"
#include "uapi/selinux.h"
#include "xfrm.h"

#include "selinux/sepolicy.h"

#include "abk_sandbox.h"

#define ABK_SANDBOX_APPID_COUNT \
	(ABK_SANDBOX_APPID_MAX - ABK_SANDBOX_APPID_MIN + 1)

static DECLARE_BITMAP(abk_owned_types, ABK_SANDBOX_APPID_COUNT);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif

static void abk_reset_avc_cache(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	avc_ss_reset(0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(0);
#else
	avc_ss_reset(selinux_state.avc, 0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(&selinux_state, 0);
#endif
	selinux_xfrm_notify_policyload();
}

static int abk_type_name(uid_t appid, char *type, size_t size)
{
	int length;

	if (appid < ABK_SANDBOX_APPID_MIN || appid > ABK_SANDBOX_APPID_MAX)
		return -EINVAL;
	length = scnprintf(type, size, ABK_SANDBOX_DOMAIN_PREFIX "%u", appid);
	if (length <= 0 || length >= size)
		return -ENAMETOOLONG;
	return 0;
}

static bool abk_valid_mls(const char *mls)
{
	size_t i;
	size_t length;

	if (!mls)
		return false;
	length = strnlen(mls, 96);
	if (!length || length == 96)
		return false;
	for (i = 0; i < length; i++) {
		if (!isalnum(mls[i]) && mls[i] != ':' && mls[i] != ',' &&
		    mls[i] != '-' && mls[i] != '.')
			return false;
	}
	return true;
}

static int abk_allow(struct policydb *db, const char *source,
		     const char *target, const char *class, const char *permission)
{
	if (!ksu_allow(db, source, target, class, permission))
		return -EINVAL;
	return 0;
}

static int abk_allow_if_type(struct policydb *db, const char *source,
			     const char *target, const char *class,
			     const char *permission)
{
	if (!ksu_exists(db, target))
		return 0;
	return abk_allow(db, source, target, class, permission);
}

#define ABK_ALLOW(db, source, target, class, permission) do { \
	if (abk_allow((db), (source), (target), (class), (permission))) \
		return -EINVAL; \
} while (0)

#define ABK_ALLOW_IF(db, source, target, class, permission) do { \
	if (abk_allow_if_type((db), (source), (target), (class), (permission))) \
		return -EINVAL; \
} while (0)

static int abk_install_rules(struct policydb *db, const char *type,
			     bool create_type)
{
	if (create_type) {
		if (!ksu_type(db, type, "domain"))
			return -EINVAL;
	} else if (!ksu_exists(db, type)) {
		return -ENOENT;
	}

	/* netdomain carries Android's ordinary TCP/UDP routing and UID accounting. */
	if (ksu_exists(db, "netdomain") &&
	    !ksu_typeattribute(db, type, "netdomain"))
		return -EINVAL;

	ABK_ALLOW(db, type, type, "process", "fork");
	ABK_ALLOW(db, type, type, "process", "ptrace");
	ABK_ALLOW(db, type, type, "process", "signal");
	ABK_ALLOW(db, type, type, "process", "sigchld");
	ABK_ALLOW(db, type, type, "process", "sigkill");
	ABK_ALLOW(db, type, type, "process", "signull");
	ABK_ALLOW(db, type, type, "process", "sigstop");
	ABK_ALLOW(db, type, type, "process", "getattr");
	ABK_ALLOW(db, type, type, "process", "getpgid");
	ABK_ALLOW(db, type, type, "process", "getsched");
	ABK_ALLOW(db, type, type, "process", "setpgid");
	ABK_ALLOW(db, type, type, "process", "setsched");
	ABK_ALLOW(db, type, type, "fd", "use");
	ABK_ALLOW(db, type, type, "fifo_file", "create");
	ABK_ALLOW(db, type, type, "fifo_file", "open");
	ABK_ALLOW(db, type, type, "fifo_file", "read");
	ABK_ALLOW(db, type, type, "fifo_file", "write");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "create");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "connect");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "listen");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "accept");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "read");
	ABK_ALLOW(db, type, type, "unix_stream_socket", "write");
	ABK_ALLOW(db, type, type, "unix_dgram_socket", "create");
	ABK_ALLOW(db, type, type, "unix_dgram_socket", "read");
	ABK_ALLOW(db, type, type, "unix_dgram_socket", "write");

	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "getattr");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "open");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "read");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "search");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "write");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "add_name");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "mounton");
	ABK_ALLOW_IF(db, type, "app_data_file", "dir", "remove_name");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "create");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "getattr");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "open");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "read");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "write");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "append");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "map");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "lock");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "rename");
	ABK_ALLOW_IF(db, type, "app_data_file", "file", "unlink");

	ABK_ALLOW_IF(db, type, "system_file", "dir", "getattr");
	ABK_ALLOW_IF(db, type, "system_file", "dir", "open");
	ABK_ALLOW_IF(db, type, "system_file", "dir", "read");
	ABK_ALLOW_IF(db, type, "system_file", "dir", "search");
	ABK_ALLOW_IF(db, type, "system_file", "file", "execute");
	ABK_ALLOW_IF(db, type, "system_file", "file", "execute_no_trans");
	ABK_ALLOW_IF(db, type, "system_file", "file", "getattr");
	ABK_ALLOW_IF(db, type, "system_file", "file", "map");
	ABK_ALLOW_IF(db, type, "system_file", "file", "open");
	ABK_ALLOW_IF(db, type, "system_file", "file", "read");
	ABK_ALLOW_IF(db, type, "vendor_file", "dir", "getattr");
	ABK_ALLOW_IF(db, type, "vendor_file", "dir", "open");
	ABK_ALLOW_IF(db, type, "vendor_file", "dir", "read");
	ABK_ALLOW_IF(db, type, "vendor_file", "dir", "search");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "execute");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "execute_no_trans");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "getattr");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "map");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "open");
	ABK_ALLOW_IF(db, type, "vendor_file", "file", "read");

	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "create");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "getattr");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "open");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "read");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "search");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "write");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "add_name");
	ABK_ALLOW_IF(db, type, "tmpfs", "dir", "remove_name");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "create");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "execute");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "getattr");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "map");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "open");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "read");
	ABK_ALLOW_IF(db, type, "tmpfs", "file", "write");
	ABK_ALLOW_IF(db, type, "tmpfs", "filesystem", "getattr");
	ABK_ALLOW_IF(db, type, "tmpfs", "filesystem", "mount");
	ABK_ALLOW_IF(db, type, "tmpfs", "filesystem", "unmount");
	ABK_ALLOW_IF(db, type, "fs_type", "filesystem", "unmount");

	ABK_ALLOW_IF(db, type, "devpts", "chr_file", "getattr");
	ABK_ALLOW_IF(db, type, "devpts", "chr_file", "ioctl");
	ABK_ALLOW_IF(db, type, "devpts", "chr_file", "open");
	ABK_ALLOW_IF(db, type, "devpts", "chr_file", "read");
	ABK_ALLOW_IF(db, type, "devpts", "chr_file", "write");
	ABK_ALLOW_IF(db, type, "null_device", "chr_file", "getattr");
	ABK_ALLOW_IF(db, type, "null_device", "chr_file", "ioctl");
	ABK_ALLOW_IF(db, type, "null_device", "chr_file", "open");
	ABK_ALLOW_IF(db, type, "null_device", "chr_file", "read");
	ABK_ALLOW_IF(db, type, "null_device", "chr_file", "write");
	ABK_ALLOW_IF(db, type, "zero_device", "chr_file", "getattr");
	ABK_ALLOW_IF(db, type, "zero_device", "chr_file", "open");
	ABK_ALLOW_IF(db, type, "zero_device", "chr_file", "read");
	ABK_ALLOW_IF(db, type, "zero_device", "chr_file", "write");
	ABK_ALLOW_IF(db, type, "random_device", "chr_file", "getattr");
	ABK_ALLOW_IF(db, type, "random_device", "chr_file", "open");
	ABK_ALLOW_IF(db, type, "random_device", "chr_file", "read");
	ABK_ALLOW_IF(db, type, "random_device", "chr_file", "write");

	ABK_ALLOW_IF(db, type, "logd", "unix_stream_socket", "connectto");
	ABK_ALLOW_IF(db, type, "logdw_socket", "sock_file", "write");
	ABK_ALLOW_IF(db, type, "dnsproxyd_socket", "sock_file", "write");
	ABK_ALLOW_IF(db, type, "netd", "unix_stream_socket", "connectto");
	return 0;
}

int abk_sandbox_policy_reapply(struct policydb *db)
{
	char type[64];
	unsigned long bit;
	uid_t appid;
	int error;

	for_each_set_bit(bit, abk_owned_types, ABK_SANDBOX_APPID_COUNT) {
		appid = bit + ABK_SANDBOX_APPID_MIN;
		error = abk_type_name(appid, type, sizeof(type));
		if (error)
			return error;
		error = abk_install_rules(db, type, !ksu_exists(db, type));
		if (error)
			return error;
	}
	return 0;
}

int abk_sandbox_policy_ensure(uid_t appid, const char *mls, char *context,
			      size_t context_size)
{
	struct selinux_policy *old_policy;
	struct selinux_policy *new_policy;
	struct policydb *db;
	char type[64];
	unsigned int bit;
	int length;
	int error;

	error = abk_type_name(appid, type, sizeof(type));
	if (error)
		return error;
	if (!abk_valid_mls(mls))
		return -EINVAL;
	length = scnprintf(context, context_size, "u:r:%s:%s", type, mls);
	if (length <= 0 || length >= context_size)
		return -ENAMETOOLONG;

	bit = appid - ABK_SANDBOX_APPID_MIN;
	mutex_lock(&selinux_state.policy_mutex);
	old_policy = rcu_dereference_protected(selinux_state.policy,
				lockdep_is_held(&selinux_state.policy_mutex));
	if (!old_policy) {
		error = -EAGAIN;
		goto out_unlock;
	}
	db = &old_policy->policydb;
	if (ksu_exists(db, type)) {
		if (!test_bit(bit, abk_owned_types)) {
			error = -EEXIST;
			goto out_unlock;
		}
		error = 0;
		goto out_unlock;
	}
	if (bitmap_weight(abk_owned_types, ABK_SANDBOX_APPID_COUNT) >=
	    ABK_SANDBOX_MAX_INSTANCES) {
		error = -ENOSPC;
		goto out_unlock;
	}

	new_policy = ksu_dup_sepolicy(old_policy);
	if (IS_ERR(new_policy)) {
		error = PTR_ERR(new_policy);
		goto out_unlock;
	}
	error = abk_install_rules(&new_policy->policydb, type, true);
	if (error) {
		ksu_destroy_sepolicy(new_policy);
		goto out_unlock;
	}

	rcu_assign_pointer(selinux_state.policy, new_policy);
	synchronize_rcu();
	ksu_destroy_sepolicy(old_policy);
	set_bit(bit, abk_owned_types);
	abk_reset_avc_cache();
	error = 0;

out_unlock:
	mutex_unlock(&selinux_state.policy_mutex);
	return error;
}
