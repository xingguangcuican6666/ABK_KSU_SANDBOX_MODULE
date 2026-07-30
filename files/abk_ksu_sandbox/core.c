// SPDX-License-Identifier: GPL-3.0-only
/* ABK_KSU_SANDBOX_V1 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/ratelimit.h>
#include <linux/securebits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "objsec.h"
#include "security.h"

#include "ksu.h"
#include "manager/manager_identity.h"
#include "selinux/selinux.h"

#include "abk_sandbox.h"

#define ABK_UNTRUSTED_PREFIX "untrusted_app"

static int abk_current_context(char **context_out, u32 *length_out)
{
	const struct task_security_struct *tsec;
	char *context;
	u32 length;
	int error;

	tsec = selinux_cred(current_cred());
	if (!tsec)
		return -EACCES;

	error = security_secid_to_secctx(tsec->sid, &context, &length);
	if (error)
		return error;

	*context_out = context;
	*length_out = length;
	return 0;
}

static int abk_context_type_and_mls(const char *context, u32 length,
				    const char **type_out, size_t *type_len_out,
				    const char **mls_out)
{
	const char *end = context + length;
	const char *first;
	const char *second;
	const char *third;

	first = memchr(context, ':', end - context);
	if (!first)
		return -EINVAL;
	second = memchr(first + 1, ':', end - first - 1);
	if (!second)
		return -EINVAL;
	third = memchr(second + 1, ':', end - second - 1);
	if (!third || third + 1 >= end)
		return -EINVAL;

	*type_out = second + 1;
	*type_len_out = third - second - 1;
	*mls_out = third + 1;
	return 0;
}

int abk_sandbox_context_is_eligible(char **mls_out)
{
	const char *type;
	const char *mls;
	char *context;
	size_t type_len;
	u32 length;
	int error;

	*mls_out = NULL;
	error = abk_current_context(&context, &length);
	if (error)
		return error;

	error = abk_context_type_and_mls(context, length, &type, &type_len, &mls);
	if (error)
		goto out;

	if (type_len < strlen(ABK_UNTRUSTED_PREFIX) ||
	    strncmp(type, ABK_UNTRUSTED_PREFIX, strlen(ABK_UNTRUSTED_PREFIX))) {
		error = 0;
		goto out;
	}

	*mls_out = kmemdup_nul(mls, context + length - mls, GFP_KERNEL);
	if (!*mls_out) {
		error = -ENOMEM;
		goto out;
	}
	error = 1;

out:
	security_release_secctx(context, length);
	return error;
}

bool abk_sandbox_current(kuid_t *origin_uid, uid_t *appid)
{
	const struct cred *cred = current_cred();
	const struct task_security_struct *tsec;
	kuid_t fsuid = cred->fsuid;
	uid_t raw_uid;
	uid_t raw_appid;

	if (!uid_eq(cred->uid, fsuid) || !uid_eq(cred->suid, fsuid) ||
	    !uid_eq(cred->euid, GLOBAL_ROOT_UID) ||
	    !gid_eq(cred->gid, cred->fsgid) || !gid_eq(cred->sgid, cred->fsgid) ||
	    !gid_eq(cred->egid, GLOBAL_ROOT_GID))
		return false;

	raw_uid = __kuid_val(fsuid);
	raw_appid = raw_uid % ABK_SANDBOX_ANDROID_UID_RANGE;
	if (raw_appid < ABK_SANDBOX_APPID_MIN ||
	    raw_appid > ABK_SANDBOX_APPID_MAX)
		return false;

	tsec = selinux_cred(current_cred());
	if (!tsec || !abk_sandbox_identity_matches(fsuid, tsec->sid))
		return false;

	if (origin_uid)
		*origin_uid = fsuid;
	if (appid)
		*appid = raw_appid;
	return true;
}

static int abk_prepare_sandbox_cred(struct cred *cred, kuid_t origin_uid,
				    kgid_t origin_gid, u32 target_sid)
{
	struct group_info *groups;
	struct task_security_struct *tsec;

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

	groups = groups_alloc(0);
	if (!groups)
		return -ENOMEM;
	set_groups(cred, groups);
	put_group_info(groups);

	tsec = selinux_cred(cred);
	if (!tsec)
		return -EACCES;
	tsec->sid = target_sid;
	tsec->exec_sid = 0;
	tsec->create_sid = 0;
	tsec->keycreate_sid = 0;
	tsec->sockcreate_sid = 0;
	return 0;
}

int abk_sandbox_try_escape(bool *handled)
{
	char target_context[128];
	struct cred *cred = NULL;
	kuid_t origin_uid;
	kgid_t origin_gid;
	uid_t raw_uid;
	uid_t appid;
	char *mls = NULL;
	u32 target_sid;
	bool entry_held = false;
	int eligible;
	int error;

	if (!handled)
		return -EINVAL;
	*handled = false;

	if (is_manager())
		return 0;

	origin_uid = current_uid();
	origin_gid = current_gid();
	raw_uid = __kuid_val(origin_uid);
	appid = raw_uid % ABK_SANDBOX_ANDROID_UID_RANGE;
	if (appid < ABK_SANDBOX_APPID_MIN || appid > ABK_SANDBOX_APPID_MAX)
		return 0;

	eligible = abk_sandbox_context_is_eligible(&mls);
	if (!eligible)
		return 0;
	if (eligible < 0) {
		*handled = true;
		return eligible;
	}

	*handled = true;
	if (!abk_sandbox_lsm_ready()) {
		error = -EACCES;
		goto out;
	}
	if (!getenforce()) {
		error = -EACCES;
		goto out;
	}

	error = abk_sandbox_policy_ensure(appid, mls, target_context,
					  sizeof(target_context));
	if (error)
		goto out;
	error = security_secctx_to_secid(target_context, strlen(target_context),
					 &target_sid);
	if (error)
		goto out;

	cred = prepare_creds();
	if (!cred) {
		error = -ENOMEM;
		goto out;
	}
	error = abk_prepare_sandbox_cred(cred, origin_uid, origin_gid, target_sid);
	if (error)
		goto out_abort;

	error = abk_sandbox_join_or_create_namespace(origin_uid, target_sid);
	if (error)
		goto out_abort;
	entry_held = true;

	commit_creds(cred);
	cred = NULL;
	abk_sandbox_entry_complete(origin_uid, target_sid);
	entry_held = false;
	pr_info_ratelimited("ABK KSU Sandbox: entered uid=%u appid=%u\n",
			    raw_uid, appid);
	error = 0;
	goto out;

out_abort:
	if (entry_held)
		abk_sandbox_entry_complete(origin_uid, target_sid);
	abort_creds(cred);
out:
	if (error)
		pr_warn_ratelimited("ABK KSU Sandbox: denied uid=%u appid=%u error=%d\n",
				    raw_uid, appid, error);
	kfree(mls);
	return error;
}
