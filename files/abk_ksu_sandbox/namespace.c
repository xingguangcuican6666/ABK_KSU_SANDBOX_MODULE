// SPDX-License-Identifier: GPL-3.0-only
/* ABK_KSU_SANDBOX_V1 */

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/jiffies.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/perf_event.h>
#include <linux/proc_ns.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <uapi/linux/mount.h>

#include "objsec.h"

#include "ksu.h"
#include "abk_sandbox.h"

extern int path_mount(const char *dev_name, struct path *path,
			      const char *type_page, unsigned long flags, void *data_page);

struct abk_mount_record;

struct abk_sandbox_instance {
	bool allocated;
	bool ready;
	bool revoking;
	u32 uid;
	u32 sid;
	unsigned int entrants;
	unsigned int mount_count;
	u64 tmpfs_bytes;
	struct file *namespace_file;
	struct abk_mount_record *mounts;
};

struct abk_revoke_work {
	struct delayed_work work;
	u32 uid;
	unsigned int retries;
};

enum abk_mount_state {
	ABK_MOUNT_FREE,
	ABK_MOUNT_PENDING,
	ABK_MOUNT_TRACKED,
};

struct abk_mount_record {
	enum abk_mount_state state;
	struct task_struct *owner;
	struct vfsmount *mnt;
	u64 bytes;
};

static DEFINE_MUTEX(abk_instance_mutex);
static struct abk_sandbox_instance
	abk_instances[ABK_SANDBOX_MAX_INSTANCES];

static struct abk_sandbox_instance *abk_find_ready_locked(u32 uid)
{
	unsigned int i;

	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (abk_instances[i].allocated && abk_instances[i].ready &&
		    abk_instances[i].uid == uid)
			return &abk_instances[i];
	}
	return NULL;
}

static bool abk_uid_revoking_locked(u32 uid)
{
	unsigned int i;

	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (abk_instances[i].allocated && abk_instances[i].uid == uid &&
		    abk_instances[i].revoking)
			return true;
	}
	return false;
}

static void
abk_release_unready_locked(struct abk_sandbox_instance *instance)
{
	if (!instance || instance->ready || instance->revoking ||
	    instance->entrants)
		return;
	kfree(instance->mounts);
	instance->mounts = NULL;
	instance->namespace_file = NULL;
	instance->mount_count = 0;
	instance->tmpfs_bytes = 0;
	instance->uid = 0;
	instance->sid = 0;
	smp_store_release(&instance->allocated, false);
}

static struct abk_sandbox_instance *abk_reserve_locked(u32 uid, u32 sid)
{
	struct abk_sandbox_instance *free_instance = NULL;
	unsigned int i;

	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (!abk_instances[i].allocated && !free_instance)
			free_instance = &abk_instances[i];
		if (abk_instances[i].allocated && !abk_instances[i].ready &&
		    !abk_instances[i].revoking &&
		    abk_instances[i].uid == uid && abk_instances[i].sid == sid)
			return &abk_instances[i];
	}
	if (!free_instance)
		return NULL;

	free_instance->uid = uid;
	free_instance->sid = sid;
	free_instance->mount_count = 0;
	free_instance->tmpfs_bytes = 0;
	free_instance->entrants = 0;
	free_instance->namespace_file = NULL;
	free_instance->mounts = NULL;
	free_instance->revoking = false;
	smp_store_release(&free_instance->allocated, true);
	return free_instance;
}

bool abk_sandbox_identity_matches(kuid_t origin_uid, u32 sid)
{
	u32 uid = __kuid_val(origin_uid);
	unsigned int i;

	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (!smp_load_acquire(&abk_instances[i].allocated))
			continue;
		if (READ_ONCE(abk_instances[i].uid) == uid &&
		    READ_ONCE(abk_instances[i].sid) == sid)
			return true;
	}
	return false;
}

static int abk_join_namespace_file(struct file *file)
{
	const struct cred *saved;
	struct ns_common *namespace;
	struct nsproxy *new_nsproxy;
	struct nsset nsset = { };
	int error;

	saved = override_creds(ksu_cred);
	error = ksys_unshare(CLONE_FS);
	if (error)
		goto out;
	error = unshare_nsproxy_namespaces(CLONE_NEWNS, &new_nsproxy,
					   NULL, current->fs);
	if (error)
		goto out;

	namespace = get_proc_ns(file_inode(file));
	if (!namespace || namespace->ops != &mntns_operations) {
		error = -EINVAL;
		goto out_put_nsproxy;
	}
	nsset.flags = CLONE_NEWNS;
	nsset.nsproxy = new_nsproxy;
	nsset.fs = current->fs;
	nsset.cred = ksu_cred;
	error = mntns_operations.install(&nsset, namespace);
	if (error)
		goto out_put_nsproxy;
	switch_task_namespaces(current, new_nsproxy);
	perf_event_namespaces(current);
	goto out;

out_put_nsproxy:
	put_nsproxy(new_nsproxy);

out:
	revert_creds(saved);
	fput(file);
	return error;
}

static int abk_create_private_namespace(struct file **file_out)
{
	const struct cred *saved;
	struct path namespace_path;
	struct path root_path;
	struct file *original_file = NULL;
	struct file *file;
	bool namespace_changed = false;
	int restore_error;
	long error;

	saved = override_creds(ksu_cred);
	error = ns_get_path(&namespace_path, current, &mntns_operations);
	if (error)
		goto out_revert;
	original_file = dentry_open(&namespace_path, O_RDONLY, ksu_cred);
	path_put(&namespace_path);
	if (IS_ERR(original_file)) {
		error = PTR_ERR(original_file);
		original_file = NULL;
		goto out_revert;
	}

	error = ksys_unshare(CLONE_NEWNS);
	if (error)
		goto out_revert;
	namespace_changed = true;

	get_fs_root(current->fs, &root_path);
	error = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
	path_put(&root_path);
	if (error)
		goto out_revert;

	error = ns_get_path(&namespace_path, current, &mntns_operations);
	if (error)
		goto out_revert;
	file = dentry_open(&namespace_path, O_RDONLY, ksu_cred);
	path_put(&namespace_path);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_revert;
	}
	*file_out = file;
	fput(original_file);
	original_file = NULL;
	error = 0;

out_revert:
	revert_creds(saved);
	if (error && namespace_changed && original_file) {
		restore_error = abk_join_namespace_file(original_file);
		original_file = NULL;
		if (restore_error)
			pr_err_ratelimited("ABK KSU Sandbox: failed to restore caller mount namespace: %d\n",
					   restore_error);
	}
	if (original_file)
		fput(original_file);
	return error;
}

int abk_sandbox_join_or_create_namespace(kuid_t origin_uid, u32 sid)
{
	struct abk_sandbox_instance *instance = NULL;
	struct file *namespace_file;
	u32 uid = __kuid_val(origin_uid);
	int error;

	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(uid);
	if (instance) {
		if (instance->sid != sid || instance->revoking) {
			error = -EKEYREJECTED;
			goto out_unlock;
		}
		instance->entrants++;
		namespace_file = get_file(instance->namespace_file);
		mutex_unlock(&abk_instance_mutex);
		error = abk_join_namespace_file(namespace_file);
		if (error)
			abk_sandbox_entry_complete(origin_uid, sid);
		return error;
	}
	if (abk_uid_revoking_locked(uid)) {
		error = -EKEYREVOKED;
		goto out_unlock;
	}

	instance = abk_reserve_locked(uid, sid);
	if (!instance) {
		error = -ENOSPC;
		goto out_unlock;
	}
	if (instance->revoking) {
		error = -EKEYREVOKED;
		goto out_unlock;
	}
	if (!instance->mounts) {
		instance->mounts = kcalloc(ABK_SANDBOX_MAX_MOUNTS,
					  sizeof(*instance->mounts), GFP_KERNEL);
		if (!instance->mounts) {
			error = -ENOMEM;
			goto out_unlock;
		}
	}

	error = abk_create_private_namespace(&namespace_file);
	if (error)
		goto out_unlock;
	instance->namespace_file = namespace_file;
	instance->entrants++;
	smp_store_release(&instance->ready, true);
	mutex_unlock(&abk_instance_mutex);
	return 0;

out_unlock:
	if (error)
		abk_release_unready_locked(instance);
	mutex_unlock(&abk_instance_mutex);
	return error;
}

void abk_sandbox_entry_complete(kuid_t origin_uid, u32 sid)
{
	u32 uid = __kuid_val(origin_uid);
	unsigned int i;

	mutex_lock(&abk_instance_mutex);
	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (!abk_instances[i].allocated || abk_instances[i].uid != uid ||
		    abk_instances[i].sid != sid)
			continue;
		if (abk_instances[i].entrants)
			abk_instances[i].entrants--;
		else
			pr_warn_ratelimited("ABK KSU Sandbox: unmatched entry completion uid=%u sid=%u\n",
					    uid, sid);
		break;
	}
	mutex_unlock(&abk_instance_mutex);
}

static bool abk_namespace_file_is_current(struct file *file)
{
	struct path current_namespace;
	bool matches = false;

	if (!ns_get_path(&current_namespace, current, &mntns_operations)) {
		matches = file_inode(file) == d_inode(current_namespace.dentry);
		path_put(&current_namespace);
	}
	return matches;
}

bool abk_sandbox_namespace_matches(kuid_t origin_uid)
{
	struct abk_sandbox_instance *instance;
	struct file *file = NULL;
	u32 uid = __kuid_val(origin_uid);
	bool matches;

	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(uid);
	if (instance && !instance->revoking)
		file = get_file(instance->namespace_file);
	mutex_unlock(&abk_instance_mutex);
	if (!file)
		return false;

	matches = abk_namespace_file_is_current(file);
	fput(file);
	return matches;
}

int abk_sandbox_mount_reserve(kuid_t origin_uid, u64 bytes)
{
	struct abk_sandbox_instance *instance;
	struct abk_mount_record *record = NULL;
	u32 uid = __kuid_val(origin_uid);
	unsigned int i;
	int error = 0;

	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(uid);
	if (!instance || instance->revoking) {
		error = -EACCES;
		goto out;
	}
	if (instance->mount_count >= ABK_SANDBOX_MAX_MOUNTS) {
		error = -EDQUOT;
		goto out;
	}
	if (bytes > ABK_SANDBOX_TMPFS_LIMIT - instance->tmpfs_bytes) {
		error = -EDQUOT;
		goto out;
	}
	for (i = 0; i < ABK_SANDBOX_MAX_MOUNTS; i++) {
		if (instance->mounts[i].state == ABK_MOUNT_FREE) {
			record = &instance->mounts[i];
			break;
		}
	}
	if (!record) {
		error = -EDQUOT;
		goto out;
	}
	record->state = ABK_MOUNT_PENDING;
	record->owner = current;
	record->mnt = NULL;
	record->bytes = bytes;
	instance->mount_count++;
	instance->tmpfs_bytes += bytes;

out:
	mutex_unlock(&abk_instance_mutex);
	return error;
}

static struct abk_mount_record *
abk_pending_mount_locked(struct abk_sandbox_instance *instance)
{
	unsigned int i;

	for (i = 0; i < ABK_SANDBOX_MAX_MOUNTS; i++) {
		if (instance->mounts[i].state == ABK_MOUNT_PENDING &&
		    instance->mounts[i].owner == current)
			return &instance->mounts[i];
	}
	return NULL;
}

static void abk_clear_mount_locked(struct abk_sandbox_instance *instance,
				   struct abk_mount_record *record)
{
	if (instance->mount_count)
		instance->mount_count--;
	if (record->bytes <= instance->tmpfs_bytes)
		instance->tmpfs_bytes -= record->bytes;
	record->state = ABK_MOUNT_FREE;
	record->owner = NULL;
	record->mnt = NULL;
	record->bytes = 0;
}

void abk_sandbox_mount_result(const struct path *path, int error)
{
	struct abk_sandbox_instance *instance;
	struct abk_mount_record *record;
	struct path mounted;
	struct vfsmount *mnt = NULL;
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return;
	if (!error && path) {
		mounted = *path;
		path_get(&mounted);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		while (follow_down(&mounted, 0))
#else
		while (follow_down(&mounted))
#endif
			;
		mnt = mntget(mounted.mnt);
		path_put(&mounted);
	}

	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(__kuid_val(origin_uid));
	if (!instance || !instance->mounts)
		goto out_unlock;
	record = abk_pending_mount_locked(instance);
	if (!record)
		goto out_unlock;
	if (error || !mnt) {
		abk_clear_mount_locked(instance, record);
	} else {
		record->state = ABK_MOUNT_TRACKED;
		record->owner = NULL;
		record->mnt = mnt;
		mnt = NULL;
	}

out_unlock:
	mutex_unlock(&abk_instance_mutex);
	if (mnt)
		mntput(mnt);
}

bool abk_sandbox_mount_is_tracked(kuid_t origin_uid,
				  const struct vfsmount *mnt)
{
	struct abk_sandbox_instance *instance;
	unsigned int i;
	bool tracked = false;

	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(__kuid_val(origin_uid));
	if (!instance || !instance->mounts)
		goto out;
	for (i = 0; i < ABK_SANDBOX_MAX_MOUNTS; i++) {
		if (instance->mounts[i].state == ABK_MOUNT_TRACKED &&
		    instance->mounts[i].mnt == mnt) {
			tracked = true;
			break;
		}
	}
out:
	mutex_unlock(&abk_instance_mutex);
	return tracked;
}

int abk_sandbox_umount_validate(const struct path *path, int flags)
{
	kuid_t origin_uid;

	if (!abk_sandbox_current(&origin_uid, NULL))
		return 0;
	if (!path || !abk_sandbox_namespace_matches(origin_uid))
		return -EPERM;
	if (path->dentry != path->mnt->mnt_root)
		return -EPERM;
	if (flags & ~UMOUNT_NOFOLLOW)
		return -EPERM;
	return abk_sandbox_mount_is_tracked(origin_uid, path->mnt) ? 0 : -EPERM;
}

void abk_sandbox_umount_result(const struct path *path, int error)
{
	struct abk_sandbox_instance *instance;
	struct abk_mount_record *record = NULL;
	struct vfsmount *mnt = NULL;
	kuid_t origin_uid;
	unsigned int i;

	if (error || !path || !abk_sandbox_current(&origin_uid, NULL))
		return;
	mutex_lock(&abk_instance_mutex);
	instance = abk_find_ready_locked(__kuid_val(origin_uid));
	if (!instance || !instance->mounts)
		goto out;
	for (i = 0; i < ABK_SANDBOX_MAX_MOUNTS; i++) {
		if (instance->mounts[i].state == ABK_MOUNT_TRACKED &&
		    instance->mounts[i].mnt == path->mnt) {
			record = &instance->mounts[i];
			mnt = record->mnt;
			abk_clear_mount_locked(instance, record);
			break;
		}
	}
out:
	mutex_unlock(&abk_instance_mutex);
	if (mnt)
		mntput(mnt);
}

void abk_ksu_sandbox_mount_result(const struct path *path, int error)
{
	abk_sandbox_mount_result(path, error);
}

int abk_ksu_sandbox_umount_validate(const struct path *path, int flags)
{
	return abk_sandbox_umount_validate(path, flags);
}

void abk_ksu_sandbox_umount_result(const struct path *path, int error)
{
	abk_sandbox_umount_result(path, error);
}

#define ABK_REVOKE_RETRIES 50U
#define ABK_REVOKE_DELAY_MS 100U

static bool abk_kill_instance_tasks(u32 uid)
{
	struct task_struct *group;
	struct task_struct *task;
	bool alive = false;

	rcu_read_lock();
	for_each_process_thread(group, task) {
		const struct cred *cred = __task_cred(task);
		const struct task_security_struct *tsec = selinux_cred(cred);

		if (tsec && __kuid_val(cred->fsuid) == uid &&
		    uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
		    abk_sandbox_identity_matches(cred->fsuid, tsec->sid) &&
		    !READ_ONCE(task->exit_state)) {
			alive = true;
			send_sig(SIGKILL, task, 1);
		}
	}
	rcu_read_unlock();
	return alive;
}

static void abk_revoke_detach_resources(u32 uid)
{
	struct vfsmount *mounts[ABK_SANDBOX_MAX_MOUNTS];
	struct abk_sandbox_instance *instance;
	struct file *file;
	unsigned int mount_count;
	unsigned int i;
	unsigned int j;

	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		file = NULL;
		mount_count = 0;
		mutex_lock(&abk_instance_mutex);
		if (abk_instances[i].allocated && abk_instances[i].uid == uid) {
			instance = &abk_instances[i];
			instance->revoking = true;
			file = instance->namespace_file;
			instance->namespace_file = NULL;
			if (instance->mounts) {
				for (j = 0; j < ABK_SANDBOX_MAX_MOUNTS; j++) {
					if (instance->mounts[j].mnt)
						mounts[mount_count++] =
							instance->mounts[j].mnt;
					memset(&instance->mounts[j], 0,
					       sizeof(instance->mounts[j]));
				}
			}
			instance->mount_count = 0;
			instance->tmpfs_bytes = 0;
			smp_store_release(&instance->ready, false);
		}
		mutex_unlock(&abk_instance_mutex);

		if (file)
			fput(file);
		for (j = 0; j < mount_count; j++)
			mntput(mounts[j]);
	}
}

static bool abk_revoke_has_entrants(u32 uid)
{
	unsigned int i;
	bool entrants = false;

	mutex_lock(&abk_instance_mutex);
	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (abk_instances[i].allocated && abk_instances[i].uid == uid &&
		    abk_instances[i].entrants) {
			entrants = true;
			break;
		}
	}
	mutex_unlock(&abk_instance_mutex);
	return entrants;
}

static void abk_revoke_release_slots(u32 uid)
{
	unsigned int i;

	mutex_lock(&abk_instance_mutex);
	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		struct abk_sandbox_instance *instance = &abk_instances[i];

		if (!instance->allocated || instance->uid != uid || instance->ready ||
		    instance->entrants)
			continue;
		kfree(instance->mounts);
		instance->mounts = NULL;
		instance->uid = 0;
		instance->sid = 0;
		instance->revoking = false;
		smp_store_release(&instance->allocated, false);
	}
	mutex_unlock(&abk_instance_mutex);
}

static void abk_revoke_worker(struct work_struct *work)
{
	struct abk_revoke_work *request =
		container_of(to_delayed_work(work), struct abk_revoke_work, work);

	abk_revoke_detach_resources(request->uid);
	if (abk_revoke_has_entrants(request->uid) ||
	    abk_kill_instance_tasks(request->uid)) {
		if (request->retries++ < ABK_REVOKE_RETRIES) {
			queue_delayed_work(system_unbound_wq, &request->work,
					   msecs_to_jiffies(ABK_REVOKE_DELAY_MS));
			return;
		}
		pr_warn_ratelimited("ABK KSU Sandbox: uid=%u did not exit; retaining identity slots\n",
				    request->uid);
		kfree(request);
		return;
	}
	abk_revoke_release_slots(request->uid);
	pr_info_ratelimited("ABK KSU Sandbox: revoked uid=%u\n", request->uid);
	kfree(request);
}

static void abk_mark_uid_revoking(u32 uid)
{
	unsigned int i;

	mutex_lock(&abk_instance_mutex);
	for (i = 0; i < ABK_SANDBOX_MAX_INSTANCES; i++) {
		if (!abk_instances[i].allocated || abk_instances[i].uid != uid)
			continue;
		abk_instances[i].revoking = true;
		smp_store_release(&abk_instances[i].ready, false);
	}
	mutex_unlock(&abk_instance_mutex);
}

void abk_sandbox_revoke_uid_async(uid_t uid)
{
	struct abk_revoke_work *request;

	abk_mark_uid_revoking(uid);
	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		abk_revoke_detach_resources(uid);
		abk_kill_instance_tasks(uid);
		pr_err_ratelimited("ABK KSU Sandbox: cannot queue revoke uid=%u; tasks killed and identity slots retained\n",
				   uid);
		return;
	}
	request->uid = uid;
	INIT_DELAYED_WORK(&request->work, abk_revoke_worker);
	queue_delayed_work(system_unbound_wq, &request->work, 0);
}

void abk_sandbox_revoke_namespace_async(kuid_t origin_uid)
{
	abk_sandbox_revoke_uid_async(__kuid_val(origin_uid));
}
