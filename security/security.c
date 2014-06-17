/*
 * Security plug functions
 *
 * Copyright (C) 2001 WireX Communications, Inc <chris@wirex.com>
 * Copyright (C) 2001-2002 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2001 Networks Associates Technology, Inc <ssmalley@nai.com>
 * Copyright (C) 2013 Intel Corporation
 * Copyright (C) 2013 Casey Schaufler <casey@schaufler-ca.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/lsm.h>
#include <linux/integrity.h>
#include <linux/ima.h>
#include <linux/evm.h>
#include <linux/fsnotify.h>
#include <net/flow.h>
#ifdef CONFIG_NETLABEL
#include <net/netlabel.h>
#endif

#define MAX_LSM_EVM_XATTR	2

struct list_head lsm_hooks[LSM_MAX_HOOKS];
static __initdata int lsm_order_set;
static __initdata int lsm_count;
static __initdata char *specified_lsms[LSM_SLOTS];
static __initdata char allowed_lsms[LSM_NAMES_MAX];

/*
 * Boot-time LSM user choice
 */
#define LSM_FIRST	"(first)"
#define LSM_ALL		"(all)"

#ifdef CONFIG_SECURITY_NETWORK_XFRM
struct security_operations *xfrm_ops;
EXPORT_SYMBOL(xfrm_ops);
#endif /* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_NETLABEL
struct security_operations *netlbl_ops;
#endif /* CONFIG_NETLABEL */
#ifdef CONFIG_NETWORK_SECMARK
struct security_operations *secmark_ops;
EXPORT_SYMBOL(secmark_ops);
#endif /* CONFIG_NETWORK_SECMARK */
struct security_operations *peersec_ops;
struct security_operations *present_ops;
static int (*present_getprocattr)
	(struct task_struct *p, char *name, char **value);
static int (*present_setprocattr)
	(struct task_struct *p, char *name, void *value, size_t size);

#define for_each_hook(SOP, HOOK) \
	list_for_each_entry(SOP, &lsm_hooks[lsm_##HOOK], list[lsm_##HOOK])

/*
 * Add an entry to a list of security operation vectors.
 * The "interesting" logic is included here rather than in the
 * caller to reduce the volume of the calling code.
 */
static void __init lsm_enlist(struct security_operations *ops,
			      const enum lsm_hooks_index index,
			      void *interesting)
{
	struct security_operations *sop;

	if (!interesting) {
		INIT_LIST_HEAD(&ops->list[index]);
		return;
	}

	if (list_empty(&lsm_hooks[index])) {
		list_add_rcu(&ops->list[index], &lsm_hooks[index]);
		return;
	}

	list_for_each_entry(sop, &lsm_hooks[index], list[index]) {
		if (ops->order < sop->order) {
			list_add_tail_rcu(&ops->list[index], &sop->list[index]);
			return;
		}
		if (list_is_last(&sop->list[index], &lsm_hooks[index])) {
			list_add_rcu(&ops->list[index], &sop->list[index]);
			return;
		}
	}
}

static void __init lsm_enlist_ops(struct security_operations *sop)
{
	lsm_enlist(sop, lsm_binder_set_context_mgr, sop->binder_set_context_mgr);
	lsm_enlist(sop, lsm_binder_transaction, sop->binder_transaction);
	lsm_enlist(sop, lsm_binder_transfer_binder, sop->binder_transfer_binder);
	lsm_enlist(sop, lsm_binder_transfer_file, sop->binder_transfer_file);
	lsm_enlist(sop, lsm_ptrace_access_check, sop->ptrace_access_check);
	lsm_enlist(sop, lsm_ptrace_traceme, sop->ptrace_traceme);
	lsm_enlist(sop, lsm_capget, sop->capget);
	lsm_enlist(sop, lsm_capset, sop->capset);
	lsm_enlist(sop, lsm_capable, sop->capable);
	lsm_enlist(sop, lsm_quotactl, sop->quotactl);
	lsm_enlist(sop, lsm_quota_on, sop->quota_on);
	lsm_enlist(sop, lsm_syslog, sop->syslog);
	lsm_enlist(sop, lsm_settime, sop->settime);
	lsm_enlist(sop, lsm_vm_enough_memory, sop->vm_enough_memory);
	lsm_enlist(sop, lsm_bprm_set_creds, sop->bprm_set_creds);
	lsm_enlist(sop, lsm_bprm_check_security, sop->bprm_check_security);
	lsm_enlist(sop, lsm_bprm_committing_creds, sop->bprm_committing_creds);
	lsm_enlist(sop, lsm_bprm_committed_creds, sop->bprm_committed_creds);
	lsm_enlist(sop, lsm_bprm_secureexec, sop->bprm_secureexec);
	lsm_enlist(sop, lsm_sb_alloc_security, sop->sb_alloc_security);
	lsm_enlist(sop, lsm_sb_free_security, sop->sb_free_security);
	lsm_enlist(sop, lsm_sb_copy_data, sop->sb_copy_data);
	lsm_enlist(sop, lsm_sb_remount, sop->sb_remount);
	lsm_enlist(sop, lsm_sb_kern_mount, sop->sb_kern_mount);
	lsm_enlist(sop, lsm_sb_show_options, sop->sb_show_options);
	lsm_enlist(sop, lsm_sb_statfs, sop->sb_statfs);
	lsm_enlist(sop, lsm_sb_mount, sop->sb_mount);
	lsm_enlist(sop, lsm_sb_umount, sop->sb_umount);
	lsm_enlist(sop, lsm_sb_pivotroot, sop->sb_pivotroot);
	lsm_enlist(sop, lsm_sb_set_mnt_opts, sop->sb_set_mnt_opts);
	lsm_enlist(sop, lsm_sb_clone_mnt_opts, sop->sb_clone_mnt_opts);
	lsm_enlist(sop, lsm_sb_parse_opts_str, sop->sb_parse_opts_str);
	lsm_enlist(sop, lsm_inode_alloc_security, sop->inode_alloc_security);
	lsm_enlist(sop, lsm_inode_free_security, sop->inode_free_security);
	lsm_enlist(sop, lsm_inode_init_security, sop->inode_init_security);
#ifdef CONFIG_SECURITY_PATH
	lsm_enlist(sop, lsm_path_mknod, sop->path_mknod);
	lsm_enlist(sop, lsm_path_mkdir, sop->path_mkdir);
	lsm_enlist(sop, lsm_path_rmdir, sop->path_rmdir);
	lsm_enlist(sop, lsm_path_unlink, sop->path_unlink);
	lsm_enlist(sop, lsm_path_symlink, sop->path_symlink);
	lsm_enlist(sop, lsm_path_link, sop->path_link);
	lsm_enlist(sop, lsm_path_rename, sop->path_rename);
	lsm_enlist(sop, lsm_path_truncate, sop->path_truncate);
	lsm_enlist(sop, lsm_path_chmod, sop->path_chmod);
	lsm_enlist(sop, lsm_path_chown, sop->path_chown);
	lsm_enlist(sop, lsm_path_chroot, sop->path_chroot);
#endif
	lsm_enlist(sop, lsm_inode_create, sop->inode_create);
	lsm_enlist(sop, lsm_inode_link, sop->inode_link);
	lsm_enlist(sop, lsm_inode_unlink, sop->inode_unlink);
	lsm_enlist(sop, lsm_inode_symlink, sop->inode_symlink);
	lsm_enlist(sop, lsm_inode_mkdir, sop->inode_mkdir);
	lsm_enlist(sop, lsm_inode_rmdir, sop->inode_rmdir);
	lsm_enlist(sop, lsm_inode_mknod, sop->inode_mknod);
	lsm_enlist(sop, lsm_inode_rename, sop->inode_rename);
	lsm_enlist(sop, lsm_inode_readlink, sop->inode_readlink);
	lsm_enlist(sop, lsm_inode_follow_link, sop->inode_follow_link);
	lsm_enlist(sop, lsm_inode_permission, sop->inode_permission);
	lsm_enlist(sop, lsm_inode_setattr, sop->inode_setattr);
	lsm_enlist(sop, lsm_inode_getattr, sop->inode_getattr);
	lsm_enlist(sop, lsm_inode_setxattr, sop->inode_setxattr);
	lsm_enlist(sop, lsm_inode_post_setxattr, sop->inode_post_setxattr);
	lsm_enlist(sop, lsm_inode_getxattr, sop->inode_getxattr);
	lsm_enlist(sop, lsm_inode_listxattr, sop->inode_listxattr);
	lsm_enlist(sop, lsm_inode_removexattr, sop->inode_removexattr);
	lsm_enlist(sop, lsm_inode_need_killpriv, sop->inode_need_killpriv);
	lsm_enlist(sop, lsm_inode_killpriv, sop->inode_killpriv);
	lsm_enlist(sop, lsm_inode_getsecurity, sop->inode_getsecurity);
	lsm_enlist(sop, lsm_inode_setsecurity, sop->inode_setsecurity);
	lsm_enlist(sop, lsm_inode_listsecurity, sop->inode_listsecurity);
	lsm_enlist(sop, lsm_inode_getsecid, sop->inode_getsecid);
	lsm_enlist(sop, lsm_file_permission, sop->file_permission);
	lsm_enlist(sop, lsm_file_alloc_security, sop->file_alloc_security);
	lsm_enlist(sop, lsm_file_free_security, sop->file_free_security);
	lsm_enlist(sop, lsm_file_ioctl, sop->file_ioctl);
	lsm_enlist(sop, lsm_file_mmap, sop->file_mmap);
	/* lsm_enlist(sop, lsm_mmap_addr, sop->mmap_addr); */
	lsm_enlist(sop, lsm_file_mprotect, sop->file_mprotect);
	lsm_enlist(sop, lsm_file_lock, sop->file_lock);
	lsm_enlist(sop, lsm_file_fcntl, sop->file_fcntl);
	lsm_enlist(sop, lsm_file_set_fowner, sop->file_set_fowner);
	lsm_enlist(sop, lsm_file_send_sigiotask, sop->file_send_sigiotask);
	lsm_enlist(sop, lsm_file_receive, sop->file_receive);
	lsm_enlist(sop, lsm_dentry_open, sop->dentry_open);
	/* lsm_enlist(sop, lsm_file_open, sop->file_open); */
	lsm_enlist(sop, lsm_task_create, sop->task_create);
	lsm_enlist(sop, lsm_task_free, sop->task_free);
	lsm_enlist(sop, lsm_cred_alloc_blank, sop->cred_alloc_blank);
	lsm_enlist(sop, lsm_cred_free, sop->cred_free);
	lsm_enlist(sop, lsm_cred_prepare, sop->cred_prepare);
	lsm_enlist(sop, lsm_cred_transfer, sop->cred_transfer);
	lsm_enlist(sop, lsm_kernel_act_as, sop->kernel_act_as);
	lsm_enlist(sop, lsm_kernel_create_files_as,
			sop->kernel_create_files_as);
	lsm_enlist(sop, lsm_kernel_module_request, sop->kernel_module_request);
	/* lsm_enlist(sop, lsm_kernel_module_from_file, */
	/* 		sop->kernel_module_from_file); */
	lsm_enlist(sop, lsm_task_fix_setuid, sop->task_fix_setuid);
	lsm_enlist(sop, lsm_task_setpgid, sop->task_setpgid);
	lsm_enlist(sop, lsm_task_getpgid, sop->task_getpgid);
	lsm_enlist(sop, lsm_task_getsid, sop->task_getsid);
	lsm_enlist(sop, lsm_task_getsecid, sop->task_getsecid);
	lsm_enlist(sop, lsm_task_setnice, sop->task_setnice);
	lsm_enlist(sop, lsm_task_setioprio, sop->task_setioprio);
	lsm_enlist(sop, lsm_task_getioprio, sop->task_getioprio);
	lsm_enlist(sop, lsm_task_setrlimit, sop->task_setrlimit);
	lsm_enlist(sop, lsm_task_setscheduler, sop->task_setscheduler);
	lsm_enlist(sop, lsm_task_getscheduler, sop->task_getscheduler);
	lsm_enlist(sop, lsm_task_movememory, sop->task_movememory);
	lsm_enlist(sop, lsm_task_kill, sop->task_kill);
	lsm_enlist(sop, lsm_task_wait, sop->task_wait);
	lsm_enlist(sop, lsm_task_prctl, sop->task_prctl);
	lsm_enlist(sop, lsm_task_to_inode, sop->task_to_inode);
	lsm_enlist(sop, lsm_ipc_permission, sop->ipc_permission);
	lsm_enlist(sop, lsm_ipc_getsecid, sop->ipc_getsecid);
	lsm_enlist(sop, lsm_msg_msg_alloc_security,
			sop->msg_msg_alloc_security);
	lsm_enlist(sop, lsm_msg_msg_free_security, sop->msg_msg_free_security);
	lsm_enlist(sop, lsm_msg_queue_alloc_security,
			sop->msg_queue_alloc_security);
	lsm_enlist(sop, lsm_msg_queue_free_security,
			sop->msg_queue_free_security);
	lsm_enlist(sop, lsm_msg_queue_associate, sop->msg_queue_associate);
	lsm_enlist(sop, lsm_msg_queue_msgctl, sop->msg_queue_msgctl);
	lsm_enlist(sop, lsm_msg_queue_msgsnd, sop->msg_queue_msgsnd);
	lsm_enlist(sop, lsm_msg_queue_msgrcv, sop->msg_queue_msgrcv);
	lsm_enlist(sop, lsm_shm_alloc_security, sop->shm_alloc_security);
	lsm_enlist(sop, lsm_shm_free_security, sop->shm_free_security);
	lsm_enlist(sop, lsm_shm_associate, sop->shm_associate);
	lsm_enlist(sop, lsm_shm_shmctl, sop->shm_shmctl);
	lsm_enlist(sop, lsm_shm_shmat, sop->shm_shmat);
	lsm_enlist(sop, lsm_sem_alloc_security, sop->sem_alloc_security);
	lsm_enlist(sop, lsm_sem_free_security, sop->sem_free_security);
	lsm_enlist(sop, lsm_sem_associate, sop->sem_associate);
	lsm_enlist(sop, lsm_sem_semctl, sop->sem_semctl);
	lsm_enlist(sop, lsm_sem_semop, sop->sem_semop);
	lsm_enlist(sop, lsm_d_instantiate, sop->d_instantiate);
	lsm_enlist(sop, lsm_getprocattr, sop->getprocattr);
	lsm_enlist(sop, lsm_setprocattr, sop->setprocattr);
	lsm_enlist(sop, lsm_netlink_send, sop->netlink_send);
	lsm_enlist(sop, lsm_secid_to_secctx, sop->secid_to_secctx);
	lsm_enlist(sop, lsm_secctx_to_secid, sop->secctx_to_secid);
	lsm_enlist(sop, lsm_release_secctx, sop->release_secctx);
	lsm_enlist(sop, lsm_inode_notifysecctx, sop->inode_notifysecctx);
	lsm_enlist(sop, lsm_inode_setsecctx, sop->inode_setsecctx);
	lsm_enlist(sop, lsm_inode_getsecctx, sop->inode_getsecctx);
#ifdef CONFIG_SECURITY_NETWORK
	lsm_enlist(sop, lsm_unix_stream_connect, sop->unix_stream_connect);
	lsm_enlist(sop, lsm_unix_may_send, sop->unix_may_send);
	lsm_enlist(sop, lsm_socket_create, sop->socket_create);
	lsm_enlist(sop, lsm_socket_post_create, sop->socket_post_create);
	lsm_enlist(sop, lsm_socket_bind, sop->socket_bind);
	lsm_enlist(sop, lsm_socket_connect, sop->socket_connect);
	lsm_enlist(sop, lsm_socket_listen, sop->socket_listen);
	lsm_enlist(sop, lsm_socket_accept, sop->socket_accept);
	lsm_enlist(sop, lsm_socket_sendmsg, sop->socket_sendmsg);
	lsm_enlist(sop, lsm_socket_recvmsg, sop->socket_recvmsg);
	lsm_enlist(sop, lsm_socket_getsockname, sop->socket_getsockname);
	lsm_enlist(sop, lsm_socket_getpeername, sop->socket_getpeername);
	lsm_enlist(sop, lsm_socket_getsockopt, sop->socket_getsockopt);
	lsm_enlist(sop, lsm_socket_setsockopt, sop->socket_setsockopt);
	lsm_enlist(sop, lsm_socket_shutdown, sop->socket_shutdown);
	lsm_enlist(sop, lsm_socket_sock_rcv_skb, sop->socket_sock_rcv_skb);
	lsm_enlist(sop, lsm_socket_getpeersec_stream,
			sop->socket_getpeersec_stream);
	lsm_enlist(sop, lsm_socket_getpeersec_dgram,
			sop->socket_getpeersec_dgram);
	lsm_enlist(sop, lsm_sk_alloc_security, sop->sk_alloc_security);
	lsm_enlist(sop, lsm_sk_free_security, sop->sk_free_security);
	lsm_enlist(sop, lsm_sk_clone_security, sop->sk_clone_security);
	lsm_enlist(sop, lsm_req_classify_flow, sop->req_classify_flow);
	lsm_enlist(sop, lsm_sock_graft, sop->sock_graft);
	lsm_enlist(sop, lsm_inet_conn_request, sop->inet_conn_request);
	lsm_enlist(sop, lsm_inet_csk_clone, sop->inet_csk_clone);
	lsm_enlist(sop, lsm_inet_conn_established, sop->inet_conn_established);
	lsm_enlist(sop, lsm_secmark_relabel_packet,
			sop->secmark_relabel_packet);
	lsm_enlist(sop, lsm_secmark_refcount_inc, sop->secmark_refcount_inc);
	lsm_enlist(sop, lsm_secmark_refcount_dec, sop->secmark_refcount_dec);
	lsm_enlist(sop, lsm_tun_dev_create, sop->tun_dev_create);
	lsm_enlist(sop, lsm_tun_dev_post_create, sop->tun_dev_post_create);
	lsm_enlist(sop, lsm_tun_dev_attach, sop->tun_dev_attach);
	/* lsm_enlist(sop, lsm_skb_owned_by, sop->skb_owned_by); */
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	lsm_enlist(sop, lsm_xfrm_policy_alloc_security,
			sop->xfrm_policy_alloc_security);
	lsm_enlist(sop, lsm_xfrm_policy_clone_security,
			sop->xfrm_policy_clone_security);
	lsm_enlist(sop, lsm_xfrm_policy_free_security,
			sop->xfrm_policy_free_security);
	lsm_enlist(sop, lsm_xfrm_policy_delete_security,
			sop->xfrm_policy_delete_security);
	lsm_enlist(sop, lsm_xfrm_state_alloc_security,
			sop->xfrm_state_alloc_security);
	lsm_enlist(sop, lsm_xfrm_state_delete_security,
			sop->xfrm_state_delete_security);
	lsm_enlist(sop, lsm_xfrm_state_free_security,
			sop->xfrm_state_free_security);
	lsm_enlist(sop, lsm_xfrm_policy_lookup, sop->xfrm_policy_lookup);
	lsm_enlist(sop, lsm_xfrm_state_pol_flow_match,
			sop->xfrm_state_pol_flow_match);
	lsm_enlist(sop, lsm_xfrm_decode_session, sop->xfrm_decode_session);
#endif
#ifdef CONFIG_KEYS
	lsm_enlist(sop, lsm_key_alloc, sop->key_alloc);
	lsm_enlist(sop, lsm_key_free, sop->key_free);
	lsm_enlist(sop, lsm_key_permission, sop->key_permission);
	lsm_enlist(sop, lsm_key_getsecurity, sop->key_getsecurity);
#endif
#ifdef CONFIG_AUDIT
	lsm_enlist(sop, lsm_audit_rule_init, sop->audit_rule_init);
	lsm_enlist(sop, lsm_audit_rule_known, sop->audit_rule_known);
	lsm_enlist(sop, lsm_audit_rule_free, sop->audit_rule_free);
	lsm_enlist(sop, lsm_audit_rule_match, sop->audit_rule_match);
#endif

	lsm_enlist(sop, lsm_name, sop->name);
}

/* Save user chosen LSM(s) */
static int __init choose_lsm(char *str)
{
	char *cp;
	char *ep;
	int i;

	if (lsm_order_set || !strcmp(str, LSM_ALL))
		return 1;
	lsm_order_set = 1;
	pr_info("LSM order requested is \"%s\".\n", str);

	strncpy(allowed_lsms, str, LSM_NAMES_MAX);
	cp = allowed_lsms;

	for (i = 0; i < LSM_SLOTS; i++) {
		ep = strchr(cp, ',');
		if (ep != NULL)
			*ep = '\0';
		if (strlen(cp) > SECURITY_NAME_MAX)
			pr_warn("LSM \"%s\" is invalid and ignored.\n", cp);
		else
			specified_lsms[i] = cp;
		if (ep == NULL)
			break;
		cp = ep + 1;
	}

	return 1;
}
__setup("security=", choose_lsm);


static void __init do_security_initcalls(void)
{
	initcall_t *call;

	call = __security_initcall_start;
	while (call < __security_initcall_end) {
		(*call) ();
		call++;
	}
}

/**
 * security_init - initializes the security framework
 *
 * This should be called early in the kernel initialization sequence.
 */
int __init security_init(void)
{
	enum lsm_hooks_index i;

	for (i = 0; i < LSM_MAX_HOOKS; i++)
		INIT_LIST_HEAD(&lsm_hooks[i]);

	(void) choose_lsm(CONFIG_DEFAULT_SECURITY);
	pr_info("Security Framework initialized\n");
	do_security_initcalls();

	if (present_ops)
		pr_info("Security Module %s presented in /proc/.../attr.\n",
			present_ops->name);
#ifdef CONFIG_NETLABEL
	/*
	 * Reserve the netlabel subsystem for the specified LSM.
	 */
	if (netlbl_ops) {
		i = netlbl_lsm_register(netlbl_ops);
		pr_info("Security Module %s %s Netlabel network labeling.\n",
			netlbl_ops->name, i ? "denied" : "uses");
	}
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	if (xfrm_ops)
		pr_info("Security Module %s uses XFRM network labeling.\n",
			xfrm_ops->name);
#endif
#ifdef CONFIG_NETWORK_SECMARK
	/*
	 * Reserve the networking secmark for the specified LSM.
	 */
	if (secmark_ops)
		pr_info("Security Module %s uses secmark network labeling.\n",
			secmark_ops->name);
#endif

	return 0;
}

/*
 * Only SELinux calls security_module_disable.
 */
#ifdef CONFIG_SECURITY_SELINUX_DISABLE

static void lsm_delist_ops(struct security_operations *sop)
{
	enum lsm_hooks_index i;

	for (i = 0; i < LSM_MAX_HOOKS; i++)
		if (sop->list[i].next && !list_empty(&sop->list[i]))
			list_del_rcu(&sop->list[i]);
	return;
}

/**
 * security_module_disable - Remove hooks for an LSM
 *
 * @ops: the security operations for the LSM
 *
 * Remove the hooks for the LSM from the lists of security operations.
 * This is not sufficient to "unregister" an LSM. The LSM will still
 * have a slot in the lsm_blob and as the hooks that implement freeing
 * of LSM data are removed memory leakage is almost certain to occur
 * if the module uses security blobs.
 */
void security_module_disable(struct security_operations *ops)
{
	/*
	 * This LSM is configured to own /proc/.../attr.
	 */
	if (present_ops == ops)
		present_ops = NULL;

	lsm_delist_ops(ops);
}

#endif /* CONFIG_SECURITY_SELINUX_DISABLE */

static int __init owns_feature(struct security_operations *fops,
			       struct security_operations *lops,
			       char *configured, int feature)
{
	if (!(lops->features & feature))
		return 0;
	if (!strcmp(lops->name, configured))
		return 1;
	if (strcmp(configured, LSM_FIRST))
		return 0;
	if (!fops || fops->order > lops->order)
		return 1;
	return 0;
}

/**
 * security_module_enable - Load given security module on boot ?
 * @ops: a pointer to the struct security_operations that is to be checked.
 *
 * Each LSM must pass this method before registering its own operations
 * to avoid security registration races. This method may also be used
 * to check if your LSM is currently loaded during kernel initialization.
 *
 * Return true if:
 *	-The passed LSM is chosen by user at boot time,
 *	-or the passed LSM is configured and the user did not
 *	 choose to exclude it at boot time.
 * Otherwise, return false.
 */
int __init security_module_enable(struct security_operations *ops)
{
	struct security_operations *sop;
	int i;
	/*
	 * Set up the operation vector early, but only once.
	 * This allows LSM specific file systems to check to see if they
	 * should come on line.
	 */
	if (ops == NULL) {
		pr_debug("%s could not verify security_operations.\n",
			 __func__);
		return 0;
 	}
	/*
	 * Return success if the LSM is already registered
	 */
	for_each_hook(sop, name)
		if (sop == ops)
			return 1;
	/*
	 * This LSM has not yet been ordered.
	 */
	ops->order = -1;


	if (lsm_count >= LSM_SLOTS) {
		pr_warn("Too many security modules. %s not loaded.\n",
			ops->name);
		return 0;
	}
	if (lsm_order_set) {
		for (i = 0; i < LSM_SLOTS && specified_lsms[i]; i++) {
			if (strcmp(ops->name, specified_lsms[i]) == 0) {
				ops->order = i;
				break;
			}
		}
		if (ops->order == -1) {
			pr_notice("LSM %s declined by boot options.\n",
				  ops->name);
			return 0;
		}
	}
	/*
	 * The order will already be set if the command line
	 * includes "security=" or CONFIG_DEFAULT_SECURITY was set.
	 * Do this before the enlisting.
	 */
	if (ops->order == -1)
		ops->order = lsm_count;
	lsm_count++;
	/*
	 * Allocate the features that require a dedicated module.
	 * Give the feature to the first module in the list that
	 * supports it unless explicitly told otherwise.
	 * If a module is specified that does not supply the
	 * required hooks don't assign the feature to anyone.
	 *
	 * CONFIG_PEERSEC_LSM
	 *      What shows up with SO_PEERSEC
	 * CONFIG_SECURITY_PRESENT
	 *      What shows up in /proc/.../attr/current
	 * CONFIG_NETLABEL_LSM
	 *      CIPSO networking
	 * CONFIG_XFRM_LSM
	 *      XFRM networking
	 * CONFIG_SECMARK_LSM
	 *      Networking secmark
	 */
	if (owns_feature(peersec_ops, ops, CONFIG_PEERSEC_LSM,
				LSM_FEATURE_PEERSEC))
		peersec_ops = ops;
	if (owns_feature(present_ops, ops, CONFIG_PRESENT_SECURITY,
			 LSM_FEATURE_PRESENT)) {
		present_ops = ops;
		present_getprocattr = ops->getprocattr;
		present_setprocattr = ops->setprocattr;
	}
#ifdef CONFIG_NETLABEL
	if (owns_feature(netlbl_ops, ops, CONFIG_NETLABEL_LSM,
			 LSM_FEATURE_NETLABEL))
		netlbl_ops = ops;
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	if (owns_feature(xfrm_ops, ops, CONFIG_XFRM_LSM, LSM_FEATURE_XFRM))
		xfrm_ops = ops;
#endif
#ifdef CONFIG_NETWORK_SECMARK
		if (owns_feature(secmark_ops, ops, CONFIG_SECMARK_LSM,
				 LSM_FEATURE_SECMARK))
			secmark_ops = ops;
#endif
	/*
	 * Return success after registering the LSM.
	 */
	lsm_enlist_ops(ops);

	return 1;
}

/* Security operations */

/*
 * Because so many of the cases are treated the same it
 * cleans things up to use these macros instead of having
 * duplicate text all over the place.
 *
 * call_void_hook:
 *	This is a hook that does not return a value.
 *
 * call_int_hook:
 *	This is a hook that returns a value. Return the last
 *	non-zero return.
 *
 * call_int_must:
 *	Returns 1 if any LSMs actually had hooks and one
 *	or more got called. The return value goes into RC.
 *
 * call_alloc_hook:
 *	Allocate not only the LSM security blobs, but a blob
 *	to hold pointers to all of them as well.
 *
 */
#define call_void_hook(FUNC, ...)					\
	do {								\
		struct security_operations *sop;			\
									\
		list_for_each_entry(sop, &lsm_hooks[lsm_##FUNC],	\
				    list[lsm_##FUNC])			\
			sop->FUNC(__VA_ARGS__);				\
	} while (0)							\

#define call_int_hook(FUNC, ...) ({					\
			int rc = 0;					\
			do {						\
				struct security_operations *sop;	\
				int thisrc;				\
									\
				list_for_each_entry(sop, &lsm_hooks[lsm_##FUNC], \
						    list[lsm_##FUNC]) {	\
					thisrc = sop->FUNC(__VA_ARGS__); \
					if (thisrc)			\
						rc = thisrc;		\
				}					\
			} while (0);					\
			rc;						\
		})
#define call_int_must(RC, FUNC, ...) ({					\
			int called = 0;					\
			RC = 0;						\
			do {						\
				struct security_operations *sop;	\
				int thisrc;				\
									\
				list_for_each_entry(sop, &lsm_hooks[lsm_##FUNC], \
						    list[lsm_##FUNC]) {	\
					thisrc = sop->FUNC(__VA_ARGS__); \
					if (thisrc)			\
						RC = thisrc;		\
					called = 1;			\
				}					\
			} while (0);					\
			called;						\
		})

#define call_int_cap_first(FUNC, ...) ({				\
			int rc = 0;					\
			do {						\
				struct security_operations *sop;	\
				int thisrc;				\
									\
				thisrc = cap_##FUNC(__VA_ARGS__);	\
				if (thisrc) {				\
					rc = thisrc;			\
					break;				\
				}					\
									\
				list_for_each_entry(sop, &lsm_hooks[lsm_##FUNC], \
						    list[lsm_##FUNC]) {	\
					thisrc = sop->FUNC(__VA_ARGS__); \
					if (thisrc)			\
						rc = thisrc;		\
				}					\
			} while (0);					\
			rc;						\
		})
#define call_int_cap_last(FUNC, ...) ({					\
			int rc = 0;					\
			do {						\
				struct security_operations *sop;	\
				int thisrc;				\
									\
				list_for_each_entry(sop, &lsm_hooks[lsm_##FUNC], \
						    list[lsm_##FUNC]) {	\
					thisrc = sop->FUNC(__VA_ARGS__); \
					if (thisrc)			\
						rc = thisrc;		\
				}					\
									\
				if (!rc)				\
					rc = cap_##FUNC(__VA_ARGS__);	\
			} while (0);					\
			rc;						\
		})

#define call_alloc_hook(ALLOC, FREE, FIELD, GFP, ARG) ({		\
			int rc = 0;					\
			do {						\
				struct security_operations *sop;	\
				struct security_operations *note[LSM_SLOTS]; \
				struct lsm_blob tblob;			\
				struct lsm_blob *bp = NULL;		\
				int successes = 0;			\
									\
				memset(&tblob, 0, sizeof(tblob));	\
				FIELD = &tblob;				\
				for_each_hook(sop, ALLOC) {		\
					rc = sop->ALLOC(ARG);		\
					if (rc)				\
						break;			\
					note[successes++] = sop;	\
				}					\
				if (tblob.lsm_setcount != 0) {		\
					if (rc == 0)			\
						bp = kmemdup(&tblob, sizeof(tblob), GFP); \
					if (bp == NULL) {		\
						if (rc == 0)		\
							rc = -ENOMEM;	\
						while (successes > 0)	\
							note[--successes]->FREE(ARG); \
					}				\
				}					\
				FIELD = bp;				\
			} while (0);					\
			rc;						\
		})


int security_binder_set_context_mgr(struct task_struct *mgr)
{
	return call_int_hook(binder_set_context_mgr, mgr);
}

int security_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	return call_int_hook(binder_transaction, from, to);
}

int security_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
	return call_int_hook(binder_transfer_binder, from, to);
}

int security_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
	return call_int_hook(binder_transfer_file, from, to, file);
}

int security_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	int rc = cap_ptrace_access_check(child, mode);

	if (rc)
		return rc;

	return call_int_hook(ptrace_access_check, child, mode);
}

int security_ptrace_traceme(struct task_struct *parent)
{
	int rc = cap_ptrace_traceme(parent);

	if (rc)
		return rc;


	return call_int_hook(ptrace_traceme, parent);
}

int security_capget(struct task_struct *target,
		     kernel_cap_t *effective,
		     kernel_cap_t *inheritable,
		     kernel_cap_t *permitted)
{
	int rc = cap_capget(target, effective, inheritable, permitted);

	if (rc)
		return rc;

	return call_int_hook(capget, target, effective, inheritable, permitted);
}

int security_capset(struct cred *new, const struct cred *old,
		    const kernel_cap_t *effective,
		    const kernel_cap_t *inheritable,
		    const kernel_cap_t *permitted)
{
	int rc = cap_capset(new, old, effective, inheritable, permitted);

	if (rc)
		return rc;
	return call_int_hook(capset, new, old, effective,
					inheritable, permitted);
}

int security_capable(const struct cred *cred, struct user_namespace *ns,
		     int cap)
{
	int rc = cap_capable(cred, ns, cap, SECURITY_CAP_AUDIT);

	if (rc)
		return rc;
	return call_int_hook(capable, cred, ns, cap, SECURITY_CAP_AUDIT);
}

int security_capable_noaudit(const struct cred *cred, struct user_namespace *ns,
			     int cap)
{
	int rc = cap_capable(cred, ns, cap, SECURITY_CAP_NOAUDIT);

	if (rc)
		return rc;
	return call_int_hook(capable, cred, ns, cap, SECURITY_CAP_NOAUDIT);
}

int security_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return call_int_hook(quotactl, cmds, type, id, sb);
}

int security_quota_on(struct dentry *dentry)
{
	return call_int_hook(quota_on, dentry);
}

int security_syslog(int type)
{
	return call_int_hook(syslog, type);
}

int security_settime(const struct timespec *ts, const struct timezone *tz)
{
	int rc = cap_settime(ts, tz);

	if (rc)
		return rc;
	return call_int_hook(settime, ts, tz);
}

int security_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
	int rc = cap_vm_enough_memory(mm, pages);

	if (rc)
		return rc;
	return call_int_hook(vm_enough_memory, mm, pages);
}

int security_bprm_set_creds(struct linux_binprm *bprm)
{
	int rc = cap_bprm_set_creds(bprm);

	if (rc)
		return rc;
	return call_int_hook(bprm_set_creds, bprm);
}

int security_bprm_check(struct linux_binprm *bprm)
{
	int ret;

	ret = call_int_hook(bprm_check_security, bprm);
	if (ret)
		return ret;
	return ima_bprm_check(bprm);
}

void security_bprm_committing_creds(struct linux_binprm *bprm)
{
	call_void_hook(bprm_committing_creds, bprm);
}

void security_bprm_committed_creds(struct linux_binprm *bprm)
{
	call_void_hook(bprm_committed_creds, bprm);
}

int security_bprm_secureexec(struct linux_binprm *bprm)
{
	int rc = call_int_hook(bprm_secureexec, bprm);

	if (rc)
		return rc;
	return cap_bprm_secureexec(bprm);
}

int security_sb_alloc(struct super_block *sb)
{
	return call_alloc_hook(sb_alloc_security, sb_free_security,
				sb->s_security, GFP_KERNEL, sb);
}

void security_sb_free(struct super_block *sb)
{
	call_void_hook(sb_free_security, sb);
}

int security_sb_copy_data(char *orig, char *copy)
{
	return call_int_hook(sb_copy_data, orig, copy);
}
EXPORT_SYMBOL(security_sb_copy_data);

int security_sb_remount(struct super_block *sb, void *data)
{
	return call_int_hook(sb_remount, sb, data);
}

int security_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return call_int_hook(sb_kern_mount, sb, flags, data);
}

int security_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return call_int_hook(sb_show_options, m, sb);
}

int security_sb_statfs(struct dentry *dentry)
{
	return call_int_hook(sb_statfs, dentry);
}

int security_sb_mount(char *dev_name, struct path *path,
                       char *type, unsigned long flags, void *data)
{
	return call_int_hook(sb_mount, dev_name, path, type, flags, data);
}

int security_sb_umount(struct vfsmount *mnt, int flags)
{
	return call_int_hook(sb_umount, mnt, flags);
}

int security_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	return call_int_hook(sb_pivotroot, old_path, new_path);
}

int security_sb_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts)
{
	return call_int_hook(sb_set_mnt_opts, sb, opts);
}
EXPORT_SYMBOL(security_sb_set_mnt_opts);

void security_sb_clone_mnt_opts(const struct super_block *oldsb,
				struct super_block *newsb)
{
	call_void_hook(sb_clone_mnt_opts, oldsb, newsb);
}
EXPORT_SYMBOL(security_sb_clone_mnt_opts);

int security_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return call_int_hook(sb_parse_opts_str, options, opts);
}
EXPORT_SYMBOL(security_sb_parse_opts_str);

int security_inode_alloc(struct inode *inode)
{
	return call_alloc_hook(inode_alloc_security, inode_free_security,
				inode->i_security, GFP_KERNEL, inode);
}

void security_inode_free(struct inode *inode)
{
	integrity_inode_free(inode);
	call_void_hook(inode_free_security, inode);
}

int security_inode_init_security(struct inode *inode, struct inode *dir,
				 const struct qstr *qstr,
				 const initxattrs initxattrs, void *fs_data)
{
	struct security_operations *sop;
	struct xattr new_xattrs[MAX_LSM_EVM_XATTR + 1];
	struct xattr *lsm_xattr = new_xattrs;
	struct xattr *evm_xattr;
	struct xattr *xattr;
	int thisrc;
	int rc = 0;
	int supported = 0;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	if (!initxattrs)
		return call_int_hook(inode_init_security, inode, dir, qstr,
				     NULL, NULL, NULL);

	memset(new_xattrs, 0, sizeof new_xattrs);

	for_each_hook(sop, inode_init_security) {
		thisrc = sop->inode_init_security(inode, dir, qstr,
				&lsm_xattr->name, &lsm_xattr->value,
				&lsm_xattr->value_len);
		if (thisrc != 0) {
			if (thisrc != -EOPNOTSUPP) {
				supported = 1;
				rc = thisrc;
			}
			continue;
		}
		supported = 1;
		evm_xattr = lsm_xattr + 1;
		thisrc = evm_inode_init_security(inode, lsm_xattr, evm_xattr);
		if (thisrc == 0)
			thisrc = initxattrs(inode, new_xattrs, fs_data);
		if (thisrc != 0)
			rc = thisrc;
		for (xattr = new_xattrs; xattr->name != NULL; xattr++) {
			kfree(xattr->name);
			kfree(xattr->value);
		}
	}
	if (supported)
		return rc;
	return 0;
}
EXPORT_SYMBOL(security_inode_init_security);

int security_old_inode_init_security(struct inode *inode, struct inode *dir,
				     const struct qstr *qstr, char **name,
				     void **value, size_t *len)
{
	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	return call_int_hook(inode_init_security, inode, dir, qstr, name,
						value, len);
}
EXPORT_SYMBOL(security_old_inode_init_security);

#ifdef CONFIG_SECURITY_PATH
int security_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
			unsigned int dev)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_mknod, dir, dentry, mode, dev);
}
EXPORT_SYMBOL(security_path_mknod);

int security_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_mkdir, dir, dentry, mode);
}
EXPORT_SYMBOL(security_path_mkdir);

int security_path_rmdir(struct path *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_rmdir, dir, dentry);
}

int security_path_unlink(struct path *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_unlink, dir, dentry);
}
EXPORT_SYMBOL(security_path_unlink);

int security_path_symlink(struct path *dir, struct dentry *dentry,
			  const char *old_name)
{
	if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
		return 0;
	return call_int_hook(path_symlink, dir, dentry, old_name);
}

int security_path_link(struct dentry *old_dentry, struct path *new_dir,
		       struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
		return 0;
	return call_int_hook(path_link, old_dentry, new_dir, new_dentry);
}

int security_path_rename(struct path *old_dir, struct dentry *old_dentry,
			 struct path *new_dir, struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
		     (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
		return 0;
	return call_int_hook(path_rename, old_dir, old_dentry, new_dir,
					 new_dentry);
}
EXPORT_SYMBOL(security_path_rename);

int security_path_truncate(struct path *path)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_truncate, path);
}

int security_path_chmod(struct path *path, umode_t mode)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_chmod, path, mode);
}

int security_path_chown(struct path *path, uid_t uid, gid_t gid)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return call_int_hook(path_chown, path, uid, gid);
}

int security_path_chroot(struct path *path)
{
	return call_int_hook(path_chroot, path);
}
#endif

int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_create, dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(security_inode_create);

int security_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
		return 0;
	return call_int_hook(inode_link, old_dentry, dir, new_dentry);
}

int security_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_unlink, dir, dentry);
}

int security_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_symlink, dir, dentry, old_name);
}

int security_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_mkdir, dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(security_inode_mkdir);

int security_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_rmdir, dir, dentry);
}

int security_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return call_int_hook(inode_mknod, dir, dentry, mode, dev);
}

int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
        if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
            (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
		return 0;
	return call_int_hook(inode_rename, old_dir, old_dentry,
					   new_dir, new_dentry);
}

int security_inode_readlink(struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_readlink, dentry);
}

int security_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_follow_link, dentry, nd);
}

int security_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return call_int_hook(inode_permission, inode, mask);
}

int security_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	ret = call_int_hook(inode_setattr, dentry, attr);
	if (ret)
		return ret;
	return evm_inode_setattr(dentry, attr);
}
EXPORT_SYMBOL_GPL(security_inode_setattr);

int security_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_getattr, mnt, dentry);
}

int security_inode_setxattr(struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	ret = call_int_hook(inode_setxattr, dentry, name, value, size, flags);
	if (ret)
		return ret;
	return evm_inode_setxattr(dentry, name, value, size);
}

void security_inode_post_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return;
	call_void_hook(inode_post_setxattr, dentry, name, value, size, flags);
	evm_inode_post_setxattr(dentry, name, value, size);
}

int security_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_getxattr, dentry, name);
}

int security_inode_listxattr(struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return call_int_hook(inode_listxattr, dentry);
}

int security_inode_removexattr(struct dentry *dentry, const char *name)
{
	int ret;

	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	if (!call_int_must(ret, inode_removexattr, dentry, name))
		ret = cap_inode_removexattr(dentry, name);
	if (ret)
		return ret;
	return evm_inode_removexattr(dentry, name);
}

int security_inode_need_killpriv(struct dentry *dentry)
{
	int rc = cap_inode_need_killpriv(dentry);

	if (rc)
		return rc;
	return call_int_hook(inode_need_killpriv, dentry);
}

int security_inode_killpriv(struct dentry *dentry)
{
	int rc = cap_inode_killpriv(dentry);

	if (rc)
		return rc;
	return call_int_hook(inode_killpriv, dentry);
}

int security_inode_getsecurity(const struct inode *inode, const char *name,
			       void **buffer, bool alloc,
			       struct security_operations **secops)
{
	struct security_operations *sop;
	int ret;

	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	/*
	 * Only one LSM will supply a given "name".
	 * -EOPNOTSUPP is an indication that the LSM does not
	 * provide a value for the provided name.
	 */
	for_each_hook(sop, inode_getsecurity) {
		ret = sop->inode_getsecurity(inode, name, buffer, alloc);
		if (ret != -EOPNOTSUPP) {
			*secops = sop;
			return ret;
		}
	}
	return -EOPNOTSUPP;
}

int security_inode_setsecurity(struct inode *inode, const char *name,
			       const void *value, size_t size, int flags)
{
	struct security_operations *sop;
	int ret;

	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	/*
	 * Only one LSM will set a given "name".
	 * -EOPNOTSUPP is an indication that the LSM does not
	 * set a value for the provided name.
	 */
	for_each_hook(sop, inode_setsecurity) {
		ret = sop->inode_setsecurity(inode, name, value, size, flags);
		if (ret != -EOPNOTSUPP)
			return ret;
	}
	return -EOPNOTSUPP;
}

int security_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	struct security_operations *sop;
	int ret = 0;
	int thisrc;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	/*
	 * inode_listsecurity hooks never return negative values.
	 */
	for_each_hook(sop, inode_listsecurity) {
		thisrc = sop->inode_listsecurity(inode, buffer, buffer_size);
		if (buffer != NULL)
			buffer += thisrc;
		buffer_size -= thisrc;
		ret += thisrc;
	}
	return ret;
}

void security_inode_getsecid(const struct inode *inode, struct secids *secid)
{
	struct security_operations *sop;
	u32 sid;

	lsm_set_secid(secid, 0, -1);
	for_each_hook(sop, inode_getsecid) {
		sop->inode_getsecid(inode, &sid);
		lsm_set_secid(secid, sid, sop->order);
	}
}

int security_file_permission(struct file *file, int mask)
{
	int ret;

	ret = call_int_hook(file_permission, file, mask);
	if (ret)
		return ret;

	return fsnotify_perm(file, mask);
}

int security_file_alloc(struct file *file)
{
	return call_alloc_hook(file_alloc_security, file_free_security,
		file->f_security, GFP_KERNEL, file);
}

void security_file_free(struct file *file)
{
	call_void_hook(file_free_security, file);
	kfree(file->f_security);
	file->f_security = NULL;
}

int security_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return call_int_hook(file_ioctl, file, cmd, arg);
}

int security_file_mmap(struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only)
{
	int ret;

	ret = call_int_hook(file_mmap, file, reqprot, prot, flags, addr, addr_only);
	if (ret)
		return ret;
	return ima_file_mmap(file, prot);
}

int security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			    unsigned long prot)
{
	return call_int_hook(file_mprotect, vma, reqprot, prot);
}

int security_file_lock(struct file *file, unsigned int cmd)
{
	return call_int_hook(file_lock, file, cmd);
}

int security_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return call_int_hook(file_fcntl, file, cmd, arg);
}

int security_file_set_fowner(struct file *file)
{
	return call_int_hook(file_set_fowner, file);
}

int security_file_send_sigiotask(struct task_struct *tsk,
				  struct fown_struct *fown, int sig)
{
	return call_int_hook(file_send_sigiotask, tsk, fown, sig);
}

int security_file_receive(struct file *file)
{
	return call_int_hook(file_receive, file);
}

int security_dentry_open(struct file *file, const struct cred *cred)
{
	int ret;

	ret = call_int_hook(dentry_open, file, cred);
	if (ret)
		return ret;

	return fsnotify_perm(file, MAY_OPEN);
}

int security_task_create(unsigned long clone_flags)
{
	return call_int_hook(task_create, clone_flags);
}

void security_task_free(struct task_struct *task)
{
	call_void_hook(task_free, task);
}

int security_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct security_operations *sop;
	struct security_operations *note[LSM_SLOTS];
	struct lsm_blob tblob;
	struct lsm_blob *bp = NULL;
	int ret = 0;
	int successes = 0;

	memset(&tblob, 0, sizeof(tblob));
	cred->security = &tblob;

	for_each_hook(sop, cred_alloc_blank) {
		ret = sop->cred_alloc_blank(cred, gfp);
		if (ret)
			break;
		note[successes++] = sop;
	}

	if (tblob.lsm_setcount != 0) {
		if (ret == 0)
			bp = kmemdup(&tblob, sizeof(tblob), gfp);
		if (bp == NULL) {
			if (ret == 0)
				ret = -ENOMEM;
			while (successes > 0)
				note[--successes]->cred_free(cred);
		}
	}
	cred->security = bp;
	return ret;
}

void security_cred_free(struct cred *cred)
{
	call_void_hook(cred_free, cred);
	kfree(cred->security);
	cred->security = NULL;
}

int security_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct security_operations *sop;
	struct security_operations *note[LSM_SLOTS];
	struct lsm_blob tblob;
	struct lsm_blob *bp = NULL;
	int ret = 0;
	int successes = 0;

	/*
	 * new->security will be NULL on entry.
	 */
	memset(&tblob, 0, sizeof(tblob));
	new->security = &tblob;

	for_each_hook(sop, cred_prepare) {
		ret = sop->cred_prepare(new, old, gfp);
		if (ret)
			break;
		note[successes++] = sop;
	}

	if (tblob.lsm_setcount != 0) {
		if (ret == 0)
			bp = kmemdup(&tblob, sizeof(tblob), gfp);
		if (bp == NULL) {
			if (ret == 0)
			ret = -ENOMEM;
			while (successes > 0)
				note[--successes]->cred_free(new);
		}
	}
	new->security = bp;
	return ret;
}

void security_transfer_creds(struct cred *new, const struct cred *old)
{
	call_void_hook(cred_transfer, new, old);
}

int security_kernel_act_as(struct cred *new, struct secids *secid)
{
	struct security_operations *sop;
	int thisrc;
	int ret = 0;

	for_each_hook(sop, kernel_act_as) {
		thisrc = sop->kernel_act_as(new, secid->si_lsm[sop->order]);
		if (thisrc)
			ret = thisrc;
	}
	return ret;
}

int security_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return call_int_hook(kernel_create_files_as, new, inode);
}

int security_kernel_module_request(char *kmod_name)
{
	return call_int_hook(kernel_module_request, kmod_name);
}

int security_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags)
{
	int rc = cap_task_fix_setuid(new, old, flags);

	if (rc)
		return rc;
	return call_int_hook(task_fix_setuid, new, old, flags);
}

int security_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return call_int_hook(task_setpgid, p, pgid);
}

int security_task_getpgid(struct task_struct *p)
{
	return call_int_hook(task_getpgid, p);
}

int security_task_getsid(struct task_struct *p)
{
	return call_int_hook(task_getsid, p);
}

void security_task_getsecid(struct task_struct *p, struct secids *secid)
{
	struct security_operations *sop;
	u32 sid;

	lsm_init_secid(secid, 0, -1);

	for_each_hook(sop, task_getsecid) {
		sop->task_getsecid(p, &sid);
		lsm_set_secid(secid, sid, sop->order);
	}
}
EXPORT_SYMBOL(security_task_getsecid);

int security_task_setnice(struct task_struct *p, int nice)
{
	int ret = cap_task_setnice(p, nice);

	if (ret)
		return ret;
	return call_int_hook(task_setnice, p, nice);
}

int security_task_setioprio(struct task_struct *p, int ioprio)
{
	int rc = cap_task_setioprio(p, ioprio);

	if (rc)
		return rc;
	return call_int_hook(task_setioprio, p, ioprio);
}

int security_task_getioprio(struct task_struct *p)
{
	return call_int_hook(task_getioprio, p);
}

int security_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim)
{
	return call_int_hook(task_setrlimit, p, resource, new_rlim);
}

int security_task_setscheduler(struct task_struct *p)
{
	int rc = cap_task_setscheduler(p);

	if (rc)
		return rc;
	return call_int_hook(task_setscheduler, p);
}

int security_task_getscheduler(struct task_struct *p)
{
	return call_int_hook(task_getscheduler, p);
}

int security_task_movememory(struct task_struct *p)
{
	return call_int_hook(task_movememory, p);
}

int security_task_kill(struct task_struct *p, struct siginfo *info,
			int sig, struct secids *secid)
{
	struct security_operations *sop;
	int thisrc;
	int ret = 0;

	for_each_hook(sop, kernel_act_as) {
		thisrc = sop->task_kill(p, info, sig,
					lsm_get_secid(secid, sop->order));
		if (thisrc)
			ret = thisrc;
	}
	return ret;
}

int security_task_wait(struct task_struct *p)
{
	return call_int_hook(task_wait, p);
}

int security_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			 unsigned long arg4, unsigned long arg5)
{
	return call_int_hook(task_prctl, option, arg2, arg3, arg4, arg5);
}

void security_task_to_inode(struct task_struct *p, struct inode *inode)
{
	call_void_hook(task_to_inode, p, inode);
}

int security_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return call_int_hook(ipc_permission, ipcp, flag);
}

void security_ipc_getsecid(struct kern_ipc_perm *ipcp, struct secids *secid)
{
	u32 sid;

	call_void_hook(ipc_getsecid, ipcp, &sid);
	lsm_init_secid(secid, sid, -1);
}

int security_msg_msg_alloc(struct msg_msg *msg)
{
	return call_alloc_hook(msg_msg_alloc_security, msg_msg_free_security,
				msg->security, GFP_KERNEL, msg);
}

void security_msg_msg_free(struct msg_msg *msg)
{
	call_void_hook(msg_msg_free_security, msg);

	kfree(msg->security);
	msg->security = NULL;
}

int security_msg_queue_alloc(struct msg_queue *msq)
{
	struct kern_ipc_perm *kp = &msq->q_perm;

	return call_alloc_hook(msg_queue_alloc_security,
			msg_queue_free_security, kp->security, GFP_KERNEL,
			msq);
}

void security_msg_queue_free(struct msg_queue *msq)
{
	call_void_hook(msg_queue_free_security, msq);
	kfree(msq->q_perm.security);
	msq->q_perm.security = NULL;
}

int security_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return call_int_hook(msg_queue_associate, msq, msqflg);
}

int security_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return call_int_hook(msg_queue_msgctl, msq, cmd);
}

int security_msg_queue_msgsnd(struct msg_queue *msq,
			      struct msg_msg *msg, int msqflg)
{
	return call_int_hook(msg_queue_msgsnd, msq, msg, msqflg);
}

int security_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
			      struct task_struct *target, long type, int mode)
{
	return call_int_hook(msg_queue_msgrcv, msq, msg, target, type, mode);
}

int security_shm_alloc(struct shmid_kernel *shp)
{
	struct kern_ipc_perm *kp = &shp->shm_perm;

	return call_alloc_hook(shm_alloc_security, shm_free_security,
				kp->security, GFP_KERNEL, shp);
}

void security_shm_free(struct shmid_kernel *shp)
{
	call_void_hook(shm_free_security, shp);
	kfree(shp->shm_perm.security);
	shp->shm_perm.security = NULL;
}

int security_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return call_int_hook(shm_associate, shp, shmflg);
}

int security_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return call_int_hook(shm_shmctl, shp, cmd);
}

int security_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg)
{
	return call_int_hook(shm_shmat, shp, shmaddr, shmflg);
}

int security_sem_alloc(struct sem_array *sma)
{
	struct kern_ipc_perm *kp = &sma->sem_perm;

	return call_alloc_hook(sem_alloc_security, sem_free_security,
				kp->security, GFP_KERNEL, sma);
}

void security_sem_free(struct sem_array *sma)
{
	call_void_hook(sem_free_security, sma);
	kfree(sma->sem_perm.security);
	sma->sem_perm.security = NULL;
}

int security_sem_associate(struct sem_array *sma, int semflg)
{
	return call_int_hook(sem_associate, sma, semflg);
}

int security_sem_semctl(struct sem_array *sma, int cmd)
{
	return call_int_hook(sem_semctl, sma, cmd);
}

int security_sem_semop(struct sem_array *sma, struct sembuf *sops,
			unsigned nsops, int alter)
{
	return call_int_hook(sem_semop, sma, sops, nsops, alter);
}

void security_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (unlikely(inode && IS_PRIVATE(inode)))
		return;
	call_void_hook(d_instantiate, dentry, inode);
}
EXPORT_SYMBOL(security_d_instantiate);

int security_getprocattr(struct task_struct *p, char *name, char **value)
{
	struct security_operations *sop = NULL;
	struct secids secid;
	char *lsm;
	int lsmlen;
	int ret;

	/*
	 * Names will either be in the legacy form containing
	 * no periods (".") or they will be the LSM name followed
	 * by the legacy suffix. "current" or "selinux.current"
	 * The exception is "context", which gets all of the LSMs.
	 *
	 * Legacy names are handled by the presenting LSM.
	 * Suffixed names are handled by the named LSM.
	 */
	if (strcmp(name, "context") == 0) {
		security_task_getsecid(p, &secid);
		ret = security_secid_to_secctx(&secid, &lsm, &lsmlen, &sop);
		if (ret == 0) {
			*value = kstrdup(lsm, GFP_KERNEL);
			if (*value == NULL)
				ret = -ENOMEM;
			else
				ret = strlen(*value);
			security_release_secctx(lsm, lsmlen, sop);
		}
		return ret;
	}

	if (present_ops && !strchr(name, '.'))
		return present_getprocattr(p, name, value);

	for_each_hook(sop, getprocattr) {
		lsm = sop->name;
		lsmlen = strlen(lsm);
		if (!strncmp(name, lsm, lsmlen) && name[lsmlen] == '.')
			return sop->getprocattr(p, name + lsmlen + 1, value);
	}
	return -EINVAL;
}

int security_setprocattr(struct task_struct *p, char *name, void *value,
			 size_t size)
{
	struct security_operations *sop;
	char *lsm;
	int lsmlen;

	/*
	 * Names will either be in the legacy form containing
	 * no periods (".") or they will be the LSM name followed
	 * by the legacy suffix.
	 * "current" or "selinux.current"
	 *
	 * Legacy names are handled by the presenting LSM.
	 * Suffixed names are handled by the named LSM.
	 */
	if (present_ops && !strchr(name, '.'))
		return present_setprocattr(p, name, value, size);

	for_each_hook(sop, setprocattr) {
		lsm = sop->name;
		lsmlen = strlen(lsm);
		if (!strncmp(name, lsm, lsmlen) && name[lsmlen] == '.')
			return sop->setprocattr(p, name + lsmlen + 1, value,
						size);
	}
	return -EINVAL;
}

int security_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	int rc = cap_netlink_send(sk, skb);

	if (rc)
		return rc;
	return call_int_hook(netlink_send, sk, skb);
}

/*
 * On input *secops is either the operations for the one LSM
 * to get the text for or NULL, indicating that the entire set
 * on security information is desired.
 *
 * On exit *secops will contain the operations for the LSM
 * that allocated the secctx or NULL, indicating that the lsm
 * infrastructure allocated it.
 */
int security_secid_to_secctx(struct secids *secid, char **secdata, u32 *seclen,
			     struct security_operations **secops)
{
	struct security_operations *sop = *secops;
	struct security_operations *gotthis = NULL;
	char *data;
	char *cp;
	char *thisdata[LSM_SLOTS];
	u32 thislen[LSM_SLOTS];
	int thisrc[LSM_SLOTS];
	int gotmany = 0;
	int ord;
	u32 lenmany = 2;
	int ret = 0;

	
	if (sop)
		return sop->secid_to_secctx(secid->si_lsm[sop->order],
						secdata, seclen);

	for_each_hook(sop, secid_to_secctx) {
		ord = sop->order;
		if (secdata == NULL)
			thisrc[ord] = sop->secid_to_secctx(secid->si_lsm[ord],
						NULL, &thislen[ord]);
		else
			thisrc[ord] = sop->secid_to_secctx(secid->si_lsm[ord],
						&thisdata[ord], &thislen[ord]);
		if (thisrc[ord] == 0) {
			if (gotthis == NULL)
				gotthis = sop;
			else
				gotmany = 1;
			lenmany += thislen[ord] + strlen(sop->name) + 3;
		} else
			ret = thisrc[ord];
	}
	if (gotthis == NULL) {
		if (ret == 0)
			return -EOPNOTSUPP;
		return ret;
	}
	if (!gotmany) {
		if (secdata != NULL)
			*secdata = thisdata[gotthis->order];
		*seclen = thislen[gotthis->order];
		*secops = gotthis;
		return 0;
	}
	if (secdata == NULL) {
		*seclen = lenmany;
		*secops = NULL;
		return 0;
	}
 
	data = kzalloc(lenmany, GFP_KERNEL);
	if (data != NULL) {
		cp = data;
		for_each_hook(sop, secid_to_secctx) {
			ord = sop->order;
			if (thisrc[ord] == 0)
				cp += sprintf(cp, "%s='%s'", sop->name,
							thisdata[ord]);
		}
		*secdata = data;
		*seclen = lenmany;
		*secops = NULL;
		ret = 0;
	} else
		ret = -ENOMEM;

	for_each_hook(sop, secid_to_secctx) {
		ord = sop->order;
		sop->release_secctx(thisdata[ord], thislen[ord]);
	}

	return ret;
}
EXPORT_SYMBOL(security_secid_to_secctx);

static int lsm_specific_ctx(const char *secdata, char *lsm, char *ctx)
{
	char fmt[SECURITY_NAME_MAX + 10];
	char *cp;

	sprintf(fmt, "%s='", lsm);
	cp = strstr(secdata, fmt);
	if (cp == NULL)
		return 0;

	sprintf(fmt, "%s='%%[^']'", lsm);
	return sscanf(cp, fmt, ctx);
}

int security_secctx_to_secid(const char *secdata, u32 seclen,
			     struct secids *secid,
			     struct security_operations *secops)
{
	struct security_operations *sop;
	char *cp;
	char *thisdata;
	int thisrc;
	int gotten = 0;
	int ret = 0;
	u32 sid;

	lsm_init_secid(secid, 0, -1);

	if (secops) {
		ret = secops->secctx_to_secid(secdata, seclen, &sid);
		lsm_set_secid(secid, sid, secops->order);
		return ret;
	}
#ifdef CONFIG_SECURITY_PLAIN_CONTEXT_CBS
	if (peersec_ops) {
		ret = peersec_ops->secctx_to_secid(secdata, seclen, &sid);
		lsm_set_secid(secid, sid, peersec_ops->order);
		return ret;
	}
#endif

	cp = strnstr(secdata, "='", seclen);
	if (cp == NULL) {
		for_each_hook(sop, secctx_to_secid) {
			thisrc = sop->secctx_to_secid(secdata, seclen, &sid);
			lsm_set_secid(secid, sid, sop->order);
			if (thisrc)
				ret = thisrc;
			gotten = 1;
		}
	} else {
		thisdata = kzalloc(seclen, GFP_KERNEL);
		if (thisdata == NULL)
			return -ENOMEM;

		for_each_hook(sop, secctx_to_secid) {
			thisrc = lsm_specific_ctx(secdata, sop->name, thisdata);
			if (thisrc == 0)
				continue;
			thisrc = sop->secctx_to_secid(thisdata, seclen, &sid);
			lsm_set_secid(secid, sid, sop->order);
			if (thisrc)
				ret = thisrc;
			gotten = 1;
		}
		kfree(thisdata);
	}
	if (gotten)
		return 0;
	return ret;
}
EXPORT_SYMBOL(security_secctx_to_secid);

void security_release_secctx(char *secdata, u32 seclen,
			     struct security_operations *sop)
{
	/* if (sop) */
	/* 	sop->release_secctx(secdata, seclen); */
	/* else */
	/* 	kfree(secdata); */
	if (!sop)
		kfree(secdata);
}
EXPORT_SYMBOL(security_release_secctx);

int security_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return call_int_hook(inode_notifysecctx, inode, ctx, ctxlen);
}
EXPORT_SYMBOL(security_inode_notifysecctx);

int security_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return call_int_hook(inode_setsecctx, dentry, ctx, ctxlen);
}
EXPORT_SYMBOL(security_inode_setsecctx);

int security_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen,
			     struct security_operations **sop)
{
	return call_int_hook(inode_getsecctx, inode, ctx, ctxlen);
}
EXPORT_SYMBOL(security_inode_getsecctx);

#ifdef CONFIG_SECURITY_NETWORK

int security_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk)
{
	return call_int_hook(unix_stream_connect, sock, other, newsk);
}
EXPORT_SYMBOL(security_unix_stream_connect);

int security_unix_may_send(struct socket *sock,  struct socket *other)
{
	return call_int_hook(unix_may_send, sock, other);
}
EXPORT_SYMBOL(security_unix_may_send);

int security_socket_create(int family, int type, int protocol, int kern)
{
	return call_int_hook(socket_create, family, type, protocol, kern);
}

int security_socket_post_create(struct socket *sock, int family,
				int type, int protocol, int kern)
{
	return call_int_hook(socket_post_create, sock, family, type,
						protocol, kern);
}

int security_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return call_int_hook(socket_bind, sock, address, addrlen);
}

int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return call_int_hook(socket_connect, sock, address, addrlen);
}

int security_socket_listen(struct socket *sock, int backlog)
{
	return call_int_hook(socket_listen, sock, backlog);
}

int security_socket_accept(struct socket *sock, struct socket *newsock)
{
	return call_int_hook(socket_accept, sock, newsock);
}

int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return call_int_hook(socket_sendmsg, sock, msg, size);
}

int security_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			    int size, int flags)
{
	return call_int_hook(socket_recvmsg, sock, msg, size, flags);
}

int security_socket_getsockname(struct socket *sock)
{
	return call_int_hook(socket_getsockname, sock);
}

int security_socket_getpeername(struct socket *sock)
{
	return call_int_hook(socket_getpeername, sock);
}

int security_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return call_int_hook(socket_getsockopt, sock, level, optname);
}

int security_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return call_int_hook(socket_setsockopt, sock, level, optname);
}

int security_socket_shutdown(struct socket *sock, int how)
{
	return call_int_hook(socket_shutdown, sock, how);
}

int security_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return call_int_hook(socket_sock_rcv_skb, sk, skb);
}
EXPORT_SYMBOL(security_sock_rcv_skb);

int security_socket_getpeersec_stream(struct socket *sock, char __user *optval,
				      int __user *optlen, unsigned len)
{
	struct security_operations *sop;
	char *result;
	char *tp;
	char *thisval;
	int thislen;
	int thisrc;
	int ret = -ENOPROTOOPT;

	thisval = kzalloc(len * 2, GFP_KERNEL);
	if (thisval == NULL)
		return -ENOMEM;
	result = thisval;
	tp = result + len;

	if (peersec_ops) {
		ret = peersec_ops->socket_getpeersec_stream(sock, result,
							    &thislen, len);
		goto sendout;
	}

	for_each_hook(sop, socket_getpeersec_stream) {
		thisrc = sop->socket_getpeersec_stream(sock, tp, &thislen, len);
		if (thisrc == 0) {
			thislen += strlen(sop->name) + 3;
			if (thislen >= len) {
				ret = -ERANGE;
				break;
			}
			thisval += sprintf(thisval, "%s='%s'", sop->name, tp);
			len -= thislen;
			ret = 0;
		} else if (thisrc != -ENOPROTOOPT)
			ret = thisrc;
	}
 sendout:
	if (ret == 0) {
		len = strlen(result) + 1;
		if (put_user(len, optlen))
			ret = -EFAULT;
		else if (copy_to_user(optval, result, len))
			ret = -EFAULT;
	}
	kfree(result);
	return ret;
}
EXPORT_SYMBOL(security_socket_getpeersec_stream);

int security_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb,
				     struct secids *secid)
{
	struct security_operations *sop;
	int thisrc;
	int ret = -ENOPROTOOPT;
	u32 sid;

	lsm_init_secid(secid, 0, -1);

	if (peersec_ops)
		return peersec_ops->socket_getpeersec_dgram(sock, skb, &sid);

	for_each_hook(sop, socket_getpeersec_dgram) {
		thisrc = sop->socket_getpeersec_dgram(sock, skb, &sid);
		lsm_set_secid(secid, sid, sop->order);
		if (!thisrc)
			ret = 0;
		else if (thisrc != -ENOPROTOOPT)
			ret = thisrc;
	}
	return ret;
}
EXPORT_SYMBOL(security_socket_getpeersec_dgram); 

int security_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	struct security_operations *sop;
	struct security_operations *note[LSM_SLOTS];
	struct lsm_blob tblob;
	struct lsm_blob *bp = NULL;
	int ret = 0;
	int successes = 0;

	memset(&tblob, 0, sizeof(tblob));
	sk->sk_security = &tblob;

	for_each_hook(sop, sk_alloc_security) {
		ret = sop->sk_alloc_security(sk, family, priority);
		if (ret)
			break;
		note[successes++] = sop;
	}

	if (tblob.lsm_setcount != 0) {
		if (ret == 0)
			bp = kmemdup(&tblob, sizeof(tblob), priority);
		if (bp == NULL) {
			if (ret == 0)
				ret = -ENOMEM;
			while (successes > 0)
				note[--successes]->sk_free_security(sk);
		}
	}
	sk->sk_security = bp;
	return ret;
}

void security_sk_free(struct sock *sk)
{
	call_void_hook(sk_free_security, sk);
}

void security_sk_clone(const struct sock *sk, struct sock *newsk)
{
	call_void_hook(sk_clone_security, sk, newsk);
}
EXPORT_SYMBOL(security_sk_clone);

void security_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
	call_void_hook(sk_getsecid, sk, &fl->flowi_secid);
}
EXPORT_SYMBOL(security_sk_classify_flow);

void security_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
	call_void_hook(req_classify_flow, req, fl);
}
EXPORT_SYMBOL(security_req_classify_flow);

void security_sock_graft(struct sock *sk, struct socket *parent)
{
	call_void_hook(sock_graft, sk, parent);
}
EXPORT_SYMBOL(security_sock_graft);

int security_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
	return call_int_hook(inet_conn_request, sk, skb, req);
}
EXPORT_SYMBOL(security_inet_conn_request);

void security_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{
	call_void_hook(inet_csk_clone, newsk, req);
}

void security_inet_conn_established(struct sock *sk,
			struct sk_buff *skb)
{
	call_void_hook(inet_conn_established, sk, skb);
}

int security_secmark_relabel_packet(struct secids *secid)
{
	u32 sid = lsm_get_secid(secid, lsm_secmark_order());

	if (secmark_ops)
		return secmark_ops->secmark_relabel_packet(sid);
	return 0;
}
EXPORT_SYMBOL(security_secmark_relabel_packet);

void security_secmark_refcount_inc(void)
{
	if (secmark_ops)
		secmark_ops->secmark_refcount_inc();
}
EXPORT_SYMBOL(security_secmark_refcount_inc);

void security_secmark_refcount_dec(void)
{
	if (secmark_ops)
		secmark_ops->secmark_refcount_inc();
}
EXPORT_SYMBOL(security_secmark_refcount_dec);

int security_tun_dev_create(void)
{
	return call_int_hook(tun_dev_create);
}
EXPORT_SYMBOL(security_tun_dev_create);

void security_tun_dev_post_create(struct sock *sk)
{
	call_void_hook(tun_dev_post_create, sk);
}
EXPORT_SYMBOL(security_tun_dev_post_create);

int security_tun_dev_attach(struct sock *sk)
{
	return call_int_hook(tun_dev_attach, sk);
}
EXPORT_SYMBOL(security_tun_dev_attach);

#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
/*
 * The xfrm hooks present special issues for composition
 * as they don't use the usual scheme for passing in blobs.
 * LSM registration checks ensure that only one xfrm using
 * security module is loaded at a time.
 * This shouldn't be much of an issue since SELinux is the
 * only security module ever expected to use xfrm.
 */
#define call_xfrm_int_hook(FUNC, ...) ({		\
	int rc = 0;					\
	do {						\
		if (!xfrm_ops)				\
			break;				\
		if (!xfrm_ops->FUNC)			\
			break;				\
		rc = xfrm_ops->FUNC(__VA_ARGS__);	\
	} while (0);					\
	rc;						\
})
/* stoped here at diff 4 */
int security_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
			       struct xfrm_user_sec_ctx *sec_ctx)
{
	return call_xfrm_int_hook(xfrm_policy_alloc_security, ctxp, sec_ctx);
}
EXPORT_SYMBOL(security_xfrm_policy_alloc);

int security_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
			      struct xfrm_sec_ctx **new_ctxp)
{
	return call_xfrm_int_hook(xfrm_policy_clone_security, old_ctx,
					new_ctxp);
}

void security_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
	if (xfrm_ops && xfrm_ops->xfrm_policy_free_security)
		xfrm_ops->xfrm_policy_free_security(ctx);
}
EXPORT_SYMBOL(security_xfrm_policy_free);

int security_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
	return call_xfrm_int_hook(xfrm_policy_delete_security, ctx);
}

int security_xfrm_state_alloc(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
	return call_xfrm_int_hook(xfrm_state_alloc_security, x, sec_ctx, 0);
}
EXPORT_SYMBOL(security_xfrm_state_alloc);

int security_xfrm_state_alloc_acquire(struct xfrm_state *x,
				      struct xfrm_sec_ctx *polsec, u32 secid)
{
	if (!polsec)
		return 0;
	/*
	 * We want the context to be taken from secid which is usually
	 * from the sock.
	 */
	if (xfrm_ops && xfrm_ops->xfrm_state_alloc_security)
		return xfrm_ops->xfrm_state_alloc_security(x, NULL, secid);
	return 0;
}

int security_xfrm_state_delete(struct xfrm_state *x)
{
	return call_xfrm_int_hook(xfrm_state_delete_security, x);
}
EXPORT_SYMBOL(security_xfrm_state_delete);

void security_xfrm_state_free(struct xfrm_state *x)
{
	if (xfrm_ops && xfrm_ops->xfrm_state_free_security)
		xfrm_ops->xfrm_state_free_security(x);
}

int security_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx,
				u32 fl_secid, u8 dir)
{
	return call_xfrm_int_hook(xfrm_policy_lookup, ctx, fl_secid, dir);
}

int security_xfrm_state_pol_flow_match(struct xfrm_state *x,
				       struct xfrm_policy *xp,
				       const struct flowi *fl)
{
	if (xfrm_ops && xfrm_ops->xfrm_state_pol_flow_match)
		return xfrm_ops->xfrm_state_pol_flow_match(x, xp, fl);
	return 1;
}

int security_xfrm_decode_session(struct sk_buff *skb, u32 *secid)
{
	return call_xfrm_int_hook(xfrm_decode_session, skb, secid, 1);
}

void security_skb_classify_flow(struct sk_buff *skb, struct flowi *fl)
{
	int rc = call_xfrm_int_hook(xfrm_decode_session, skb,
					&fl->flowi_secid, 0);

	BUG_ON(rc);
}
EXPORT_SYMBOL(security_skb_classify_flow);

#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS

int security_key_alloc(struct key *key, const struct cred *cred,
		       unsigned long flags)
{
	struct security_operations *sop;
	struct security_operations *note[LSM_SLOTS];
	struct lsm_blob tblob;
	struct lsm_blob *bp = NULL;
	int ret = 0;
	int successes = 0;

	memset(&tblob, 0, sizeof(tblob));
	key->security = &tblob;

	for_each_hook(sop, key_alloc) {
		ret = sop->key_alloc(key, cred, flags);
		if (ret)
			break;
		note[successes++] = sop;
	}

	if (tblob.lsm_setcount != 0) {
		if (ret == 0)
			bp = kmemdup(&tblob, sizeof(tblob), GFP_KERNEL);
		if (bp == NULL) {
			if (ret == 0)
				ret = -ENOMEM;
			while (successes > 0)
			note[--successes]->key_free(key);
		}
	}

	key->security = bp;
	return ret;
}

void security_key_free(struct key *key)
{
	call_void_hook(key_free, key);
	kfree(key->security);
	key->security = NULL;
}

int security_key_permission(key_ref_t key_ref,
			    const struct cred *cred, key_perm_t perm)
{
	return call_int_hook(key_permission, key_ref, cred, perm);
}

int security_key_getsecurity(struct key *key, char **_buffer)
{
	int ret;

	if (call_int_must(ret, key_getsecurity, key, _buffer))
		return ret;
	*_buffer = NULL;
	return 0;
}

#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT

int security_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	struct security_operations *sop;
	struct lsm_blob tblob;
	struct lsm_blob *bp = NULL;
	int thisrc;
	int ret = 0;

	memset(&tblob, 0, sizeof(tblob));

	for_each_hook(sop, audit_rule_init) {
		thisrc = sop->audit_rule_init(field, op, rulestr,
					&tblob.lsm_blobs[sop->order]);
		if (thisrc == 0)
			tblob.lsm_setcount++;
		else if (thisrc == -EINVAL) {
			tblob.lsm_setcount++;
			pr_warn("audit rule \"%s\" is invalid for %s.\n",
					rulestr, sop->name);
		} else
			ret = thisrc;
	}

	if (tblob.lsm_setcount != 0) {
		bp = kmemdup(&tblob, sizeof(tblob), GFP_KERNEL);
		if (bp == NULL) {
			ret = -ENOMEM;
			for_each_hook(sop, audit_rule_free)
				sop->audit_rule_free(
					tblob.lsm_blobs[sop->order]);
		}
	}

	*lsmrule = bp;
	return ret;
}

int security_audit_rule_known(struct audit_krule *krule)
{
	struct security_operations *sop;

	for_each_hook(sop, audit_rule_free)
		if (sop->audit_rule_known(krule))
			return 1;
	return 0;
}

void security_audit_rule_free(void *lsmrule)
{
	struct security_operations *sop;
	struct lsm_blob *bp = lsmrule;

	if (bp == NULL)
		return;

	for_each_hook(sop, audit_rule_free)
		sop->audit_rule_free(bp->lsm_blobs[sop->order]);

	kfree(bp);
}

int security_audit_rule_match(struct secids *secid, u32 field, u32 op,
			      void *lsmrule, struct audit_context *actx)
{
	struct security_operations *sop;
	struct lsm_blob *bp = lsmrule;
	int order;
	int ret;

	if (lsmrule == NULL)
		return 0;

	for_each_hook(sop, audit_rule_match) {
		order = sop->order;
		if (bp->lsm_blobs[order] != NULL) {
			ret = sop->audit_rule_match(secid->si_lsm[order], field,
						op, bp->lsm_blobs[order], actx);
			if (ret)
				return ret;
		}
	}
	return 0;
}

#endif /* CONFIG_AUDIT */
