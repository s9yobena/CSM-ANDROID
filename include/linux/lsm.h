/*
 *
 * Copyright (C) 2012 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2012 Intel Corporation
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 *
 * Author:
 *	Casey Schaufler <casey@schaufler-ca.com>
 *
 */
#ifndef _LINUX_LSM_H
#define _LINUX_LSM_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/msg.h>
#include <linux/key.h>
#include <net/sock.h>
#include <linux/security.h>

#ifdef CONFIG_SECURITY

extern struct security_operations *security_ops;

/*
 * Just a set of slots for each LSM to keep its blob in.
 */
struct lsm_blob {
	int	lsm_setcount;		/* Number of blobs set */
	void	*lsm_blobs[LSM_SLOTS];	/* LSM specific blobs */
};

static inline struct lsm_blob *lsm_alloc_blob(gfp_t gfp)
{
	return kzalloc(sizeof(struct lsm_blob), gfp);
}

static inline void *lsm_get_blob(void *vp, const int lsm)
{
	struct lsm_blob *bp = vp;

	if (bp == NULL)
		return NULL;
	return bp->lsm_blobs[lsm];
}

static inline void lsm_set_blob(void **vpp, void *value, const int lsm)
{
	struct lsm_blob *bp = *vpp;

	if (value == NULL && bp->lsm_blobs[lsm] != NULL)
		bp->lsm_setcount--;
	if (value != NULL && bp->lsm_blobs[lsm] == NULL)
		bp->lsm_setcount++;

	bp->lsm_blobs[lsm] = value;
}

static inline void *lsm_get_cred(const struct cred *cred,
					const struct security_operations *sop)
{
	return lsm_get_blob(cred->security, sop->order);
}

static inline void lsm_set_cred(struct cred *cred, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&cred->security, value, sop->order);
}

static inline int lsm_set_init_cred(struct cred *cred, void *value,
					const struct security_operations *sop)
{
	if (cred->security == NULL) {
		cred->security = lsm_alloc_blob(GFP_KERNEL);
		if (cred->security == NULL)
			return -ENOMEM;
	}

	lsm_set_blob(&cred->security, value, sop->order);
	return 0;
}

static inline void *lsm_get_file(const struct file *file,
					const struct security_operations *sop)
{
	return lsm_get_blob(file->f_security, sop->order);
}

static inline void lsm_set_file(struct file *file, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&file->f_security, value, sop->order);
}

static inline void *lsm_get_inode(const struct inode *inode,
					const struct security_operations *sop)
{
	return lsm_get_blob(inode->i_security, sop->order);
}

static inline void lsm_set_inode(struct inode *inode, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&inode->i_security, value, sop->order);
}

static inline void *lsm_get_super(const struct super_block *super,
					const struct security_operations *sop)
{
	return lsm_get_blob(super->s_security, sop->order);
}

static inline void lsm_set_super(struct super_block *super, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&super->s_security, value, sop->order);
}

static inline void *lsm_get_ipc(const struct kern_ipc_perm *ipc,
				const struct security_operations *sop)
{
	return lsm_get_blob(ipc->security, sop->order);
}

static inline void lsm_set_ipc(struct kern_ipc_perm *ipc, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&ipc->security, value, sop->order);
}

static inline void *lsm_get_msg(const struct msg_msg *msg,
				const struct security_operations *sop)
{
	return lsm_get_blob(msg->security, sop->order);
}

static inline void lsm_set_msg(struct msg_msg *msg, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&msg->security, value, sop->order);
}

#ifdef CONFIG_KEYS
static inline void *lsm_get_key(const struct key *key,
				const struct security_operations *sop)
{
	return lsm_get_blob(key->security, sop->order);
}

static inline void lsm_set_key(struct key *key, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&key->security, value, sop->order);
}
#endif

static inline void *lsm_get_sock(const struct sock *sock,
					const struct security_operations *sop)
{
	return lsm_get_blob(sock->sk_security, sop->order);
}

static inline void lsm_set_sock(struct sock *sock, void *value,
				const struct security_operations *sop)
{
	lsm_set_blob(&sock->sk_security, value, sop->order);
}

#endif /* CONFIG_SECURITY */

static inline u32 lsm_get_secid(const struct secids *secid, int order)
{
	return secid->si_lsm[order];
}

static inline void lsm_set_secid(struct secids *secid, u32 lsecid, int order)
{
	secid->si_lsm[order] = lsecid;
}

static inline void lsm_init_secid(struct secids *secid, u32 lsecid, int order)
{
	int i;

	memset(secid, 0, sizeof(*secid));

	if (lsecid == 0)
		return;
	if (order >= 0) {
		secid->si_lsm[order] = lsecid;
		return;
	}
	for (i = 0; i < LSM_SLOTS; i++)
		secid->si_lsm[i] = lsecid;
}

static inline int lsm_zero_secid(struct secids *secid)
{
	int i;

	for (i = 0; i < LSM_SLOTS; i++)
		if (secid->si_lsm[i] != 0)
			return 0;
	return 1;
}

#ifdef CONFIG_SECURITY

extern struct security_operations *present_ops;
static inline struct security_operations *lsm_present_ops(void)
{
	return present_ops;
}

static inline int lsm_present_order(void)
{
	return present_ops->order;
}

#ifdef CONFIG_NETLABEL
extern struct security_operations *netlbl_ops;

static inline struct security_operations *lsm_netlbl_ops(void)
{
	return netlbl_ops;
}

static inline int lsm_netlbl_order(void)
{
	return netlbl_ops->order;
}
#endif /* CONFIG_NETLABEL */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
extern struct security_operations *xfrm_ops;

static inline struct security_operations *lsm_xfrm_ops(void)
{
	return xfrm_ops;
}

static inline int lsm_xfrm_order(void)
{
	return xfrm_ops->order;
}
#endif /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_NETWORK_SECMARK
extern struct security_operations *secmark_ops;

static inline struct security_operations *lsm_secmark_ops(void)
{
	return secmark_ops;
}

static inline int lsm_secmark_order(void)
{
	return secmark_ops->order;
}
#endif /* CONFIG_NETWORK_SECMARK */

static inline int lsm_peersec_order(void)
{
	return peersec_ops->order;
}

static inline struct security_operations *lsm_peersec_ops(void)
{
	return peersec_ops;
}

#else /* CONFIG_SECURITY */

static inline int lsm_xfrm_order(void)
{
	return 0;
}

static inline int lsm_secmark_order(void)
{
	return 0;
}

static inline struct security_operations *lsm_secmark_ops(void)
{
	return NULL;
}

static inline struct security_operations *lsm_peersec_ops(void)
{
	return NULL;
}

#endif /* CONFIG_SECURITY */

#endif /* ! _LINUX_LSM_H */
