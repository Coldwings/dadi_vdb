/*
 * ovbd.h
 *
 * Written by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 */
#ifndef _LINUX_LOOP_H
#define _LINUX_LOOP_H

#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "oloop.h"

struct lsmt_file;

/* Possible states of device */
enum {
    Lo_unbound,
    Lo_bound,
    Lo_rundown,
};

#define OV_NAME_SIZE 64

struct ovbd_func_table;

struct ovbd_device {
    int ov_number;
    atomic_t ov_refcnt;
    loff_t ov_offset;
    loff_t ov_sizelimit;
    int ov_flags;
    int (*transfer)(struct ovbd_device *, int cmd, struct page *raw_page,
                    unsigned raw_off, struct page *ovbd_page, unsigned ovbd_off,
                    int size, sector_t real_block);
    char ov_file_name[OV_NAME_SIZE];
    __u32 ov_init[2];
    kuid_t ov_key_owner; /* Who set the key */
    int (*ioctl)(struct ovbd_device *, int cmd, unsigned long arg);

    struct lsmt_file *ov_backing_file;
    struct block_device *ov_device;
    void *key_data;

    spinlock_t ov_lock;
    int ov_state;
    struct kthread_worker worker;
    struct task_struct *worker_task;
    // bool			use_dio;
    bool sysfs_inited;

    struct request_queue *ov_queue;
    struct blk_mq_tag_set tag_set;
    struct gendisk *ov_disk;
};

struct ovbd_cmd {
    struct kthread_work work;
    // bool use_aio; /* use AIO interface to handle I/O */
    atomic_t ref; /* only for aio */
    long ret;
    struct kiocb iocb;
    struct bio_vec *bvec;
    struct cgroup_subsys_state *css;
};

/* Support for loadable transfer modules */
struct ovbd_func_table {
    int number; /* filter type */
    int (*init)(struct ovbd_device *, const struct ovbd_info64 *);
    int (*release)(struct ovbd_device *);
    int (*ioctl)(struct ovbd_device *, int cmd, unsigned long arg);
    struct module *owner;
};

#endif
