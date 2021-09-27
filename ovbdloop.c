/*
 *  linux/drivers/block/ovbd.c
 *
 *  Written by Theodore Ts'o, 3/29/93
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this lsmt_file is
 * permitted under the GNU General Public License.
 *
 * DES encryption plus some minor changes by Werner Almesberger, 30-MAY-1993
 * more DES encryption plus IDEA encryption by Nicholas J. Leon, June 20, 1996
 *
 * Modularized and updated for 1.1.16 kernel - Mitch Dsouza 28th May 1994
 * Adapted for 1.3.59 kernel - Andries Brouwer, 1 Feb 1996
 *
 * Fixed do_ovbd_request() re-entrancy - Vincent.Renardias@waw.com Mar 20, 1997
 *
 * Added devfs support - Richard Gooch <rgooch@atnf.csiro.au> 16-Jan-1998
 *
 * Handle sparse backing files correctly - Kenn Humborg, Jun 28, 1998
 *
 * Loadable modules and other fixes by AK, 1998
 *
 * Make real block number available to downstream transfer functions, enables
 * CBC (and relatives) mode encryption requiring unique IVs per data block.
 * Reed H. Petty, rhp@draper.net
 *
 * Maximum number of ovbd devices now dynamic via max_ovbd module parameter.
 * Russell Kroll <rkroll@exploits.org> 19990701
 *
 * Maximum number of ovbd devices when compiled-in now selectable by passing
 * max_ovbd=<1-255> to the kernel on boot.
 * Erik I. Bolsø, <eriki@himolde.no>, Oct 31, 1999
 *
 * Completely rewrite request handling to be make_request_fn style and
 * non blocking, pushing work to a helper thread. Lots of fixes from
 * Al Viro too.
 * Jens Axboe <axboe@suse.de>, Nov 2000
 *
 * Support up to 256 ovbd devices
 * Heinz Mauelshagen <mge@sistina.com>, Feb 2002
 *
 * Support for falling back on the write lsmt_file operation when the address
 * space operations write_begin is not available on the backing filesystem.
 * Anton Altaparmakov, 16 Feb 2005
 *
 * Still To Fix:
 * - Advisory locking is ignored here.
 * - Should use an own CAP_* category instead of CAP_SYS_ADMIN
 *
 */

#include "ovbdloop.h"

#include <linux/blk-cgroup.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/compat.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/falloc.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/ioprio.h>
#include <linux/kthread.h>
#include <linux/major.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/splice.h>
#include <linux/stat.h>
#include <linux/suspend.h>
#include <linux/swap.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <linux/writeback.h>

#include "lsmt.h"
#include "oloop.h"
#include "zfile.h"

static DEFINE_IDR(ovbd_index_idr);
static DEFINE_MUTEX(ovbd_ctl_mutex);

#define OVBD_MAJOR 10
static int max_part;
static int part_shift;

static loff_t get_size(loff_t offset, loff_t sizelimit,
                       struct lsmt_file *lsmt_file) {
    loff_t ovbdsize;

    /* Compute ovbdsize in bytes */
    ovbdsize = lsmt_len(lsmt_file);
    if (offset > 0) ovbdsize -= offset;
    /* offset is beyond i_size, weird but possible */
    if (ovbdsize < 0) return 0;

    if (sizelimit > 0 && sizelimit < ovbdsize) ovbdsize = sizelimit;
    /*
     * Unfortunately, if we want to do I/O on the device,
     * the number of 512-byte sectors has to fit into a sector_t.
     */
    return ovbdsize >> 9;
}

static loff_t get_ovbd_size(struct ovbd_device *lo,
                            struct lsmt_file *lsmt_file) {
    return get_size(lo->ov_offset, lo->ov_sizelimit, lsmt_file);
}

/**
 * ovbd_validate_block_size() - validates the passed in block size
 * @bsize: size to validate
 */
static int ovbd_validate_block_size(unsigned short bsize) {
    if (bsize < 512 || bsize > PAGE_SIZE || !is_power_of_2(bsize))
        return -EINVAL;

    return 0;
}

/**
 * ovbd_set_size() - sets device size and notifies userspace
 * @lo: struct ovbd_device to set the size for
 * @size: new size of the ovbd device
 *
 * Callers must validate that the size passed into this function fits into
 * a sector_t, eg using ovbd_validate_size()
 */
static void ovbd_set_size(struct ovbd_device *lo, loff_t size) {
    struct block_device *bdev = lo->ov_device;

    bd_set_size(bdev, size << SECTOR_SHIFT);

    set_capacity_revalidate_and_notify(lo->ov_disk, size, false);
}

static int ov_read_simple(struct ovbd_device *lo, struct request *rq,
                          loff_t pos) {
    struct bio_vec bvec;
    struct req_iterator iter;
    ssize_t len;
    void *mem;
    ssize_t offset = blk_rq_pos(rq) << 9;

    rq_for_each_segment(bvec, rq, iter) {
        mem = kmap_atomic(bvec.bv_page);
        len = lsmt_read(ovbd->fp, mem + bvec.bv_offset, bvec.bv_len, pos);
        kunmap_atomic(mem);

        if (len < 0) return len;

        flush_dcache_page(bvec.bv_page);

        if (len != bvec.bv_len) {
            struct bio *bio;

            __rq_for_each_bio(bio, rq) zero_fill_bio(bio);
            break;
        }
        cond_resched();
    }

    return 0;
}

static void ov_complete_rq(struct request *rq) {
    struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);
    blk_status_t ret = BLK_STS_OK;

    if (cmd->ret < 0 || cmd->ret == blk_rq_bytes(rq) ||
        req_op(rq) != REQ_OP_READ) {
        if (cmd->ret < 0) ret = errno_to_blk_status(cmd->ret);
        goto end_io;
    }

    /*
     * Short READ - if we got some data, advance our request and
     * retry it. If we got no data, end the rest with EIO.
     */
    if (cmd->ret) {
        blk_update_request(rq, BLK_STS_OK, cmd->ret);
        cmd->ret = 0;
        blk_mq_requeue_request(rq, true);
    } else {
        ret = BLK_STS_IOERR;
    end_io:
        blk_mq_end_request(rq, ret);
    }
}

static int do_req_filebacked(struct ovbd_device *lo, struct request *rq) {
    loff_t pos = ((loff_t)blk_rq_pos(rq) << 9) + lo->ov_offset;

    /*
     * ov_write_simple and ov_read_simple should have been covered
     * by io submit style function like ov_rw_aio(), one blocker
     * is that ov_read_simple() need to call flush_dcache_page after
     * the page is written from kernel, and it isn't easy to handle
     * this in io submit style function which submits all segments
     * of the req at one time. And direct read IO doesn't need to
     * run flush_dcache_page().
     */
    switch (req_op(rq)) {
        case REQ_OP_READ:
            return ov_read_simple(lo, rq, pos);
        default:
            WARN_ON_ONCE(1);
            return -EIO;
    }
}

/*
 * ovbd_change_fd switched the backing store of a ovbdback device to
 * a new lsmt_file. This is useful for operating system installers to free up
 * the original lsmt_file and in High Availability environments to switch to
 * an alternative location for the content in case of server meltdown.
 * This can only work if the ovbd device is used read-only, and if the
 * new backing store is the same size and type as the old backing store.
 */
static int ovbd_change_fd(struct ovbd_device *lo, struct block_device *bdev,
                          unsigned int arg) {
    struct lsmt_file *lsmt_file = NULL, *old_file;
	struct file *file;
    int error;

    error = mutex_lock_killable(&ovbd_ctl_mutex);
    if (error) return error;
    error = -ENXIO;
    if (lo->ov_state != Lo_bound) goto out_err;

    /* the ovbd device has to be read-only */
    error = -EINVAL;

    error = -EBADF;
    file = fget(arg);
    lsmt_file = lsmt_open(zfile_open_by_file(file));
    if (!file) goto out_err;

    old_file = lo->ov_backing_file;

    error = -EINVAL;

    /* size of the new backing store needs to be the same */
    if (get_ovbd_size(lo, lsmt_file) != get_ovbd_size(lo, old_file))
        goto out_err;

    /* and ... switch */
    blk_mq_freeze_queue(lo->ov_queue);
    lo->ov_backing_file = lsmt_file;
    blk_mq_unfreeze_queue(lo->ov_queue);
    mutex_unlock(&ovbd_ctl_mutex);
    /*
     * We must drop lsmt_file reference outside of ovbd_ctl_mutex as dropping
     * the lsmt_file ref can take bd_mutex which creates circular locking
     * dependency.
     */
    lsmt_close(old_file);
    return 0;

out_err:
    mutex_unlock(&ovbd_ctl_mutex);
    if (lsmt_file) lsmt_close(lsmt_file);
    return error;
}

/* ovbd sysfs attributes */

static ssize_t ovbd_attr_show(struct device *dev, char *page,
                              ssize_t (*callback)(struct ovbd_device *,
                                                  char *)) {
    struct gendisk *disk = dev_to_disk(dev);
    struct ovbd_device *lo = disk->private_data;

    return callback(lo, page);
}

#define OVBD_ATTR_RO(_name)                                                \
    static ssize_t ovbd_attr_##_name##_show(struct ovbd_device *, char *); \
    static ssize_t ovbd_attr_do_show_##_name(                              \
        struct device *d, struct device_attribute *attr, char *b) {        \
        return ovbd_attr_show(d, b, ovbd_attr_##_name##_show);             \
    }                                                                      \
    static struct device_attribute ovbd_attr_##_name =                     \
        __ATTR(_name, 0444, ovbd_attr_do_show_##_name, NULL);

static ssize_t ovbd_attr_backing_file_show(struct ovbd_device *lo, char *buf) {
    ssize_t ret;
    char *p = NULL;

    spin_lock_irq(&lo->ov_lock);
    if (lo->ov_backing_file)
        p = file_path(lsmt_getfile(lo->ov_backing_file), buf, PAGE_SIZE - 1);
    spin_unlock_irq(&lo->ov_lock);

    if (IS_ERR_OR_NULL(p))
        ret = PTR_ERR(p);
    else {
        ret = strlen(p);
        memmove(buf, p, ret);
        buf[ret++] = '\n';
        buf[ret] = 0;
    }

    return ret;
}

static ssize_t ovbd_attr_offset_show(struct ovbd_device *lo, char *buf) {
    return sprintf(buf, "%llu\n", (unsigned long long)lo->ov_offset);
}

static ssize_t ovbd_attr_sizelimit_show(struct ovbd_device *lo, char *buf) {
    return sprintf(buf, "%llu\n", (unsigned long long)lo->ov_sizelimit);
}

static ssize_t ovbd_attr_autoclear_show(struct ovbd_device *lo, char *buf) {
    return sprintf(buf, "0\n");
}

static ssize_t ovbd_attr_partscan_show(struct ovbd_device *lo, char *buf) {
    return sprintf(buf, "0\n");
}

static ssize_t ovbd_attr_dio_show(struct ovbd_device *lo, char *buf) {
    return sprintf(buf, "0\n");
}

OVBD_ATTR_RO(backing_file);
OVBD_ATTR_RO(offset);
OVBD_ATTR_RO(sizelimit);
OVBD_ATTR_RO(autoclear);
OVBD_ATTR_RO(partscan);
OVBD_ATTR_RO(dio);

static struct attribute *ovbd_attrs[] = {
    &ovbd_attr_backing_file.attr,
    &ovbd_attr_offset.attr,
    &ovbd_attr_sizelimit.attr,
    &ovbd_attr_autoclear.attr,
    &ovbd_attr_partscan.attr,
    &ovbd_attr_dio.attr,
    NULL,
};

static struct attribute_group ovbd_attribute_group = {
    .name = "ovbd",
    .attrs = ovbd_attrs,
};

static void ovbd_sysfs_init(struct ovbd_device *lo) {
    lo->sysfs_inited = !sysfs_create_group(&disk_to_dev(lo->ov_disk)->kobj,
                                           &ovbd_attribute_group);
}

static void ovbd_sysfs_exit(struct ovbd_device *lo) {
    if (lo->sysfs_inited)
        sysfs_remove_group(&disk_to_dev(lo->ov_disk)->kobj,
                           &ovbd_attribute_group);
}

static void ovbd_config_discard(struct ovbd_device *lo) {
    struct request_queue *q = lo->ov_queue;

    blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
}

static void ovbd_unprepare_queue(struct ovbd_device *lo) {
    kthread_flush_worker(&lo->worker);
    kthread_stop(lo->worker_task);
}

static int ovbd_kthread_worker_fn(void *worker_ptr) {
    current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
    return kthread_worker_fn(worker_ptr);
}

static int ovbd_prepare_queue(struct ovbd_device *lo) {
    kthread_init_worker(&lo->worker);
    lo->worker_task = kthread_run(ovbd_kthread_worker_fn, &lo->worker, "ovbd%d",
                                  lo->ov_number);
    if (IS_ERR(lo->worker_task)) return -ENOMEM;
    set_user_nice(lo->worker_task, MIN_NICE);
    return 0;
}

static void ovbd_update_rotational(struct ovbd_device *lo) {
    struct request_queue *q = lo->ov_queue;
    blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
}

/**
 * ovbd_set_status_from_info - configure device from ovbd_info
 * @lo: struct ovbd_device to configure
 * @info: struct ovbd_info64 to configure the device with
 *
 * Configures the ovbd device parameters according to the passed
 * in ovbd_info64 configuration.
 */
static int ovbd_set_status_from_info(struct ovbd_device *lo,
                                     const struct ovbd_info64 *info) {
    lo->ov_offset = info->ov_offset;
    lo->ov_sizelimit = info->ov_sizelimit;
    memcpy(lo->ov_file_name, info->ov_file_name, OV_NAME_SIZE);
    lo->ov_file_name[OV_NAME_SIZE - 1] = 0;

    lo->ov_flags = info->ov_flags;

    lo->ov_init[0] = info->ov_init[0];
    lo->ov_init[1] = info->ov_init[1];

    return 0;
}

static int ovbd_configure(struct ovbd_device *lo, fmode_t mode,
                          struct block_device *bdev,
                          const struct ovbd_config *config) {
    struct lsmt_file *lsmt_file;
    struct file *file;
    struct inode *inode;
    struct block_device *claimed_bdev = NULL;
    int error;
    loff_t size;
    unsigned short bsize;

    /* This is safe, since we have a reference from open(). */
    __module_get(THIS_MODULE);

    error = -EBADF;
    file = fget(config->fd);
    lsmt_file = lsmt_open(zfile_open_by_file(file));
    if (!lsmt_file) goto out;

    /*
     * If we don't hold exclusive handle for the device, upgrade to it
     * here to avoid changing device under exclusive owner.
     */
    if (!(mode & FMODE_EXCL)) {
        claimed_bdev = bd_start_claiming(bdev, ovbd_configure);
        if (IS_ERR(claimed_bdev)) {
            error = PTR_ERR(claimed_bdev);
            goto out_putf;
        }
    }

    error = mutex_lock_killable(&ovbd_ctl_mutex);
    if (error) goto out_bdev;

    error = -EBUSY;
    if (lo->ov_state != Lo_unbound) goto out_unlock;

    size = get_ovbd_size(lo, lsmt_file);

    if (config->block_size) {
        error = ovbd_validate_block_size(config->block_size);
        if (error) goto out_unlock;
    }

    error = ovbd_set_status_from_info(lo, &config->info);
    if (error) goto out_unlock;

    error = ovbd_prepare_queue(lo);
    if (error) goto out_unlock;

    set_device_ro(bdev, true);

    lo->ov_device = bdev;
    lo->ov_backing_file = lsmt_file;

    if (config->block_size)
        bsize = config->block_size;
    else
        bsize = 512;

    blk_queue_logical_block_size(lo->ov_queue, bsize);
    blk_queue_physical_block_size(lo->ov_queue, bsize);
    blk_queue_io_min(lo->ov_queue, bsize);

    ovbd_update_rotational(lo);
    ovbd_sysfs_init(lo);
    ovbd_set_size(lo, size);

    set_blocksize(
        bdev, S_ISBLK(inode->i_mode) ? block_size(inode->i_bdev) : PAGE_SIZE);

    lo->ov_state = Lo_bound;

    /* Grab the block_device to prevent its destruction after we
     * put /dev/ovbdXX inode. Later in __ovbd_clr_fd() we bdput(bdev).
     */
    bdgrab(bdev);
    mutex_unlock(&ovbd_ctl_mutex);
    if (claimed_bdev) bd_abort_claiming(bdev, claimed_bdev, ovbd_configure);
    return 0;

out_unlock:
    mutex_unlock(&ovbd_ctl_mutex);
out_bdev:
    if (claimed_bdev) bd_abort_claiming(bdev, claimed_bdev, ovbd_configure);
out_putf:
    lsmt_close(lsmt_file);
out:
    /* This is safe: open() is still holding a reference. */
    module_put(THIS_MODULE);
    return error;
}

static int __ovbd_clr_fd(struct ovbd_device *lo, bool release) {
    struct lsmt_file *filp = NULL;
    struct block_device *bdev = lo->ov_device;
    int err = 0;
    int ov_number;

    mutex_lock(&ovbd_ctl_mutex);
    if (WARN_ON_ONCE(lo->ov_state != Lo_rundown)) {
        err = -ENXIO;
        goto out_unlock;
    }

    filp = lo->ov_backing_file;
    if (filp == NULL) {
        err = -EINVAL;
        goto out_unlock;
    }

    /* freeze request queue during the transition */
    blk_mq_freeze_queue(lo->ov_queue);

    spin_lock_irq(&lo->ov_lock);
    lo->ov_backing_file = NULL;
    spin_unlock_irq(&lo->ov_lock);

    lo->ioctl = NULL;
    lo->ov_device = NULL;
    lo->ov_offset = 0;
    lo->ov_sizelimit = 0;
    memset(lo->ov_file_name, 0, OV_NAME_SIZE);
    blk_queue_logical_block_size(lo->ov_queue, 512);
    blk_queue_physical_block_size(lo->ov_queue, 512);
    blk_queue_io_min(lo->ov_queue, 512);
    if (bdev) {
        bdput(bdev);
        invalidate_bdev(bdev);
        bdev->bd_inode->i_mapping->wb_err = 0;
    }
    set_capacity(lo->ov_disk, 0);
    ovbd_sysfs_exit(lo);
    if (bdev) {
        bd_set_size(bdev, 0);
        /* let user-space know about this change */
        kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
    }
    /* This is safe: open() is still holding a reference. */
    module_put(THIS_MODULE);
    blk_mq_unfreeze_queue(lo->ov_queue);

    ov_number = lo->ov_number;
    ovbd_unprepare_queue(lo);
out_unlock:
    mutex_unlock(&ovbd_ctl_mutex);

    /*
     * lo->ov_state is set to Lo_unbound here after above partscan has
     * finished.
     *
     * There cannot be anybody else entering __ovbd_clr_fd() as
     * lo->ov_backing_file is already cleared and Lo_rundown state
     * protects us from all the other places trying to change the 'lo'
     * device.
     */
    mutex_lock(&ovbd_ctl_mutex);
    lo->ov_flags = 0;
    if (!part_shift) lo->ov_disk->flags |= GENHD_FL_NO_PART_SCAN;
    lo->ov_state = Lo_unbound;
    mutex_unlock(&ovbd_ctl_mutex);

    /*
     * Need not hold ovbd_ctl_mutex to fput backing lsmt_file.
     * Calling fput holding ovbd_ctl_mutex triggers a circular
     * lock dependency possibility warning as fput can take
     * bd_mutex which is usually taken before ovbd_ctl_mutex.
     */
    if (filp) lsmt_close(filp);
    return err;
}

static int ovbd_clr_fd(struct ovbd_device *lo) {
    int err;

    err = mutex_lock_killable(&ovbd_ctl_mutex);
    if (err) return err;
    if (lo->ov_state != Lo_bound) {
        mutex_unlock(&ovbd_ctl_mutex);
        return -ENXIO;
    }
    /*
     * If we've explicitly asked to tear down the ovbd device,
     * and it has an elevated reference count, set it for auto-teardown when
     * the last reference goes away. This stops $!~#$@ udev from
     * preventing teardown because it decided that it needs to run blkid on
     * the ovbdback device whenever they appear. xfstests is notorious for
     * failing tests because blkid via udev races with a losetup
     * <dev>/do something like mkfs/losetup -d <dev> causing the losetup -d
     * command to fail with EBUSY.
     */
    lo->ov_state = Lo_rundown;
    mutex_unlock(&ovbd_ctl_mutex);

    return __ovbd_clr_fd(lo, false);
}

static int ovbd_set_status(struct ovbd_device *lo,
                           const struct ovbd_info64 *info) {
    int err;
    int prev_ov_flags;
    bool size_changed = false;

    err = mutex_lock_killable(&ovbd_ctl_mutex);
    if (err) return err;
    if (lo->ov_state != Lo_bound) {
        err = -ENXIO;
        goto out_unlock;
    }

    if (lo->ov_offset != info->ov_offset ||
        lo->ov_sizelimit != info->ov_sizelimit) {
        size_changed = true;
        sync_blockdev(lo->ov_device);
        invalidate_bdev(lo->ov_device);
    }

    /* I/O need to be drained during transfer transition */
    blk_mq_freeze_queue(lo->ov_queue);

    if (size_changed && lo->ov_device->bd_inode->i_mapping->nrpages) {
        /* If any pages were dirtied after invalidate_bdev(), try again */
        err = -EAGAIN;
        pr_warn("%s: ovbd%d (%s) has still dirty pages (nrpages=%lu)\n",
                __func__, lo->ov_number, lo->ov_file_name,
                lo->ov_device->bd_inode->i_mapping->nrpages);
        goto out_unfreeze;
    }

    prev_ov_flags = lo->ov_flags;

    err = ovbd_set_status_from_info(lo, info);
    if (err) goto out_unfreeze;

    if (size_changed) {
        loff_t new_size =
            get_size(lo->ov_offset, lo->ov_sizelimit, lo->ov_backing_file);
        ovbd_set_size(lo, new_size);
    }

    ovbd_config_discard(lo);

out_unfreeze:
    blk_mq_unfreeze_queue(lo->ov_queue);

out_unlock:
    mutex_unlock(&ovbd_ctl_mutex);

    return err;
}

static int ovbd_get_status(struct ovbd_device *lo, struct ovbd_info64 *info) {
    struct path path;
    struct kstat stat;
    int ret;

    ret = mutex_lock_killable(&ovbd_ctl_mutex);
    if (ret) return ret;
    if (lo->ov_state != Lo_bound) {
        mutex_unlock(&ovbd_ctl_mutex);
        return -ENXIO;
    }

    memset(info, 0, sizeof(*info));
    info->ov_number = lo->ov_number;
    info->ov_offset = lo->ov_offset;
    info->ov_sizelimit = lo->ov_sizelimit;
    info->ov_flags = lo->ov_flags;
    memcpy(info->ov_file_name, lo->ov_file_name, OV_NAME_SIZE);
    /* Drop ovbd_ctl_mutex while we call into the filesystem. */
    path = lsmt_getpath(lo->ov_backing_file);
    path_get(&path);
    mutex_unlock(&ovbd_ctl_mutex);
    ret = vfs_getattr(&path, &stat, STATX_INO, AT_STATX_SYNC_AS_STAT);
    if (!ret) {
        info->ov_device = huge_encode_dev(stat.dev);
        info->ov_inode = stat.ino;
        info->ov_rdevice = huge_encode_dev(stat.rdev);
    }
    path_put(&path);
    return ret;
}

static void ovbd_info64_from_old(const struct ovbd_info *info,
                                 struct ovbd_info64 *info64) {
    memset(info64, 0, sizeof(*info64));
    info64->ov_number = info->ov_number;
    info64->ov_device = info->ov_device;
    info64->ov_inode = info->ov_inode;
    info64->ov_rdevice = info->ov_rdevice;
    info64->ov_offset = info->ov_offset;
    info64->ov_sizelimit = 0;
    info64->ov_encrypt_type = info->ov_encrypt_type;
    info64->ov_encrypt_key_size = info->ov_encrypt_key_size;
    info64->ov_flags = info->ov_flags;
    info64->ov_init[0] = info->ov_init[0];
    info64->ov_init[1] = info->ov_init[1];
}

static int ovbd_info64_to_old(const struct ovbd_info64 *info64,
                              struct ovbd_info *info) {
    memset(info, 0, sizeof(*info));
    info->ov_number = info64->ov_number;
    info->ov_device = info64->ov_device;
    info->ov_inode = info64->ov_inode;
    info->ov_rdevice = info64->ov_rdevice;
    info->ov_offset = info64->ov_offset;
    info->ov_encrypt_type = info64->ov_encrypt_type;
    info->ov_encrypt_key_size = info64->ov_encrypt_key_size;
    info->ov_flags = info64->ov_flags;
    info->ov_init[0] = info64->ov_init[0];
    info->ov_init[1] = info64->ov_init[1];

    /* error in case values were truncated */
    if (info->ov_device != info64->ov_device ||
        info->ov_rdevice != info64->ov_rdevice ||
        info->ov_inode != info64->ov_inode ||
        info->ov_offset != info64->ov_offset)
        return -EOVERFLOW;

    return 0;
}

static int ovbd_set_status_old(struct ovbd_device *lo,
                               const struct ovbd_info __user *arg) {
    struct ovbd_info info;
    struct ovbd_info64 info64;

    if (copy_from_user(&info, arg, sizeof(struct ovbd_info))) return -EFAULT;
    ovbd_info64_from_old(&info, &info64);
    return ovbd_set_status(lo, &info64);
}

static int ovbd_set_status64(struct ovbd_device *lo,
                             const struct ovbd_info64 __user *arg) {
    struct ovbd_info64 info64;

    if (copy_from_user(&info64, arg, sizeof(struct ovbd_info64)))
        return -EFAULT;
    return ovbd_set_status(lo, &info64);
}

static int ovbd_get_status_old(struct ovbd_device *lo,
                               struct ovbd_info __user *arg) {
    struct ovbd_info info;
    struct ovbd_info64 info64;
    int err;

    if (!arg) return -EINVAL;
    err = ovbd_get_status(lo, &info64);
    if (!err) err = ovbd_info64_to_old(&info64, &info);
    if (!err && copy_to_user(arg, &info, sizeof(info))) err = -EFAULT;

    return err;
}

static int ovbd_get_status64(struct ovbd_device *lo,
                             struct ovbd_info64 __user *arg) {
    struct ovbd_info64 info64;
    int err;

    if (!arg) return -EINVAL;
    err = ovbd_get_status(lo, &info64);
    if (!err && copy_to_user(arg, &info64, sizeof(info64))) err = -EFAULT;

    return err;
}

static int ovbd_set_capacity(struct ovbd_device *lo) {
    loff_t size;

    if (unlikely(lo->ov_state != Lo_bound)) return -ENXIO;

    size = get_ovbd_size(lo, lo->ov_backing_file);
    ovbd_set_size(lo, size);

    return 0;
}

static int ovbd_set_block_size(struct ovbd_device *lo, unsigned long arg) {
    int err = 0;

    if (lo->ov_state != Lo_bound) return -ENXIO;

    err = ovbd_validate_block_size(arg);
    if (err) return err;

    if (lo->ov_queue->limits.logical_block_size == arg) return 0;

    sync_blockdev(lo->ov_device);
    invalidate_bdev(lo->ov_device);

    blk_mq_freeze_queue(lo->ov_queue);

    /* invalidate_bdev should have truncated all the pages */
    if (lo->ov_device->bd_inode->i_mapping->nrpages) {
        err = -EAGAIN;
        pr_warn("%s: ovbd%d (%s) has still dirty pages (nrpages=%lu)\n",
                __func__, lo->ov_number, lo->ov_file_name,
                lo->ov_device->bd_inode->i_mapping->nrpages);
        goto out_unfreeze;
    }

    blk_queue_logical_block_size(lo->ov_queue, arg);
    blk_queue_physical_block_size(lo->ov_queue, arg);
    blk_queue_io_min(lo->ov_queue, arg);
out_unfreeze:
    blk_mq_unfreeze_queue(lo->ov_queue);

    return err;
}

static int ov_simple_ioctl(struct ovbd_device *lo, unsigned int cmd,
                           unsigned long arg) {
    int err;

    err = mutex_lock_killable(&ovbd_ctl_mutex);
    if (err) return err;
    switch (cmd) {
        case OVBD_SET_CAPACITY:
            err = ovbd_set_capacity(lo);
            break;
        case OVBD_SET_BLOCK_SIZE:
            err = ovbd_set_block_size(lo, arg);
            break;
        default:
            err = lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;
    }
    mutex_unlock(&ovbd_ctl_mutex);
    return err;
}

static int ov_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
                    unsigned long arg) {
    struct ovbd_device *lo = bdev->bd_disk->private_data;
    void __user *argp = (void __user *)arg;
    int err;

    switch (cmd) {
        case OVBD_SET_FD: {
            /*
             * Legacy case - pass in a zeroed out struct ovbd_config with
             * only the lsmt_file descriptor set , which corresponds with the
             * default parameters we'd have used otherwise.
             */
            struct ovbd_config config;

            memset(&config, 0, sizeof(config));
            config.fd = arg;

            return ovbd_configure(lo, mode, bdev, &config);
        }
        case OVBD_CONFIGURE: {
            struct ovbd_config config;

            if (copy_from_user(&config, argp, sizeof(config))) return -EFAULT;

            return ovbd_configure(lo, mode, bdev, &config);
        }
        case OVBD_CHANGE_FD:
            return ovbd_change_fd(lo, bdev, arg);
        case OVBD_CLR_FD:
            return ovbd_clr_fd(lo);
        case OVBD_SET_STATUS:
            err = -EPERM;
            if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN)) {
                err = ovbd_set_status_old(lo, argp);
            }
            break;
        case OVBD_GET_STATUS:
            return ovbd_get_status_old(lo, argp);
        case OVBD_SET_STATUS64:
            err = -EPERM;
            if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN)) {
                err = ovbd_set_status64(lo, argp);
            }
            break;
        case OVBD_GET_STATUS64:
            return ovbd_get_status64(lo, argp);
        case OVBD_SET_CAPACITY:
        case OVBD_SET_BLOCK_SIZE:
            if (!(mode & FMODE_WRITE) && !capable(CAP_SYS_ADMIN)) return -EPERM;
            /* Fall through */
        default:
            err = ov_simple_ioctl(lo, cmd, arg);
            break;
    }

    return err;
}

static int ov_open(struct block_device *bdev, fmode_t mode) {
    struct ovbd_device *lo;
    int err;

    err = mutex_lock_killable(&ovbd_ctl_mutex);
    if (err) return err;
    lo = bdev->bd_disk->private_data;
    if (!lo) {
        err = -ENXIO;
        goto out;
    }

    atomic_inc(&lo->ov_refcnt);
out:
    mutex_unlock(&ovbd_ctl_mutex);
    return err;
}

static void ov_release(struct gendisk *disk, fmode_t mode) {
    struct ovbd_device *lo;

    mutex_lock(&ovbd_ctl_mutex);
    lo = disk->private_data;
    if (atomic_dec_return(&lo->ov_refcnt)) goto out_unlock;

    if (lo->ov_state == Lo_bound) {
        /*
         * Otherwise keep thread (if running) and config,
         * but flush possible ongoing bios in thread.
         */
        blk_mq_freeze_queue(lo->ov_queue);
        blk_mq_unfreeze_queue(lo->ov_queue);
    }

out_unlock:
    mutex_unlock(&ovbd_ctl_mutex);
}

static const struct block_device_operations ov_fops = {
    .owner = THIS_MODULE,
    .open = ov_open,
    .release = ov_release,
    .ioctl = ov_ioctl,
};

/*
 * And now the modules code and kernel interface.
 */
static int max_ovbd;
module_param(max_ovbd, int, 0444);
MODULE_PARM_DESC(max_ovbd, "Maximum number of ovbd devices");
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per ovbd device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(OVBD_MAJOR);

static blk_status_t ovbd_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  const struct blk_mq_queue_data *bd) {
    struct request *rq = bd->rq;
    struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);
    struct ovbd_device *lo = rq->q->queuedata;

    blk_mq_start_request(rq);

    if (lo->ov_state != Lo_bound) return BLK_STS_IOERR;

    /* always use the first bio's css */
    cmd->css = NULL;
    kthread_queue_work(&lo->worker, &cmd->work);

    return BLK_STS_OK;
}

static void ovbd_handle_cmd(struct ovbd_cmd *cmd) {
    struct request *rq = blk_mq_rq_from_pdu(cmd);
    const bool write = op_is_write(req_op(rq));
    struct ovbd_device *lo = rq->q->queuedata;
    int ret = 0;

    if (write) {
        ret = -EIO;
        goto failed;
    }

    ret = do_req_filebacked(lo, rq);
failed:
    /* complete non-aio request */
    if (ret) {
        if (ret == -EOPNOTSUPP)
            cmd->ret = ret;
        else
            cmd->ret = ret ? -EIO : 0;
        blk_mq_complete_request(rq);
    }
}

static void ovbd_queue_work(struct kthread_work *work) {
    struct ovbd_cmd *cmd = container_of(work, struct ovbd_cmd, work);

    ovbd_handle_cmd(cmd);
}

static int ovbd_init_request(struct blk_mq_tag_set *set, struct request *rq,
                             unsigned int hctx_idx, unsigned int numa_node) {
    struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);

    kthread_init_work(&cmd->work, ovbd_queue_work);
    return 0;
}

static const struct blk_mq_ops ovbd_mq_ops = {
    .queue_rq = ovbd_queue_rq,
    .init_request = ovbd_init_request,
    .complete = ov_complete_rq,
};

static int ovbd_add(struct ovbd_device **l, int i) {
    struct ovbd_device *lo;
    struct gendisk *disk;
    int err;

    err = -ENOMEM;
    lo = kzalloc(sizeof(*lo), GFP_KERNEL);
    if (!lo) goto out;

    lo->ov_state = Lo_unbound;

    /* allocate id, if @id >= 0, we're requesting that specific id */
    if (i >= 0) {
        err = idr_alloc(&ovbd_index_idr, lo, i, i + 1, GFP_KERNEL);
        if (err == -ENOSPC) err = -EEXIST;
    } else {
        err = idr_alloc(&ovbd_index_idr, lo, 0, 0, GFP_KERNEL);
    }
    if (err < 0) goto out_free_dev;
    i = err;

    err = -ENOMEM;
    lo->tag_set.ops = &ovbd_mq_ops;
    lo->tag_set.nr_hw_queues = 1;
    lo->tag_set.queue_depth = 128;
    lo->tag_set.numa_node = NUMA_NO_NODE;
    lo->tag_set.cmd_size = sizeof(struct ovbd_cmd);
    lo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING;
    lo->tag_set.driver_data = lo;

    err = blk_mq_alloc_tag_set(&lo->tag_set);
    if (err) goto out_free_idr;

    lo->ov_queue = blk_mq_init_queue(&lo->tag_set);
    if (IS_ERR(lo->ov_queue)) {
        err = PTR_ERR(lo->ov_queue);
        goto out_cleanup_tags;
    }
    lo->ov_queue->queuedata = lo;

    blk_queue_max_hw_sectors(lo->ov_queue, BLK_DEF_MAX_SECTORS);

    /*
     * By default, we do buffer IO, so it doesn't make sense to enable
     * merge because the I/O submitted to backing lsmt_file is handled page by
     * page. For directio mode, merge does help to dispatch bigger request
     * to underlayer disk. We will enable merge once directio is enabled.
     */
    blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->ov_queue);

    err = -ENOMEM;
    disk = lo->ov_disk = alloc_disk(1 << part_shift);
    if (!disk) goto out_free_queue;

    /*
     * Disable partition scanning by default. The in-kernel partition
     * scanning can be requested individually per-device during its
     * setup. Userspace can always add and remove partitions from all
     * devices. The needed partition minors are allocated from the
     * extended minor space, the main ovbd device numbers will continue
     * to match the ovbd minors, regardless of the number of partitions
     * used.
     *
     * If max_part is given, partition scanning is globally enabled for
     * all ovbd devices. The minors for the main ovbd devices will be
     * multiples of max_part.
     *
     * Note: Global-for-all-devices, set-only-at-init, read-only module
     * parameteters like 'max_ovbd' and 'max_part' make things needlessly
     * complicated, are too static, inflexible and may surprise
     * userspace tools. Parameters like this in general should be avoided.
     */
    if (!part_shift) disk->flags |= GENHD_FL_NO_PART_SCAN;
    disk->flags |= GENHD_FL_EXT_DEVT;
    atomic_set(&lo->ov_refcnt, 0);
    lo->ov_number = i;
    spin_lock_init(&lo->ov_lock);
    disk->major = OVBD_MAJOR;
    disk->first_minor = i << part_shift;
    disk->fops = &ov_fops;
    disk->private_data = lo;
    disk->queue = lo->ov_queue;
    sprintf(disk->disk_name, "ovbd%d", i);
    add_disk(disk);
    *l = lo;
    return lo->ov_number;

out_free_queue:
    blk_cleanup_queue(lo->ov_queue);
out_cleanup_tags:
    blk_mq_free_tag_set(&lo->tag_set);
out_free_idr:
    idr_remove(&ovbd_index_idr, i);
out_free_dev:
    kfree(lo);
out:
    return err;
}

static void ovbd_remove(struct ovbd_device *lo) {
    del_gendisk(lo->ov_disk);
    blk_cleanup_queue(lo->ov_queue);
    blk_mq_free_tag_set(&lo->tag_set);
    put_disk(lo->ov_disk);
    kfree(lo);
}

static int find_free_cb(int id, void *ptr, void *data) {
    struct ovbd_device *lo = ptr;
    struct ovbd_device **l = data;

    if (lo->ov_state == Lo_unbound) {
        *l = lo;
        return 1;
    }
    return 0;
}

static int ovbd_lookup(struct ovbd_device **l, int i) {
    struct ovbd_device *lo;
    int ret = -ENODEV;

    if (i < 0) {
        int err;

        err = idr_for_each(&ovbd_index_idr, &find_free_cb, &lo);
        if (err == 1) {
            *l = lo;
            ret = lo->ov_number;
        }
        goto out;
    }

    /* lookup and return a specific i */
    lo = idr_find(&ovbd_index_idr, i);
    if (lo) {
        *l = lo;
        ret = lo->ov_number;
    }
out:
    return ret;
}

static struct kobject *ovbd_probe(dev_t dev, int *part, void *data) {
    struct ovbd_device *lo;
    struct kobject *kobj;
    int err;

    mutex_lock(&ovbd_ctl_mutex);
    err = ovbd_lookup(&lo, MINOR(dev) >> part_shift);
    if (err < 0) err = ovbd_add(&lo, MINOR(dev) >> part_shift);
    if (err < 0)
        kobj = NULL;
    else
        kobj = get_disk_and_module(lo->ov_disk);
    mutex_unlock(&ovbd_ctl_mutex);

    *part = 0;
    return kobj;
}

static long ovbd_control_ioctl(struct file *file, unsigned int cmd,
                               unsigned long parm) {
    struct ovbd_device *lo;
    int ret;

    ret = mutex_lock_killable(&ovbd_ctl_mutex);
    if (ret) return ret;

    ret = -ENOSYS;
    switch (cmd) {
        case OVBD_CTL_ADD:
            ret = ovbd_lookup(&lo, parm);
            if (ret >= 0) {
                ret = -EEXIST;
                break;
            }
            ret = ovbd_add(&lo, parm);
            break;
        case OVBD_CTL_REMOVE:
            ret = ovbd_lookup(&lo, parm);
            if (ret < 0) break;
            if (lo->ov_state != Lo_unbound) {
                ret = -EBUSY;
                break;
            }
            if (atomic_read(&lo->ov_refcnt) > 0) {
                ret = -EBUSY;
                break;
            }
            lo->ov_disk->private_data = NULL;
            idr_remove(&ovbd_index_idr, lo->ov_number);
            ovbd_remove(lo);
            break;
        case OVBD_CTL_GET_FREE:
            ret = ovbd_lookup(&lo, -1);
            if (ret >= 0) break;
            ret = ovbd_add(&lo, -1);
    }
    mutex_unlock(&ovbd_ctl_mutex);

    return ret;
}

static const struct file_operations ovbd_ctl_fops = {
    .open = nonseekable_open,
    .unlocked_ioctl = ovbd_control_ioctl,
    .compat_ioctl = ovbd_control_ioctl,
    .owner = THIS_MODULE,
    .llseek = noop_llseek,
};

static struct miscdevice ovbd_misc = {
    .minor = OVBD_CTRL_MINOR,
    .name = "ovbd-control",
    .fops = &ovbd_ctl_fops,
};

MODULE_ALIAS_MISCDEV(OVBD_CTRL_MINOR);
MODULE_ALIAS("devname:ovbd-control");

static int __init ovbd_init(void) {
    int i, nr;
    unsigned long range;
    struct ovbd_device *lo;
    int err;

    pr_info("ovbd: init\n");
    part_shift = 0;
    if (max_part > 0) {
        part_shift = fls(max_part);

        /*
         * Adjust max_part according to part_shift as it is exported
         * to user space so that user can decide correct minor number
         * if [s]he want to create more devices.
         *
         * Note that -1 is required because partition 0 is reserved
         * for the whole disk.
         */
        max_part = (1UL << part_shift) - 1;
    }

    pr_info("ovbd: partshift\n");

    if ((1UL << part_shift) > DISK_MAX_PARTS) {
        err = -EINVAL;
        goto err_out;
    }

    pr_info("ovbd: maxovbd\n");

    if (max_ovbd > 1UL << (MINORBITS - part_shift)) {
        err = -EINVAL;
        goto err_out;
    }
    nr = max_ovbd;
    range = max_ovbd << part_shift;

    pr_info("ovbd: misc_register\n");
    err = misc_register(&ovbd_misc);
    if (err < 0) {
        pr_info("err=%d\n", err);
        goto err_out;
    }

    pr_info("ovbd: dev_register\n");
    if (register_blkdev(OVBD_MAJOR, "ovbd")) {
        err = -EIO;
        goto misc_out;
    }

    pr_info("ovbd: blk_register\n");
    blk_register_region(MKDEV(OVBD_MAJOR, 0), range, THIS_MODULE, ovbd_probe,
                        NULL, NULL);

    /* pre-create number of devices given by config or max_ovbd */
    pr_info("ovbd: add dev\n");
    mutex_lock(&ovbd_ctl_mutex);
    for (i = 0; i < nr; i++) ovbd_add(&lo, i);
    mutex_unlock(&ovbd_ctl_mutex);

    printk(KERN_INFO "ovbd: module loaded\n");
    return 0;

misc_out:
    misc_deregister(&ovbd_misc);
err_out:
    return err;
}

static int ovbd_exit_cb(int id, void *ptr, void *data) {
    struct ovbd_device *lo = ptr;

    ovbd_remove(lo);
    return 0;
}

static void __exit ovbd_exit(void) {
    unsigned long range;

    range = max_ovbd ? max_ovbd << part_shift : 1UL << MINORBITS;

    idr_for_each(&ovbd_index_idr, &ovbd_exit_cb, NULL);
    idr_destroy(&ovbd_index_idr);

    blk_unregister_region(MKDEV(OVBD_MAJOR, 0), range);
    unregister_blkdev(OVBD_MAJOR, "ovbd");

    misc_deregister(&ovbd_misc);
}

module_init(ovbd_init);
module_exit(ovbd_exit);

#ifndef MODULE
static int __init max_ovbd_setup(char *str) {
    max_ovbd = simple_strtol(str, NULL, 0);
    return 1;
}

__setup("max_ovbd=", max_ovbd_setup);
#endif
