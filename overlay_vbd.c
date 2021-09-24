// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>

#include <linux/uaccess.h>
#include "overlay_vbd.h"

#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)
#define OVBD_MAJOR  		231
#define OVBD_CACHE_SIZE         536870912000    

/*
 * Process a single bvec of a bio.
 */
static int ovbd_do_bvec(struct ovbd_device *ovbd, struct page *page,
			unsigned int len, unsigned int off, unsigned int op,
			sector_t sector)
{
	void *mem;
	int err = 0;
	ssize_t ret = 0;
	loff_t loff = 0;

	if (op_is_write(op)) {
		err = -ENOTSUPP;
		goto out;
	}
    mem = kmap_atomic(page);
	// 不从page缓存加载，替换了copy_from_ovbd
	// copy_from_ovbd(mem + off, ovbd, sector, len);
	loff = sector << SECTOR_SHIFT;
	// pr_info("vbd: dobvec loff=%ld sector=%lu off=%d len=%lu ret=%ld op=%x\n", loff, sector, off, len, ret, ovbd->fp, op);
	// loff指文件上（block上的逻辑的）offset
	// 必定对齐PAGS_SIZE，一次读取一个PAGE
	ret = lsmt_read(ovbd->fp, mem + off, len, loff);
	// pr_info("vbd: dobvec ret\n", ret);
	flush_dcache_page(page);
	kunmap_atomic(mem);

out:
	return err;
}

static blk_qc_t ovbd_make_request(struct request_queue *q, struct bio *bio)
{
	struct ovbd_device *ovbd = bio->bi_disk->private_data;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		goto io_error;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		/* Don't support un-aligned buffer */
		WARN_ON_ONCE((bvec.bv_offset & (SECTOR_SIZE - 1)) ||
				(bvec.bv_len & (SECTOR_SIZE - 1)));
		// pr_info("vbd: make request\n");
		err = ovbd_do_bvec(ovbd, bvec.bv_page, bvec.bv_len, bvec.bv_offset,
				  bio_op(bio), sector);
		if (err)
			goto io_error;
		sector += bvec.bv_len >> SECTOR_SHIFT;
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int ovbd_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, unsigned int op)
{
	struct ovbd_device *ovbd = bdev->bd_disk->private_data;
	int err;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	pr_info("vbd: rw_page\n");
	err = ovbd_do_bvec(ovbd, page, PAGE_SIZE, 0, op, sector);
	page_endio(page, op_is_write(op), err);
	return err;
}

static const struct block_device_operations ovbd_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		ovbd_rw_page,
};

/*
 * And now the modules code and kernel interface.
 */
static int rd_nr = CONFIG_BLK_DEV_RAM_COUNT;
module_param(rd_nr, int, 0444);
MODULE_PARM_DESC(rd_nr, "Maximum number of ovbd devices");

unsigned long rd_size = CONFIG_BLK_DEV_RAM_SIZE;
module_param(rd_size, ulong, 0444);
MODULE_PARM_DESC(rd_size, "Size of each RAM disk in kbytes.");

static int max_part = 1;
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Num Minors to reserve between devices");

static char *backfile = "/test.c";
module_param(backfile,charp,0660);
MODULE_PARM_DESC(backfile, "Back file for lsmtz");

MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(OVBD_MAJOR);
MODULE_ALIAS("rd");

/*
 * The device scheme is derived from loop.c. Keep them in synch where possible
 * (should share code eventually).
 */
static LIST_HEAD(ovbd_devices);
static DEFINE_MUTEX(ovbd_devices_mutex);

// 直接拿file对象来处理了
//比较偷懒的做法
static struct ovbd_device *ovbd_alloc(int i)
{
	struct ovbd_device *ovbd;
	struct gendisk *disk;

	ovbd = kzalloc(sizeof(*ovbd), GFP_KERNEL);
	if (!ovbd)
		goto out;
	ovbd->ovbd_number		= i;
	// spin_lock_init(&ovbd->ovbd_lock);
	// INIT_RADIX_TREE(&ovbd->ovbd_pages, GFP_ATOMIC);

	ovbd->ovbd_queue = blk_alloc_queue(ovbd_make_request, NUMA_NO_NODE);
	if (!ovbd->ovbd_queue)
		goto out_free_dev;

	/* This is so fdisk will align partitions on 4k, because of
	 * direct_access API needing 4k alignment, returning a PFN
	 * (This is only a problem on very small devices <= 4M,
	 *  otherwise fdisk will align on 1M. Regardless this call
	 *  is harmless)
	 */
	blk_queue_physical_block_size(ovbd->ovbd_queue, PAGE_SIZE);
	disk = ovbd->ovbd_disk = alloc_disk(max_part);
	if (!disk)
		goto out_free_queue;
	disk->major		= OVBD_MAJOR;
	disk->first_minor	= i * max_part;
	disk->fops		= &ovbd_fops;
	disk->private_data	= ovbd;
	disk->flags		= GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	sprintf(disk->disk_name, "vbd%d", i);
	pr_info("vbd: disk->disk_name %s\n", disk->disk_name);
	set_disk_ro(disk, true);
	ovbd->fp = 	lsmt_open(zfile_open(backfile));
	if (!ovbd->fp) {
		pr_info("Cannot load lsmtfile\n");
		goto out_free_queue;
	}
	// 此处为loop形式，文件长度即blockdev的大小
	// 如果是LSMTFile，则应以LSMTFile头记录的长度为准
	size_t flen = lsmt_len(ovbd->fp);
	ovbd->block_size = flen >> SECTOR_SHIFT;
	set_capacity(disk, flen >> SECTOR_SHIFT);
	ovbd->ovbd_queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, ovbd->ovbd_queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, ovbd->ovbd_queue);

	return ovbd;

out_free_queue:
	blk_cleanup_queue(ovbd->ovbd_queue);
out_free_dev:
	kfree(ovbd);
out:
	return NULL;
}

static void ovbd_free(struct ovbd_device *ovbd)
{
	put_disk(ovbd->ovbd_disk);
	blk_cleanup_queue(ovbd->ovbd_queue);
	if (ovbd->fp)
		lsmt_close(ovbd->fp);
	kfree(ovbd);
}

static struct ovbd_device *ovbd_init_one(int i, bool *new)
{
	struct ovbd_device *ovbd;

	*new = false;
	list_for_each_entry(ovbd, &ovbd_devices, ovbd_list) {
		if (ovbd->ovbd_number == i)
			goto out;
	}

	ovbd = ovbd_alloc(i);
	if (ovbd) {
		ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
		pr_info("add_disk\n");
		add_disk(ovbd->ovbd_disk);
		list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	}
	*new = true;
out:
	return ovbd;
}

static void ovbd_del_one(struct ovbd_device *ovbd)
{
	list_del(&ovbd->ovbd_list);
	del_gendisk(ovbd->ovbd_disk);
	ovbd_free(ovbd);
}

static struct kobject *ovbd_probe(dev_t dev, int *part, void *data)
{
	struct ovbd_device *ovbd;
	struct kobject *kobj;
	bool new;

	mutex_lock(&ovbd_devices_mutex);
	printk("ovbd_probe");
	ovbd = ovbd_init_one(MINOR(dev) / max_part, &new);
	kobj = ovbd ? get_disk_and_module(ovbd->ovbd_disk) : NULL;
	mutex_unlock(&ovbd_devices_mutex);

	if (new)
		*part = 0;

	return kobj;
}

static inline void ovbd_check_and_reset_par(void)
{
	if (unlikely(!max_part))
		max_part = 1;

	/*
	 * make sure 'max_part' can be divided exactly by (1U << MINORBITS),
	 * otherwise, it is possiable to get same dev_t when adding partitions.
	 */
	if ((1U << MINORBITS) % max_part != 0)
		max_part = 1UL << fls(max_part);

	if (max_part > DISK_MAX_PARTS) {
		pr_info("ovbd: max_part can't be larger than %d, reset max_part = %d.\n",
			DISK_MAX_PARTS, DISK_MAX_PARTS);
		max_part = DISK_MAX_PARTS;
	}
}

static int __init ovbd_init(void)
{
	struct ovbd_device *ovbd, *next;
	int i;

	pr_info("vbd: INIT\n");

	// struct lsmt_file *fp = NULL;
	// pr_info("vbd: before open file\n");
	// fp = lsmt_open(zfile_open(backfile));
	// if (!fp) {
	// 	pr_info("Cannot load lsmtfile\n");
	// 	return -EIO;
	// }
	// char buffer[4096];
	// loff_t off;
	// size_t cnt;
	// size_t flen = lsmt_len(fp);
	// struct file* fout = file_open("/root/dadi_vdb/output", O_RDWR | O_CREAT | O_TRUNC, 0644);
	// for (off = 0; off<flen; off += 4096) {
	// 	cnt = flen - off > 4096 ? 4096 : flen - off;
	// 	lsmt_read(fp, buffer, cnt, off);
	// 	loff_t woff = off;
	// 	kernel_write(fout, buffer, cnt, &woff);
	// }
	// file_close(fout);

	// pr_info("vbd: after open file fp = %lx\n", fp);
	// lsmt_close(fp);
	// pr_info("vbd: after close file fp = %lx\n", fp);

	// return 0;

	if (register_blkdev(OVBD_MAJOR, "ovbd"))
		return -EIO;

	ovbd_check_and_reset_par();
	
	// 先打开文件再创建设备
	pr_info("alloc");
	for (i = 0; i < 1; i++) {
		ovbd = ovbd_alloc(i);
		if (!ovbd)
			goto out_free;
		list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	}

	/* point of no return */

	list_for_each_entry(ovbd, &ovbd_devices, ovbd_list) {
		/*
		 * associate with queue just before adding disk for
		 * avoiding to mess up failure path
		 */
		pr_info("vbd: get filesize %d\n", ovbd->block_size);
		ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
		pr_info("add_disk\n");
		add_disk(ovbd->ovbd_disk);
	}
	pr_info("Register blk\n");
	blk_register_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS,
				  THIS_MODULE, ovbd_probe, NULL, NULL);

	pr_info("ovbd: module loaded\n");
	
	struct ovbd_device* backed_ovbd = list_first_entry_or_null(&ovbd->ovbd_list, struct ovbd_device, ovbd_list);

	return 0;

out_free:
	list_for_each_entry_safe(ovbd, next, &ovbd_devices, ovbd_list) {
		list_del(&ovbd->ovbd_list);
		ovbd_free(ovbd);
	}
	unregister_blkdev(OVBD_MAJOR, "ovbd");
	pr_info("ovbd: module NOT loaded !!!\n");
	return -ENOMEM;
}

static void __exit ovbd_exit(void)
{
	struct ovbd_device *ovbd, *next;

	list_for_each_entry_safe(ovbd, next, &ovbd_devices, ovbd_list) {
		ovbd_del_one(ovbd);
	}

	blk_unregister_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS);
	unregister_blkdev(OVBD_MAJOR, "ovbd");

	pr_info("ovbd: module unloaded\n");
}

module_init(ovbd_init);
module_exit(ovbd_exit);

