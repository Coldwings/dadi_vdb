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
 * Look up and return a ovbd's page for a given sector.
 */
static struct page *ovbd_lookup_page(struct ovbd_device *ovbd, sector_t sector)
{
	pgoff_t idx;
	struct page *page;

	/*
	 * The page lifetime is protected by the fact that we have opened the
	 * device node -- ovbd pages will never be deleted under us, so we
	 * don't need any further locking or refcounting.
	 *
	 * This is strictly true for the radix-tree nodes as well (ie. we
	 * don't actually need the rcu_read_lock()), however that is not a
	 * documented feature of the radix-tree API so it is better to be
	 * safe here (we don't have total exclusion from radix tree updates
	 * here, only deletes).
	 */
	rcu_read_lock();
	idx = sector >> PAGE_SECTORS_SHIFT; /* sector to page index */
	page = radix_tree_lookup(&ovbd->ovbd_pages, idx);
	rcu_read_unlock();

	BUG_ON(page && page->index != idx);

	return page;
}

/*
 * Look up and return a ovbd's page for a given sector.
 * If one does not exist, allocate an empty page, and insert that. Then
 * return it.
 */
static struct page *ovbd_insert_page(struct ovbd_device *ovbd, sector_t sector)
{
	pgoff_t idx;
	struct page *page;
	gfp_t gfp_flags;

	page = ovbd_lookup_page(ovbd, sector);
	if (page)
		return page;

	/*
	 * Must use NOIO because we don't want to recurse back into the
	 * block or filesystem layers from page reclaim.
	 */
	gfp_flags = GFP_NOIO | __GFP_ZERO | __GFP_HIGHMEM;
	page = alloc_page(gfp_flags);
	if (!page)
		return NULL;

	if (radix_tree_preload(GFP_NOIO)) {
		__free_page(page);
		return NULL;
	}

	spin_lock(&ovbd->ovbd_lock);
	idx = sector >> PAGE_SECTORS_SHIFT;
	page->index = idx;
	if (radix_tree_insert(&ovbd->ovbd_pages, idx, page)) {
		__free_page(page);
		page = radix_tree_lookup(&ovbd->ovbd_pages, idx);
		BUG_ON(!page);
		BUG_ON(page->index != idx);
	}
	spin_unlock(&ovbd->ovbd_lock);

	radix_tree_preload_end();

	return page;
}

/*
 * Free all backing store pages and radix tree. This must only be called when
 * there are no other users of the device.
 */
#define FREE_BATCH 16
static void ovbd_free_pages(struct ovbd_device *ovbd)
{
	unsigned long pos = 0;
	struct page *pages[FREE_BATCH];
	int nr_pages;

	do {
		int i;

		nr_pages = radix_tree_gang_lookup(&ovbd->ovbd_pages,
				(void **)pages, pos, FREE_BATCH);

		for (i = 0; i < nr_pages; i++) {
			void *ret;

			BUG_ON(pages[i]->index < pos);
			pos = pages[i]->index;
			ret = radix_tree_delete(&ovbd->ovbd_pages, pos);
			BUG_ON(!ret || ret != pages[i]);
			__free_page(pages[i]);
		}

		pos++;

		/*
		 * It takes 3.4 seconds to remove 80GiB ovbd.
		 * So, we need cond_resched to avoid stalling the CPU.
		 */
		cond_resched();

		/*
		 * This assumes radix_tree_gang_lookup always returns as
		 * many pages as possible. If the radix-tree code changes,
		 * so will this have to.
		 */
	} while (nr_pages == FREE_BATCH);
}

/*
 * copy_to_ovbd_setup must be called before copy_to_ovbd. It may sleep.
 */
static int ovbd_prepare_page(struct ovbd_device *ovbd, sector_t sector, size_t n)
{
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	printk("prepare_page, sector %d , size %d", sector, n);
	if (!ovbd_insert_page(ovbd, sector))
		return -ENOSPC;
	if (copy < n) {
		sector += copy >> SECTOR_SHIFT;
		if (!ovbd_insert_page(ovbd, sector))
			return -ENOSPC;
	}
	return 0;
}

static bool ovbd_fill_page(struct ovbd_device *ovbd, sector_t sector, size_t n) {

	struct page *page;
	void *dst;
	loff_t len;
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	if (!ovbd->initialized ) {
		printk("zfile not ready yet");
		return false;
	}
	printk("we will try offset at %d, sector %d, size %d", offset, sector, n);

	page = ovbd_lookup_page(ovbd, sector);
	BUG_ON(!page);

	dst = kmap_atomic(page);
	decompress_to(ovbd, dst, offset, n, &len);
	BUG_ON(len < 0);
	kunmap_atomic(dst);
/*
	if ( < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = brd_lookup_page(brd, sector);
		BUG_ON(!page);

		dst = kmap_atomic(page);
		memcpy(dst, src, copy);
		kunmap_atomic(dst);
	} */
	return true;
}

/*
 * Copy n bytes to dst from the ovbd starting at sector. Does not sleep.
 */
static void copy_from_ovbd(void *dst, struct ovbd_device *ovbd,
			sector_t sector, size_t n)
{
	struct page *page;
	void *src;
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = ovbd_lookup_page(ovbd, sector);
	if (page) {
		src = kmap_atomic(page);
		memcpy(dst, src + offset, copy);
		kunmap_atomic(src);
	} else {
		ovbd_prepare_page(ovbd, sector, n);
		ovbd_fill_page(ovbd, sector, n);
	}

	if (copy < n) {
		dst += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = ovbd_lookup_page(ovbd, sector);
		if (page) {
			src = kmap_atomic(page);
			memcpy(dst, src, copy);
			kunmap_atomic(src);
		} else {
			ovbd_prepare_page(ovbd, sector, n);
			ovbd_fill_page(ovbd, sector, n);
		}
	} 
}

static struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    int err = 0;

    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;

}

static void file_close(struct file *file)
{
    filp_close(file, NULL);
}

static size_t file_read(struct file *file, void *buf, size_t count, loff_t *pos)  
{
    unsigned int ret = kernel_read(file, buf, count, pos);
    // if (!ret) {
    //    pr_info("reading data failed at %d", pos);
    // }
    return ret;
}  

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
	loff_t loff = sector;

	if (op_is_write(op)) {
		err = -ENOTSUPP;
		goto out;
	}
    mem = kmap_atomic(page);
	// 不从page缓存加载，替换了copy_from_ovbd
	// copy_from_ovbd(mem + off, ovbd, sector, len);
	loff = loff << SECTOR_SHIFT;
	loff = loff & ~((loff_t)PAGE_SIZE - (loff_t)1);
	// loff指文件上（block上的逻辑的）offset
	// 必定对齐PAGS_SIZE，一次读取一个PAGE
	ret = kernel_read(ovbd->compressed_fp, mem, PAGE_SIZE, &loff);
	pr_info("vbd: dobvec %ld %lu %d %lu %ld %lx %x\n", loff, sector, off, len, ret, ovbd->compressed_fp, op);
	if (ret < 0) {
		kunmap_atomic(mem);
		err = -EIO;
		goto out;
	}
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
		unsigned int len = bvec.bv_len;
		int err;

		/* Don't support un-aligned buffer */
		WARN_ON_ONCE((bvec.bv_offset & (SECTOR_SIZE - 1)) ||
				(len & (SECTOR_SIZE - 1)));

		err = ovbd_do_bvec(ovbd, bvec.bv_page, len, bvec.bv_offset,
				  bio_op(bio), sector);
		if (err)
			goto io_error;
		sector += len >> SECTOR_SHIFT;
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
static struct ovbd_device *ovbd_alloc(int i, struct file* fp)
{
	struct ovbd_device *ovbd;
	struct gendisk *disk;

	ovbd = kzalloc(sizeof(*ovbd), GFP_KERNEL);
	if (!ovbd)
		goto out;
	ovbd->ovbd_number		= i;
	spin_lock_init(&ovbd->ovbd_lock);
	INIT_RADIX_TREE(&ovbd->ovbd_pages, GFP_ATOMIC);

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
	disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(disk->disk_name, "vbd%d", i);
	pr_info("vbd: disk->disk_name %s\n", disk->disk_name);
	ovbd->compressed_fp = fp;
	// 此处为loop形式，文件长度即blockdev的大小
	// 如果是LSMTFile，则应以LSMTFile头记录的长度为准
	ovbd->block_size = fp->f_inode->i_size >> SECTOR_SHIFT;
	ovbd->initialized = true;
	pr_info("bs=%d fs=%d\n", ovbd->block_size, fp->f_inode->i_size);
	set_capacity(disk, fp->f_inode->i_size >> SECTOR_SHIFT);
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
	if (ovbd->compressed_fp)
		file_close(ovbd->compressed_fp);
	ovbd_free_pages(ovbd);
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

	// ovbd = ovbd_alloc(i);
	// if (ovbd) {
	// 	ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
	// 	pr_info("add_disk\n");
	// 	add_disk(ovbd->ovbd_disk);
	//         // open_zfile(ovbd, backfile, true);
	// 	ovbd->initialized = true;	
	// 	list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	// }
	// *new = true;
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

	pr_info("INIT\n");

	if (register_blkdev(OVBD_MAJOR, "ovbd"))
		return -EIO;

	ovbd_check_and_reset_par();

	pr_info("vbd: before open file\n");
	struct file* fp = file_open( backfile, 0, 644);
	if (!fp) {
		pr_info("Canot open zfile\n");
		return -ENOENT;
	}
	pr_info("vbd: after open file\n");

	// 先打开文件再创建设备
	pr_info("alloc");
	for (i = 0; i < 1; i++) {
		ovbd = ovbd_alloc(i, fp);
		if (!ovbd)
			goto out_free;
		ovbd->block_size = fp->f_inode->i_size / SECTOR_SIZE;
		pr_info("vbd: get filesize %d\n", ovbd->block_size);
		ovbd->compressed_fp = fp;
		pr_info("vbd: set fp\n");
		list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	}

	/* point of no return */

	list_for_each_entry(ovbd, &ovbd_devices, ovbd_list) {
		/*
		 * associate with queue just before adding disk for
		 * avoiding to mess up failure path
		 */
		ovbd->block_size = fp->f_inode->i_size / SECTOR_SIZE;
		pr_info("vbd: get filesize %d\n", ovbd->block_size);
		ovbd->compressed_fp = fp;
		pr_info("vbd: set fp\n");
		ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
		ovbd->initialized = true;
		pr_info("add_disk\n");
		add_disk(ovbd->ovbd_disk);
	}
	pr_info("Register blk\n");
	blk_register_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS,
				  THIS_MODULE, ovbd_probe, NULL, NULL);

	pr_info("ovbd: module loaded\n");
	
	struct ovbd_device* backed_ovbd = list_first_entry_or_null(&ovbd->ovbd_list, struct ovbd_device, ovbd_list);
	// open_zfile(backed_ovbd, backfile, true);

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

	list_for_each_entry_safe(ovbd, next, &ovbd_devices, ovbd_list)
		ovbd_del_one(ovbd);

	blk_unregister_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS);
	unregister_blkdev(OVBD_MAJOR, "ovbd");

	pr_info("ovbd: module unloaded\n");
}

module_init(ovbd_init);
module_exit(ovbd_exit);

