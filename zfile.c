#include <asm/segment.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/lz4.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "overlay_vbd.h"

static struct file *file_open(const char *path, int flags, int rights) {
    struct file *fp = NULL;
    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        printk("Cannot open the file %ld\n", PTR_ERR(fp));
        return NULL;
    }
    printk("Opened the file %s", path);
    return fp;
}

static void file_close(struct file *file) { filp_close(file, NULL); }

static size_t file_read(struct file *file, void *buf, size_t count,
                        loff_t pos) {
    unsigned int ret = kernel_read(file, buf, count, &pos);
    if (!ret) {
        printk("reading data failed at %d", pos);
    }
    return ret;
}

static size_t file_len(struct file *file) {
    return file ? file->f_inode->i_size : 0;
}

// static void __user *file_mmap(struct file *file, loff_t offset, size_t size)
// {
//     mm_segment_t old_fs = get_fs();
//     set_fs(KERNEL_DS);
//     void __user *ret =
//         (void __user *)vm_mmap(file, offset, size, PROT_READ, MAP_PRIVATE,
//         0);
//     set_fs(old_fs);
//     return ret;
// }

// static void file_munmap(void *space, size_t size) {
//     mm_segment_t old_fs = get_fs();
//     set_fs(KERNEL_DS);
//     vm_munmap(space, size);
//     set_fs(old_fs);
// }

size_t zfile_len(struct zfile *zfile) { return zfile->header.vsize; }

ssize_t zfile_read(struct zfile *zf, void *dst, size_t count, loff_t offset) {
    size_t start_idx, end_idx;
    loff_t begin, range, filloff;
    size_t bs;
    ssize_t ret;
    int dc, i;
    pr_info("zfile: read off=%ld cnt=%lu\n", offset, count);
    if (!zf) return -EIO;
    bs = zf->header.opt.block_size;
    // read empty
    if (count == 0) return 0;
    // read from over-tail
    if (offset > zf->header.vsize) {
        pr_info("zfile: read over tail %ld > %ld\n", offset, zf->header.vsize);
        return 0;
    }
    // read till tail
    if (offset + count > zf->header.vsize) {
        count = zf->header.vsize - offset;
    }
    start_idx = offset / bs;
    end_idx = (offset + count - 1) / bs;

    begin = zf->jump[start_idx].partial_offset;
    range = zf->jump[end_idx].partial_offset + zf->jump[end_idx].delta - begin;

    unsigned char *src_buf;
    src_buf = kmalloc(range, GFP_KERNEL);
    unsigned char *decomp_buf;
    decomp_buf = kmalloc(4096, GFP_KERNEL);

    // read compressed data
    ret = file_read(zf->fp, src_buf, range, begin);
    if (ret != range) {
        pr_info("zfile: Read file failed, %d != %d\n", ret, range);
        ret = -EIO;
        goto fail_read;
    }

    unsigned char *c_buf = src_buf;

    // decompress in seq
    loff_t decomp_offset = offset - offset % bs;
    ret = 0;
    for (i = start_idx; i <= end_idx; i++) {
        dc = LZ4_decompress_safe(
            c_buf, decomp_buf,
            zf->jump[i].delta - (zf->header.opt.verify ? sizeof(uint32_t) : 0),
            bs);
        if (dc < bs && decomp_offset + dc < zf->header.vsize) {
            pr_info("Failed to read\n");
            goto fail_read;
        }
        loff_t poff = offset - decomp_offset;
        size_t pcnt = count > (dc - poff) ? (dc - poff) : count;
        pr_info(
            "zfile: decompress %d block, offset=%ld decomp_offset=%ld cut "
            "poff=%ld pcnt=%lu\n",
            i, offset, decomp_offset, poff, pcnt);
        memcpy(dst, decomp_buf + poff, pcnt);
        decomp_offset += dc;
        dst += pcnt;
        ret += pcnt;
        count -= pcnt;
        offset = decomp_offset;
        c_buf += zf->jump[i].delta;
    }

fail_read:
    kfree(decomp_buf);
    kfree(src_buf);

    return ret;
}

void build_jump_table(uint32_t *jt_saved, struct zfile *zf) {
    size_t i;
    zf->jump = vmalloc((zf->header.index_size + 2) * sizeof(struct jump_table));
    zf->jump[0].partial_offset = ZF_SPACE;
    for (i = 0; i < zf->header.index_size; i++) {
        zf->jump[i].delta = jt_saved[i];
        zf->jump[i + 1].partial_offset =
            zf->jump[i].partial_offset + jt_saved[i];
    }
}

void zfile_close(struct zfile *zfile) {
    pr_info("zfile: close %lx\n", zfile);
    if (zfile) {
        if (zfile->map) {
            file_munmap(zfile->map, file_len(zfile->fp));
        }
        if (zfile->jump) {
            vfree(zfile->jump);
            zfile->jump = NULL;
        }
        if (zfile->fp) {
            file_close(zfile->fp);
            zfile->fp = NULL;
        }
        kfree(zfile);
    }
}

struct zfile *zfile_open(const char *path) {
    unsigned int i;
    uint32_t *jt_saved;
    size_t jt_size = 0;
    struct zfile *zfile = NULL;
    loff_t pos = 0;
    int ret = 0;

    zfile = kzalloc(sizeof(struct zfile), GFP_KERNEL);
    if (!zfile) {
        goto fail_alloc;
    }

    zfile->fp = file_open(path, 0, 644);
    if (!zfile->fp) {
        printk("Canot open zfile %s\n", path);
        goto fail_open;
    }

    // zfile->map = file_mmap(zfile->fp, 0, file_len(zfile->fp));

    ret = file_read(zfile->fp, &zfile->header, sizeof(struct zfile_ht), 0);

    if (ret < (ssize_t)sizeof(struct zfile_ht)) {
        printk("failed to load header %d \n", ret);
        goto fail_open;
    }
    // pr_info("before copy header");
    // memcpy(&zfile->header, zfile->map, sizeof(struct zfile_ht));
    // pr_info("after copy header");

    // should verify header

    size_t file_size = file_len(zfile->fp);
    loff_t tailer_offset = file_size - ZF_SPACE;
    ret = file_read(zfile->fp, &zfile->header, sizeof(struct zfile_ht),
                    tailer_offset);
    // pr_info("before copy tailer");
    // memcpy(&zfile->header, zfile->map + tailer_offset,
    //         sizeof(struct zfile_ht));
    // pr_info("after copy tailer");

    pr_info("Header vsize=%ld index_offset=%ld index_size=%ld verify=%d\n",
            zfile->header.vsize, zfile->header.index_offset,
            zfile->header.index_size, zfile->header.opt.verify);

    pr_info("zfile: vlen=%ld size=%ld\n", zfile->header.vsize,
            zfile_len(zfile));

    jt_size = ((uint64_t)zfile->header.index_size) * sizeof(uint32_t);
    printk("get index_size %d, index_offset %d", jt_size,
           zfile->header.index_offset);

    jt_saved = vmalloc(jt_size);
    // jt_saved = zfile->map + zfile->header.index_offset;

    ret = file_read(zfile->fp, jt_saved, jt_size, zfile->header.index_offset);

    build_jump_table(jt_saved, zfile);

    vfree(jt_saved);

    return zfile;

fail_open:
    zfile_close(zfile);
fail_alloc:
    return NULL;
}
