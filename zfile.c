#include <asm/segment.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/errno.h>
#include <linux/lz4.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

#include "zfile.h"

static const uint32_t ZF_SPACE = 512;
static uint64_t *MAGIC0 = (uint64_t *)"ZFile\0\1";
static const uuid_t MAGIC1 = UUID_INIT(0x74756a69, 0x2e79, 0x7966, 0x40, 0x41,
                                       0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);
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

static size_t file_len(struct file *file) {
    return file ? file->f_inode->i_size : 0;
}

static ssize_t file_read(struct file *file, void *buf, size_t count,
                         loff_t pos) {
    ssize_t ret, sret = 0;
    // struct kvec iov;
    // struct iov_iter iter;
    loff_t lpos;
    size_t flen = file_len(file);
    // pr_info("zfile: Trying to read underlay file %ld %lu\n", pos, count);
    if (pos > flen) return 0;
    if (pos + count > flen) count = flen - pos;
    // pr_info("zfile: underlay file read off=%ld count=%lu\n", pos, count);
    while (count > 0) {
        lpos = pos;
        // pr_info("zfile: read underlay file at %ld count=%lu\n", lpos,
        //         count);
        ret = kernel_read(file, buf, count, &lpos);
        if (lpos <= pos || ret <= 0) {
            // pr_info(
            //     "zfile: read underlay file at %ld, pos move to %ld, return "
            //     "%ld\n",
            //     pos, lpos, ret);
            return ret;
        }
        count -= (lpos - pos);
        buf += (lpos - pos);
        sret += (lpos - pos);
        pos = lpos;
    }

    return sret;
}

size_t zfile_len(struct zfile *zfile) { return zfile->header.vsize; }

struct path zfile_getpath(struct zfile *zfile) {
    return zfile->fp->f_path;
}

ssize_t zfile_read(struct zfile *zf, void *dst, size_t count, loff_t offset) {
    size_t start_idx, end_idx;
    loff_t begin, range;
    size_t bs;
    ssize_t ret;
    int dc;
    ssize_t i;
    unsigned char *src_buf;
    unsigned char *decomp_buf;
    loff_t decomp_offset;
    unsigned char *c_buf;
    loff_t poff;
    size_t pcnt;

    // pr_info("zfile: read off=%ld cnt=%lu\n", offset, count);
    if (!zf) {
        // pr_info("zfile: failed empty zf\n");
        return -EIO;
    }
    bs = zf->header.opt.block_size;
    // read empty
    if (count == 0) return 0;
    // read from over-tail
    if (offset > zf->header.vsize) {
        // pr_info("zfile: read over tail %ld > %ld\n", offset,
        // zf->header.vsize);
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

    src_buf = kmalloc(range, GFP_KERNEL);
    decomp_buf = kmalloc(4096, GFP_KERNEL);

    // pr_info("zfile: before read file %ld %lu\n", begin, range);
    // read compressed data
    ret = file_read(zf->fp, src_buf, range, begin);
    if (ret != range) {
        pr_info("zfile: Read file failed, %ld != %lld\n", ret, range);
        ret = -EIO;
        goto fail_read;
    }
    // pr_info("zfile: after read file %ld\n", ret);

    c_buf = src_buf;

    // decompress in seq
    decomp_offset = offset - offset % bs;
    ret = 0;
    for (i = start_idx; i <= end_idx; i++) {
        // pr_info("zfile: before decompress %ld [%lu %lu]\n", i, start_idx,
        //         end_idx);
        dc = LZ4_decompress_safe(
            c_buf, decomp_buf,
            zf->jump[i].delta - (zf->header.opt.verify ? sizeof(uint32_t) : 0),
            bs);
        // pr_info("zfile: after decompress %ld\n", dc);
        if (dc <= 0) {
            pr_info("decompress failed\n");
            ret = -EIO;
            goto fail_read;
        }
        poff = offset - decomp_offset;
        pcnt = count > (dc - poff) ? (dc - poff) : count;
        // pr_info(
        //     "zfile: decompress %d block, offset=%ld decomp_offset=%ld cut "
        //     "poff=%ld pcnt=%lu\n",
        //     i, offset, decomp_offset, poff, pcnt);
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
    pr_info("zfile: close\n");
    if (zfile) {
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

struct zfile *zfile_open_by_file(struct file *file) {
    uint32_t *jt_saved;
    size_t jt_size = 0;
    struct zfile *zfile = NULL;
    int ret = 0;
    size_t file_size = 0;
    loff_t tailer_offset;

    if (!is_zfile(file)) return NULL;

    zfile = kzalloc(sizeof(struct zfile), GFP_KERNEL);
    if (!zfile) {
        goto fail_alloc;
    }

    zfile->fp = file;

    // should verify header

    file_size = file_len(zfile->fp);
    tailer_offset = file_size - ZF_SPACE;
    pr_info("zfile: file_size=%lu\n", file_size);
    ret = file_read(zfile->fp, &zfile->header, sizeof(struct zfile_ht),
                    tailer_offset);

    pr_info(
        "zfile: Tailer vsize=%lld index_offset=%lld index_size=%lld "
        "verify=%d\n",
        zfile->header.vsize, zfile->header.index_offset,
        zfile->header.index_size, zfile->header.opt.verify);

    pr_info("zfile: vlen=%lld size=%ld\n", zfile->header.vsize,
            zfile_len(zfile));

    jt_size = ((uint64_t)zfile->header.index_size) * sizeof(uint32_t);
    printk("get index_size %lu, index_offset %llu", jt_size,
           zfile->header.index_offset);

    if (jt_size == 0 || jt_size > 1024UL * 1024 * 1024) {
        goto fail_open;
    }

    jt_saved = vmalloc(jt_size);

    ret = file_read(zfile->fp, jt_saved, jt_size, zfile->header.index_offset);

    build_jump_table(jt_saved, zfile);

    vfree(jt_saved);

    return zfile;

fail_open:
    zfile_close(zfile);
fail_alloc:
    return NULL;
}

struct zfile *zfile_open(const char *path) {
    struct zfile *ret = NULL;
    struct file *file = file_open(path, 0, 644);
    if (!file) {
        pr_info("zfile: Canot open zfile %s\n", path);
        return NULL;
    }
    ret = zfile_open_by_file(file);
    if (!ret) {
        file_close(file);
    }
    return ret;
}

struct file *zfile_getfile(struct zfile *zfile) {
    return zfile->fp;
}

bool is_zfile(struct file *file) {
    struct zfile_ht ht;
    ssize_t ret;

    if (!file) return false;

    ret = file_read(file, &ht, sizeof(struct zfile_ht), 0);

    if (ret < (ssize_t)sizeof(struct zfile_ht)) {
        pr_info("zfile: failed to load header %ld \n", ret);
        return false;
    }

    return ht.magic0 == *MAGIC0 && uuid_equal(&ht.magic1, &MAGIC1);
}