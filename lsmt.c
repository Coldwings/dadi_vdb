#include <asm/segment.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "overlay_vbd.h"

#define SECTOR_SIZE 512UL

static uint64_t segment_end(const struct segment_mapping *s) {
    return s->offset + s->length;
}

void forward_offset_to(struct segment_mapping *s, uint64_t x) {
    // pr_info("LSMT: Forward x=%lu, off=%lu\n", x, s->offset);
    uint64_t delta = x - s->offset;
    s->offset = x;
    s->length -= delta;
    s->moffset += s->zeroed ? 0 : delta;
}

void backward_end_to(struct segment_mapping *s, uint64_t x) {
    // if (x <= s->offset) {
    //     printk("%lu > %lu is FALSE", x, s->offset);
    // }

    s->length = x - s->offset;
}

static void trim_edge(struct segment_mapping *pm, size_t m,
                      const struct segment_mapping *s) {
    if (m == 0) return;
    if (pm[0].offset < s->offset) forward_offset_to(&pm[0], s->offset);

    // back may be pm[0], when m == 1
    struct segment_mapping *back = &pm[m - 1];
    if (segment_end(back) > segment_end(s))
        backward_end_to(back, segment_end(s));
}

const struct segment_mapping *ro_index_lower_bound(
    const struct lsmt_ro_index *index, uint64_t offset) {
    const struct segment_mapping *l = index->pbegin;
    const struct segment_mapping *r = index->pend - 1;
    int ret = -1;
    while (l <= r) {
        int m = ((l - index->pbegin) + (r - index->pbegin)) >> 1;
        const struct segment_mapping *cmp = index->pbegin + m;
        if (offset >= segment_end(cmp)) {
            ret = m;
            l = index->pbegin + (m + 1);
        } else {
            r = index->pbegin + (m - 1);
        }
    }
    const struct segment_mapping *pret = index->pbegin + (ret + 1);
    if (pret >= index->pend) {
        return index->pend;
    } else {
        return pret;
    }
}

int ro_index_lookup(const struct lsmt_ro_index *index,
                    const struct segment_mapping *query_segment,
                    struct segment_mapping *ret_mappings, size_t n) {
    if (query_segment->length == 0) return 0;
    const struct segment_mapping *lb =
        ro_index_lower_bound(index, query_segment->offset);
    int cnt = 0;
    const struct segment_mapping *it = lb;
    for (; it != index->pend; it++) {
        if (it->offset >= segment_end(query_segment)) break;
        ret_mappings[cnt++] = *it;
        if (cnt == n) break;
    }
    if (cnt == 0) return 0;
    trim_edge(ret_mappings, cnt, query_segment);
    return cnt;
}

size_t ro_index_size(const struct lsmt_ro_index *index) {
    return index->pend - index->pbegin;
}

struct lsmt_file *lsmt_open(struct zfile *fp) {
    unsigned int ret, i;
    struct lsmt_ro_index *pi = NULL;
    struct segment_mapping *p = NULL;
    struct segment_mapping *it = NULL;
    loff_t pos = 0;
    struct lsmt_file *lf = NULL;

    if (!fp) {
        pr_info("LSMT: failed to open zfile\n");
        return NULL;
    }

    lf = kzalloc(sizeof(struct lsmt_file), GFP_KERNEL);
    lf->fp = fp;

    pr_info("LSMT: read header\n");
    ret = zfile_read(fp, &lf->ht, sizeof(struct lsmt_ht), 0);

    if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
        printk("failed to load header \n");
        return NULL;
    }

    size_t file_size = zfile_len(fp);
    loff_t tailer_offset = file_size - HT_SPACE;
    pr_info("LSMT: read tailer\n");
    ret = zfile_read(fp, &lf->ht, sizeof(struct lsmt_ht), tailer_offset);
    if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
        printk("failed to load tailer \n");
        return NULL;
    }
    pr_info("LSMT: index off: %ld cnt: %ld\n", lf->ht.index_offset,
            lf->ht.index_size);

    ssize_t index_bytes = lf->ht.index_size * sizeof(struct segment_mapping);
    pr_info("LSMT: off: %ld, bytes: %ld\n", lf->ht.index_offset, index_bytes);
    if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024)
        return NULL;
    p = vmalloc(index_bytes);
    pr_info("LSMT: loadindex off: %ld cnt: %ld into %lx\n", lf->ht.index_offset,
            index_bytes, p);
    ret = zfile_read(fp, p, index_bytes, lf->ht.index_offset);
    pr_info("LSMT: load index into mem %lx ret=%ld\n", p, ret);
    if (ret < index_bytes) {
        printk("failed to read index\n");
        vfree(p);
        return NULL;
    }
    uint64_t cnt = 0;
    uint64_t idx = 0;
    for (idx = 0; idx < lf->ht.index_size; idx++) {
        if (p[idx].offset != INVALID_OFFSET) {
            // pr_info("LSMT: index[%d] offset=%ld length=%ld moffset=%ld zeroed=%d\n", idx,
            //         p[idx].offset * SECTOR_SIZE, p[idx].length * SECTOR_SIZE,
            //         p[idx].moffset * SECTOR_SIZE, p[idx].zeroed);
            p[cnt] = p[idx];
            p[cnt].tag = 0;
            cnt++;
        }
    }
    lf->ht.index_size = cnt;
    lf->index.mapping = p;
    lf->index.pbegin = p;
    lf->index.pend = p + cnt;
    return lf;
}

void lsmt_close(struct lsmt_file *fp) {
    // TODO: dealloc
    zfile_close(fp->fp);
    vfree(fp->index.mapping);
    kfree(fp);
}

static bool is_aligned(uint64_t val) { return 0 == (val & 0x1FFUL); }

ssize_t lsmt_read(struct lsmt_file *fp, void *buf, size_t count,
                  loff_t offset) {
    // TODO: read from underlay
    ssize_t ret = 0;
    size_t i = 0;
    if (!is_aligned(offset | count)) {
        pr_info("LSMT: %ld %lu not aligned\n", offset, count);
        return -EINVAL;
    }
    if (offset > fp->ht.virtual_size) {
        pr_info("LSMT: %ld over tail\n", offset);
        return 0;
    }
    if (offset + count > fp->ht.virtual_size) {
        pr_info("LSMT: %ld %lu over tail\n", offset, count);
        count = fp->ht.virtual_size - offset;
    }
    pr_info("LSMT: read %ld %ld\n", offset, count);
    struct segment_mapping *m = kmalloc(16 * sizeof(struct segment_mapping), GFP_KERNEL);
    struct segment_mapping s;
    s.offset = offset / SECTOR_SIZE;
    s.length = count / SECTOR_SIZE;
    while (true) {
        int n = ro_index_lookup(&fp->index, &s, m, 16);
        for (i = 0; i < n; ++i) {
            if (s.offset < m[i].offset) {
                // hole
                pr_info("LSMT: %d set %ld, %lu to 0\n", i, offset,
                        (m[i].offset - s.offset) * SECTOR_SIZE);
                memset(buf, 0, (m->offset - s.offset) * SECTOR_SIZE);
                offset += (m[i].offset - s.offset) * SECTOR_SIZE;
                buf += (m[i].offset - s.offset) * SECTOR_SIZE;
                ret += (m[i].offset - s.offset) * SECTOR_SIZE;
            }
            // zeroe block
            if (m[i].zeroed) {
                pr_info("LSMT: %d set %ld, %lu to 0\n", i, offset,
                        m[i].length * SECTOR_SIZE);
                memset(buf, 0, m->length * SECTOR_SIZE);
                offset += m[i].length * SECTOR_SIZE;
                buf += m[i].length * SECTOR_SIZE;
                ret += m[i].length * SECTOR_SIZE;
            } else {
                pr_info("LSMT: %d decompress copy %ld, %lu, moffset=%ld\n", i,
                        offset, m[i].length * SECTOR_SIZE,
                        m[i].moffset * SECTOR_SIZE);
                ssize_t dc = zfile_read(fp->fp, buf, m->length * SECTOR_SIZE,
                                        m->moffset * SECTOR_SIZE);
                if (dc <= 0) {
                    pr_info("LSMT: read failed ret=%ld\n", dc);
                    goto out;
                }
                // pr_info("LSMT: zfile read %ld bytes\n", dc);
                offset += m[i].length * SECTOR_SIZE;
                buf += m[i].length * SECTOR_SIZE;
                ret += m[i].length * SECTOR_SIZE;
            }
            forward_offset_to(&s, segment_end(&(m[i])));
        }
        if (n < 16) break;
    }
    if (s.length > 0) {
        // pr_info("LSMT: set %ld, %lu to 0\n", offset, s.length * SECTOR_SIZE);
        memset(buf, 0, s.length * SECTOR_SIZE);
        offset += s.length * SECTOR_SIZE;
        ret += s.length * SECTOR_SIZE;
        buf += s.length * SECTOR_SIZE;
    }
out:
    kfree(m);
    return ret;
}

size_t lsmt_len(struct lsmt_file *fp) { return fp->ht.virtual_size; }