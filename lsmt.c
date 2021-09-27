#include <asm/segment.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "lsmt.h"
#include "zfile.h"

static const uint64_t INVALID_OFFSET = (1UL << 50) - 1;
static const uint32_t HT_SPACE = 4096;
static uint64_t *MAGIC0 = (uint64_t *)"LSMT\0\1\2";
static const uuid_t MAGIC1 = UUID_INIT(0x657e63d2, 0x9444, 0x084c, 0xa2, 0xd2,
                                       0xc8, 0xec, 0x4f, 0xcf, 0xae, 0x8a);

static uint64_t segment_end(const struct segment_mapping *s) {
    return s->offset + s->length;
}

void forward_offset_to(struct segment_mapping *s, uint64_t x) {
    uint64_t delta = x - s->offset;
    s->offset = x;
    s->length -= delta;
    s->moffset += s->zeroed ? 0 : delta;
}

void backward_end_to(struct segment_mapping *s, uint64_t x) {
    s->length = x - s->offset;
}

static void trim_edge(struct segment_mapping *pm, size_t m,
                      const struct segment_mapping *s) {
    struct segment_mapping *back;
    if (m == 0) return;
    if (pm[0].offset < s->offset) forward_offset_to(&pm[0], s->offset);

    // back may be pm[0], when m == 1
    back = &pm[m - 1];
    if (segment_end(back) > segment_end(s))
        backward_end_to(back, segment_end(s));
}

const struct segment_mapping *ro_index_lower_bound(
    const struct lsmt_ro_index *index, uint64_t offset) {
    const struct segment_mapping *l = index->pbegin;
    const struct segment_mapping *r = index->pend - 1;
    const struct segment_mapping *pret;
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
    pret = index->pbegin + (ret + 1);
    if (pret >= index->pend) {
        return index->pend;
    } else {
        return pret;
    }
}

int ro_index_lookup(const struct lsmt_ro_index *index,
                    const struct segment_mapping *query_segment,
                    struct segment_mapping *ret_mappings, size_t n) {
    int cnt = 0;
    const struct segment_mapping *lb;
    const struct segment_mapping *it;

    if (query_segment->length == 0) return 0;
    lb = ro_index_lower_bound(index, query_segment->offset);
    for (it = lb; it != index->pend; it++) {
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
    unsigned int ret;
    struct segment_mapping *p = NULL;
    struct lsmt_file *lf = NULL;
    uint64_t cnt = 0;
    uint64_t idx = 0;
    size_t file_size = 0;
    loff_t tailer_offset;
    ssize_t index_bytes;

    if (!fp) {
        pr_info("LSMT: failed to open zfile\n");
        return NULL;
    }

    if (!is_lsmtfile(fp)) {
        pr_info("LSMT: fp is not a lsmtfile\n");
        return NULL;
    }

    lf = kzalloc(sizeof(struct lsmt_file), GFP_KERNEL);
    lf->fp = fp;

    file_size = zfile_len(fp);
    tailer_offset = file_size - HT_SPACE;
    pr_info("LSMT: read tailer\n");
    ret = zfile_read(fp, &lf->ht, sizeof(struct lsmt_ht), tailer_offset);
    if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
        printk("failed to load tailer \n");
        return NULL;
    }
    pr_info("LSMT: index off: %lld cnt: %lld\n", lf->ht.index_offset,
            lf->ht.index_size);

    index_bytes = lf->ht.index_size * sizeof(struct segment_mapping);
    pr_info("LSMT: off: %lld, bytes: %ld\n", lf->ht.index_offset, index_bytes);
    if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024) return NULL;
    p = vmalloc(index_bytes);
    pr_info("LSMT: loadindex off: %lld cnt: %ld\n", lf->ht.index_offset,
            index_bytes);
    ret = zfile_read(fp, p, index_bytes, lf->ht.index_offset);
    pr_info("LSMT: load index ret=%d\n", ret);
    if (ret < index_bytes) {
        printk("failed to read index\n");
        vfree(p);
        return NULL;
    }
    for (idx = 0; idx < lf->ht.index_size; idx++) {
        if (p[idx].offset != INVALID_OFFSET) {
            // pr_info("LSMT: index[%d] offset=%ld length=%ld moffset=%ld
            // zeroed=%d\n", idx,
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

struct path lsmt_getpath(struct lsmt_file *file) {
    return zfile_getpath(file->fp);
}

struct file *lsmt_getfile(struct lsmt_file *file) {
    return zfile_getfile(file->fp);
}
static bool is_aligned(uint64_t val) { return 0 == (val & 0x1FFUL); }

ssize_t lsmt_read(struct lsmt_file *fp, void *buf, size_t count,
                  loff_t offset) {
    // TODO: read from underlay
    struct segment_mapping s;
    struct segment_mapping *m;
    ssize_t ret = 0;
    size_t i = 0;
    if (!is_aligned(offset | count)) {
        pr_info("LSMT: %lld %lu not aligned\n", offset, count);
        return -EINVAL;
    }
    if (offset > fp->ht.virtual_size) {
        pr_info("LSMT: %lld over tail\n", offset);
        return 0;
    }
    if (offset + count > fp->ht.virtual_size) {
        pr_info("LSMT: %lld %lu over tail\n", offset, count);
        count = fp->ht.virtual_size - offset;
    }
    // pr_info("LSMT: read %ld %ld\n", offset, count);
    m = kmalloc(16 * sizeof(struct segment_mapping), GFP_KERNEL);
    s.offset = offset / SECTOR_SIZE;
    s.length = count / SECTOR_SIZE;
    while (true) {
        int n = ro_index_lookup(&fp->index, &s, m, 16);
        for (i = 0; i < n; ++i) {
            if (s.offset < m[i].offset) {
                // hole
                // pr_info("LSMT: %d set %ld, %lu to 0\n", i, offset,
                //         (m[i].offset - s.offset) * SECTOR_SIZE);
                memset(buf, 0, (m->offset - s.offset) * SECTOR_SIZE);
                offset += (m[i].offset - s.offset) * SECTOR_SIZE;
                buf += (m[i].offset - s.offset) * SECTOR_SIZE;
                ret += (m[i].offset - s.offset) * SECTOR_SIZE;
            }
            // zeroe block
            if (m[i].zeroed) {
                // pr_info("LSMT: %d set %ld, %lu to 0\n", i, offset,
                //         m[i].length * SECTOR_SIZE);
                memset(buf, 0, m->length * SECTOR_SIZE);
                offset += m[i].length * SECTOR_SIZE;
                buf += m[i].length * SECTOR_SIZE;
                ret += m[i].length * SECTOR_SIZE;
            } else {
                // pr_info("LSMT: %d decompress copy %ld, %lu, moffset=%ld\n",
                // i,
                //         offset, m[i].length * SECTOR_SIZE,
                //         m[i].moffset * SECTOR_SIZE);
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

bool is_lsmtfile(struct zfile *fp) {
    struct lsmt_ht ht;
    ssize_t ret;
    if (!fp) return false;

    pr_info("LSMT: read header\n");
    ret = zfile_read(fp, &ht, sizeof(struct lsmt_ht), 0);

    if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
        printk("failed to load header \n");
        return NULL;
    }

    return ht.magic0 == *MAGIC0 && uuid_equal(&ht.magic1, &MAGIC1);
}