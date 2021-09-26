#ifndef __LSMT_RO_H__
#define __LSMT_RO_H__

#include <linux/uuid.h>
#include <linux/kthread.h>
#include <linux/blk-mq.h>


struct zfile;

static const uint32_t HT_SPACE = 4096;

struct lsmt_ht {
  uint64_t magic0;
  uuid_t magic1;
  // offset 24, 28
  uint32_t size;  //= sizeof(HeaderTrailer);
  uint32_t flags; //= 0;
  // offset 32, 40, 48
  uint64_t index_offset; // in bytes
  uint64_t index_size;   // # of SegmentMappings
  uint64_t virtual_size; // in bytes
} __attribute__((packed));


struct segment_mapping {                             /* 8 + 8 bytes */
        uint64_t offset : 50; // offset (0.5 PB if in sector)
        uint32_t length : 14;
        uint64_t moffset : 55; // mapped offset (2^64 B if in sector)
        uint32_t zeroed : 1;   // indicating a zero-filled segment
        uint8_t tag;
}__attribute__((packed));

struct lsmt_ro_index {
        const struct segment_mapping *pbegin;
        const struct segment_mapping *pend;
        struct segment_mapping *mapping;
};

struct lsmt_file {
        struct zfile *fp;
        struct lsmt_ht ht;
        struct lsmt_ro_index index;
};

// lsmt_file functions... 
// in `lsmt_file`, all data read by using `zfile_read`
//
struct lsmt_file* lsmt_open(struct zfile* zf);
ssize_t lsmt_read(struct lsmt_file* fp, void* buff, size_t count, loff_t offset);
size_t lsmt_len(struct lsmt_file *fp);
void lsmt_close(struct lsmt_file *fp);

#endif