#ifndef __ZFILE_RO_H__
#define __ZFILE_RO_H__

#include <linux/uuid.h>
#include <linux/kthread.h>
#include <linux/blk-mq.h>

static const uint32_t ZF_SPACE = 512;

struct compress_options {
  uint32_t block_size; //4
  uint8_t type; //5
  uint8_t level; //6
  uint8_t use_dict; //7
  uint32_t args; // 11
  uint32_t dict_size; //15
  uint8_t verify; //16
};

_Static_assert(20 == sizeof(struct compress_options), "CO size not fit");

struct _UUID {
  uint32_t a;
  uint16_t b, c, d;
  uint8_t e[6];
} __attribute__((packed));

static uint64_t *MAGIC0 = (uint64_t *)"ZFile\0\1";

static const uuid_t MAGIC1 = UUID_INIT(
    0x74756a69, 0x2e79, 0x7966, 0x40, 0x41, 0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);

struct zfile_ht {
  uint64_t magic0; // 8
  uuid_t magic1; // 4+2+2+2+6 = 4 + 12 = 20

  // till here offset = 28
  uint32_t size_ht;  //= sizeof(HeaderTrailer); // 32
  uint64_t flags; //= 0;                        // 40

  // till here offset = 40
  uint64_t index_offset; // in bytes  48
  uint64_t index_size;   // num of index  56  

  uint64_t vsize;  // 64
  uint64_t reserved_0; // 72

  struct compress_options opt; // suppose to be 24
}; 

_Static_assert(96 == sizeof(struct zfile_ht), "Header size not fit");

struct jump_table {
   uint64_t partial_offset; // 48 bits logical offset + 16 bits partial minimum
   uint16_t delta;
};

// zfile can be treated as file with extends
struct zfile {
        struct file *fp;
	struct zfile_ht header;
        struct jump_table *jump;
};

// zfile functions
// in `zfile`, data ready by `kernel_read` and then decompress to buffer
// since calling `zfile_read` may not be aligned query, may have to perform
// more-than-one page fetch, here is the place to caching non-complete used
// compressed pages.
//
struct zfile* zfile_open(const char* path);
ssize_t zfile_read(struct zfile* zfile, void* buff, size_t count, loff_t offset);
size_t zfile_len(struct zfile *zfile);
void zfile_close(struct zfile* zfile);



#endif