#ifndef __LSMT_RO_H__
#define __LSMT_RO_H__

#undef __KERNEL__
#ifndef HBDEBUG
#define HBDEBUG (1)
#endif

#include <linux/err.h>
#include <linux/printk.h>
#include <linux/uuid.h>
#include <linux/fs.h>

#define PRINT_INFO(fmt, ...)                                     \
	do { if ((HBDEBUG)) \
	printk(KERN_INFO fmt, ## __VA_ARGS__);} while (0)

#define PRINT_ERROR(fmt, ...)                                          \
	do { if ((HBDEBUG)) \
	printk(KERN_ERR fmt, ## __VA_ARGS__);} while (0)
#define ASSERT(exp)						\
	BUG_ON(exp)

#define ALIGNED_MEM(name, size, alignment)  \
        char __buf##name[(size) + (alignment)]; \
        char *name = (char *)(((uint64_t)(__buf##name + (alignment) - 1)) & \
                        ~((uint64_t)(alignment) - 1));

#define REVERSE_LIST(type, begin, back) { type *l = (begin); type *r = (back);\
        while (l<r){ type tmp = *l; *l = *r; *r = tmp; l++; r--; }} \

typedef uint16_t inttype;
static const inttype inttype_max = 1<<16 - 1;
static const int DEFAULT_PART_SIZE = 16; // 16 x 4k = 64k
static const int DEFAULT_LSHIFT = 16;    // save local minimum of each part.
static const uint32_t HT_SPACE = 4096;
static const uint32_t ZF_SPACE = 512;

const static size_t MAX_READ_SIZE     = 65536; // 64K
const static size_t BUF_SIZE = 512;
const static uint32_t NOI_WELL_KNOWN_PRIME = 100007;
const static uint32_t SPACE = 512;
static const uint32_t FLAG_SHIFT_HEADER = 0; // 1:header     0:trailer
static const uint32_t FLAG_SHIFT_TYPE = 1;   // 1:data file, 0:index file
static const uint32_t FLAG_SHIFT_SEALED = 2; // 1:YES,       0:NO
static const uint64_t INVALID_OFFSET = (1UL << 50) - 1;

const static uint8_t MINI_LZO   = 0;
const static uint8_t LZ4        = 1;
const static uint8_t ZSTD       = 2;
const static uint32_t DEFAULT_BLOCK_SIZE = 4096;//8192;//32768;

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

static struct _UUID MAGIC1 = {
    0x696a7574, 0x792e, 0x6679, 0x4140, {0x6c, 0x69, 0x62, 0x61, 0x62, 0x61}};

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

#define TYPE_SEGMENT         0
#define TYPE_SEGMENT_MAPPING 1
#define TYPE_FILDES          2
#define TYPE_LSMT_RO_INDEX   3

struct lsmt_ht {
  uint64_t magic0;
  struct _UUID magic1;
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

// zfile can be treated as file with extends
struct zfile {
        struct file *fp;
	struct zfile_ht header;
        struct jump_table *jump;
        // void __user * map;
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

/*
 * Each block ovbd device has a radix_tree ovbd_pages of pages that stores
 * the pages containing the block device's contents. A ovbd page's ->index is
 * its offset in PAGE_SIZE units. This is similar to, but in no way connected
 * with, the kernel's pagecache or buffer cache (which sit above our block
 * device).
 */
struct ovbd_device {
	int		ovbd_number;

	struct request_queue	*ovbd_queue;
	struct gendisk		*ovbd_disk;
	struct list_head	ovbd_list;

	/*
	 * Backing store of pages and lock to protect it. This is the contents
	 * of the block device.
	 */
	// spinlock_t		ovbd_lock;
	// struct radix_tree_root	ovbd_pages;

	uint16_t block_size;

        // block-dev provides data by
        // using `lsmtfile_read`
        // assume block-dev size is `lsmtfile_len`
	struct lsmt_file* fp;
 	unsigned char* path;
	// bool initialized ;

};


/*struct file *file_open(const char *path, int flags, int rights)
void  file_close(struct file *file)
size_t get_file_size(struct file* path) ;
size_t file_read(struct file *file, void *buf, size_t count, loff_t *pos);
*/
#endif
