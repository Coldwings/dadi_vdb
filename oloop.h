/* SPDX-License-Identifier: GPL-1.0+ WITH Linux-syscall-note */
/*
 * include/linux/loop.h
 *
 * Written by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 */
#ifndef _UAPI_LINUX_OVBD_H
#define _UAPI_LINUX_OVBD_H


#define LO_NAME_SIZE	64
#define LO_KEY_SIZE	32


#include <asm/posix_types.h>	/* for __kernel_old_dev_t */
#include <linux/types.h>	/* for __u64 */

/* Backwards compatibility version */
struct ovbd_info {
	int		   ov_number;		/* ioctl r/o */
	__kernel_old_dev_t ov_device; 		/* ioctl r/o */
	unsigned long	   ov_inode; 		/* ioctl r/o */
	__kernel_old_dev_t ov_rdevice; 		/* ioctl r/o */
	int		   ov_offset;
	int		   ov_encrypt_type;
	int		   ov_encrypt_key_size; 	/* ioctl w/o */
	int		   ov_flags;
	char		   ov_name[LO_NAME_SIZE];
	unsigned char	   ov_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
	unsigned long	   ov_init[2];
	char		   reserved[4];
};

struct ovbd_info64 {
	__u64		   ov_device;			/* ioctl r/o */
	__u64		   ov_inode;			/* ioctl r/o */
	__u64		   ov_rdevice;			/* ioctl r/o */
	__u64		   ov_offset;
	__u64		   ov_sizelimit;/* bytes, 0 == max available */
	__u32		   ov_number;			/* ioctl r/o */
	__u32		   ov_encrypt_type;
	__u32		   ov_encrypt_key_size;		/* ioctl w/o */
	__u32		   ov_flags;
	__u8		   ov_file_name[LO_NAME_SIZE];
	__u8		   ov_crypt_name[LO_NAME_SIZE];
	__u8		   ov_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
	__u64		   ov_init[2];
};

/**
 * struct ovbd_config - Complete configuration for a loop device.
 * @fd: fd of the file to be used as a backing file for the loop device.
 * @block_size: block size to use; ignored if 0.
 * @info: struct ovbd_info64 to configure the loop device with.
 *
 * This structure is used with the OVBD_CONFIGURE ioctl, and can be used to
 * atomically setup and configure all loop device parameters at once.
 */
struct ovbd_config {
	__u32			fd;
	__u32                   block_size;
	struct ovbd_info64	info;
	__u64			__reserved[8];
};

/*
 * IOCTL commands --- we will commandeer 0x4C ('L')
 */

#define OVBD_SET_FD		0x4C00
#define OVBD_CLR_FD		0x4C01
#define OVBD_SET_STATUS		0x4C02
#define OVBD_GET_STATUS		0x4C03
#define OVBD_SET_STATUS64	0x4C04
#define OVBD_GET_STATUS64	0x4C05
#define OVBD_CHANGE_FD		0x4C06
#define OVBD_SET_CAPACITY	0x4C07
#define OVBD_SET_BLOCK_SIZE	0x4C09
#define OVBD_CONFIGURE		0x4C0A

/* /dev/loop-control interface */
#define OVBD_CTL_ADD		0x4C80
#define OVBD_CTL_REMOVE		0x4C81
#define OVBD_CTL_GET_FREE	0x4C82

#define OVBD_CTRL_MINOR		212

#endif /* _UAPI_LINUX_OVBD_H */
