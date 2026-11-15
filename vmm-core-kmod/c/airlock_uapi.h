/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
#ifndef _AIRLOCK_UAPI_H_
#define _AIRLOCK_UAPI_H_

#include <linux/ioctl.h>
#include <linux/types.h>
#ifndef __KERNEL__
#include <sys/ioctl.h>
#endif

#define AIRLOCK_IOCTL_MAGIC 0xA4
#define AIRLOCK_API_VERSION 1U

/* Capability flags returned by AIRLOCK_IOC_GET_CAPS */
#define AIRLOCK_CAP_SVM       (1U << 0)
#define AIRLOCK_CAP_NPT       (1U << 1)
#define AIRLOCK_CAP_IOMMU     (1U << 2)

struct airlock_create_vm {
    __u64 shm_uaddr;      /* 4 KiB-aligned user VA of mmap'd BridgeShm memfd   */
    __u64 shm_size;       /* Byte size of BridgeShm (4 KiB-aligned)            */
    __u64 ram_uaddr;      /* 4 KiB-aligned user VA of mmap'd Guest RAM memfd   */
    __u64 ram_size;       /* Byte size of Guest RAM ([4 MiB ..= 64 GiB])       */
    __u64 payload_uaddr;  /* 4 KiB-aligned user VA of packed kernel||initrd    */
    __u64 payload_size;   /* Byte length of boot payload (0 if none)           */
    __u64 cwasm_uaddr;    /* User pointer to vmm-core-motor.cwasm image        */
    __u64 cwasm_size;     /* Byte length of .cwasm image (<= 16 MiB)           */
    __s32 c2i_eventfd;    /* Ring 0 -> Ring 3 doorbell eventfd                 */
    __s32 i2c_eventfd;    /* Ring 3 -> Ring 0 doorbell eventfd                 */
};

#define AIRLOCK_IOC_GET_API_VERSION _IOR(AIRLOCK_IOCTL_MAGIC, 0x00, __u32)
#define AIRLOCK_IOC_CREATE_VM       _IOW(AIRLOCK_IOCTL_MAGIC, 0x01, struct airlock_create_vm)
#define AIRLOCK_IOC_GET_CAPS        _IOR(AIRLOCK_IOCTL_MAGIC, 0x02, __u32)

#endif /* _AIRLOCK_UAPI_H_ */
