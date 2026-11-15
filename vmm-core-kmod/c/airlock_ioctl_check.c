// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * Static userspace helper run inside L1 Linux (`initramfs` / Alpine) to verify:
 *  1. `/dev/airlock` ioctls (`AIRLOCK_IOC_GET_API_VERSION`, `AIRLOCK_IOC_GET_CAPS`)
 *  2. Zero-conflict hardware coexistence with `/dev/kvm` (`KVM_CREATE_VM` + `KVM_CREATE_VCPU`)
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "airlock_uapi.h"

int main(int argc, char **argv)
{
    int check_kvm = (argc > 1 && strcmp(argv[1], "--kvm-coexist") == 0);
    int afd = open("/dev/airlock", O_RDWR | O_CLOEXEC);
    __u32 ver = 0, caps = 0;

    if (afd < 0) {
        fprintf(stderr, "open(/dev/airlock) failed: %s\n", strerror(errno));
        return 1;
    }
    if (ioctl(afd, AIRLOCK_IOC_GET_API_VERSION, &ver) != 0) {
        fprintf(stderr, "ioctl(AIRLOCK_IOC_GET_API_VERSION) failed: %s\n", strerror(errno));
        close(afd);
        return 1;
    }
    if (ver != AIRLOCK_API_VERSION) {
        fprintf(stderr, "unexpected API version %u (expected %u)\n", ver, AIRLOCK_API_VERSION);
        close(afd);
        return 1;
    }
    if (ioctl(afd, AIRLOCK_IOC_GET_CAPS, &caps) != 0) {
        fprintf(stderr, "ioctl(AIRLOCK_IOC_GET_CAPS) failed: %s\n", strerror(errno));
        close(afd);
        return 1;
    }
    if ((caps & (AIRLOCK_CAP_SVM | AIRLOCK_CAP_NPT)) != (AIRLOCK_CAP_SVM | AIRLOCK_CAP_NPT)) {
        fprintf(stderr, "missing SVM+NPT caps: got 0x%x\n", caps);
        close(afd);
        return 1;
    }

    if (check_kvm) {
        int kfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
        int vm_fd, vcpu_fd;
        __u32 caps2 = 0;

        if (kfd < 0) {
            fprintf(stderr, "open(/dev/kvm) failed: %s\n", strerror(errno));
            close(afd);
            return 1;
        }
        vm_fd = ioctl(kfd, KVM_CREATE_VM, 0UL);
        if (vm_fd < 0) {
            fprintf(stderr, "ioctl(KVM_CREATE_VM) failed while airlock.ko loaded: %s\n",
                    strerror(errno));
            close(kfd);
            close(afd);
            return 1;
        }
        vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0UL);
        if (vcpu_fd < 0) {
            fprintf(stderr, "ioctl(KVM_CREATE_VCPU) failed while airlock.ko loaded: %s\n",
                    strerror(errno));
            close(vm_fd);
            close(kfd);
            close(afd);
            return 1;
        }
        if (ioctl(afd, AIRLOCK_IOC_GET_CAPS, &caps2) != 0 || caps2 != caps) {
            fprintf(stderr, "airlock ioctl failed while KVM VM active\n");
            close(vcpu_fd);
            close(vm_fd);
            close(kfd);
            close(afd);
            return 1;
        }
        close(vcpu_fd);
        close(vm_fd);
        close(kfd);
        printf("AIRLOCK_KVM_COEXIST_OK ver=%u caps=0x%x\n", ver, caps);
    } else {
        printf("AIRLOCK_IOCTL_OK ver=%u caps=0x%x\n", ver, caps);
    }

    close(afd);
    return 0;
}
