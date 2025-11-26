#include "msr.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

static int *msr_fds = NULL;
static int cpu_count = 0;

int msr_init(void) {
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Get CPU count */
    cpu_count = msr_get_cpu_count();
    if (cpu_count <= 0) {
        FG_LOG_ERROR("Failed to determine CPU count");
        return FG_ERROR;
    }

    /* Allocate file descriptor array */
    msr_fds = calloc(cpu_count, sizeof(int));
    if (!msr_fds) {
        FG_LOG_ERROR("Failed to allocate memory for MSR file descriptors");
        return FG_ERROR;
    }

    /* Initialize all FDs to -1 */
    for (int i = 0; i < cpu_count; i++) {
        msr_fds[i] = -1;
    }

    /* Try to load msr kernel module if not already loaded */
    int modprobe_ret = system("modprobe msr 2>/dev/null");
    if (modprobe_ret != 0) {
        FG_DEBUG("modprobe msr returned %d (module may already be loaded or unavailable)", modprobe_ret);
    }

    FG_INFO("MSR subsystem initialized (%d CPUs)", cpu_count);
    return FG_SUCCESS;
}

void msr_cleanup(void) {
    if (msr_fds) {
        for (int i = 0; i < cpu_count; i++) {
            if (msr_fds[i] >= 0) {
                close(msr_fds[i]);
            }
        }
        free(msr_fds);
        msr_fds = NULL;
    }
    cpu_count = 0;
}

int msr_read(uint32_t cpu, uint32_t msr, uint64_t *value) {
    char msr_path[64];
    int fd;
    ssize_t ret;

    if (!value) {
        return FG_ERROR;
    }

    if (cpu >= cpu_count) {
        FG_LOG_ERROR("CPU %u out of range (max: %d)", cpu, cpu_count - 1);
        return FG_ERROR;
    }

    /* Open MSR device for this CPU if not already open */
    if (msr_fds[cpu] < 0) {
        snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%u/msr", cpu);
        fd = open(msr_path, O_RDONLY);
        if (fd < 0) {
            /* Try alternative path */
            snprintf(msr_path, sizeof(msr_path), "/dev/msr%u", cpu);
            fd = open(msr_path, O_RDONLY);
            if (fd < 0) {
                FG_DEBUG("Cannot open MSR device for CPU %u: %s", cpu, strerror(errno));
                return FG_NOT_SUPPORTED;
            }
        }
        msr_fds[cpu] = fd;
    } else {
        fd = msr_fds[cpu];
    }

    /* Seek to MSR address */
    if (lseek(fd, msr, SEEK_SET) < 0) {
        FG_DEBUG("Failed to seek to MSR 0x%x: %s", msr, strerror(errno));
        return FG_ERROR;
    }

    /* Read MSR value */
    ret = read(fd, value, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        FG_DEBUG("Failed to read MSR 0x%x: %s", msr, strerror(errno));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

int msr_write(uint32_t cpu, uint32_t msr, uint64_t value) {
    char msr_path[64];
    int fd;
    ssize_t ret;

    if (cpu >= cpu_count) {
        FG_LOG_ERROR("CPU %u out of range (max: %d)", cpu, cpu_count - 1);
        return FG_ERROR;
    }

    /* Open MSR device for writing */
    snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%u/msr", cpu);
    fd = open(msr_path, O_WRONLY);
    if (fd < 0) {
        snprintf(msr_path, sizeof(msr_path), "/dev/msr%u", cpu);
        fd = open(msr_path, O_WRONLY);
        if (fd < 0) {
            FG_LOG_ERROR("Cannot open MSR device for writing on CPU %u: %s",
                     cpu, strerror(errno));
            return FG_NOT_SUPPORTED;
        }
    }

    /* Seek to MSR address */
    if (lseek(fd, msr, SEEK_SET) < 0) {
        FG_LOG_ERROR("Failed to seek to MSR 0x%x: %s", msr, strerror(errno));
        close(fd);
        return FG_ERROR;
    }

    /* Write MSR value */
    ret = write(fd, &value, sizeof(uint64_t));
    close(fd);

    if (ret != sizeof(uint64_t)) {
        FG_LOG_ERROR("Failed to write MSR 0x%x: %s", msr, strerror(errno));
        return FG_ERROR;
    }

    FG_INFO("Wrote MSR 0x%x on CPU %u: 0x%lx", msr, cpu, value);
    return FG_SUCCESS;
}

bool msr_is_supported(void) {
    struct stat st;

    /* Check if /dev/cpu/0/msr or /dev/msr0 exists */
    if (stat("/dev/cpu/0/msr", &st) == 0 || stat("/dev/msr0", &st) == 0) {
        return true;
    }

    /* Check if msr module is available */
    if (stat("/lib/modules", &st) == 0) {
        return true; /* Assume we can load it */
    }

    return false;
}

int msr_get_cpu_count(void) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    /* Try to count CPUs from /sys/devices/system/cpu */
    dir = opendir("/sys/devices/system/cpu");
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "cpu", 3) == 0 &&
                entry->d_name[3] >= '0' && entry->d_name[3] <= '9') {
                count++;
            }
        }
        closedir(dir);
    }

    /* Fallback: use sysconf */
    if (count == 0) {
        count = sysconf(_SC_NPROCESSORS_ONLN);
    }

    return count > 0 ? count : 1;
}
