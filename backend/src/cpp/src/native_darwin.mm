#include <Foundation/Foundation.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>

typedef struct {
    int pid;
    char *processname;
} ProcessInfo;

extern "C" kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

int debug_log(const char *format, ...) {
    va_list list;
    va_start(list, format);
    NSString *originalFormatString = [NSString stringWithUTF8String:format];
    NSString *taggedFormatString = [NSString stringWithFormat:@"[MEMORYSERVER] %@", originalFormatString];
    NSLogv(taggedFormatString, list);
    va_end(list);
    return 0;
}
//--
extern "C" ssize_t read_memory_native(int pid, mach_vm_address_t address, mach_vm_size_t size, unsigned char *buffer) {
    debug_log("read_memory_native: pid = %d, address = 0x%llx, size = 0x%llx", pid, address, size);

    mach_port_t task;
    kern_return_t kr;
    if (pid == getpid()) {
        task = mach_task_self();
    } else {
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            debug_log("Error: task_for_pid failed with error %d (%s)", kr, mach_error_string(kr));
            return -1;
        }
    }

    mach_vm_size_t out_size;
    kr = mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buffer, &out_size);
    if (kr != KERN_SUCCESS) {
        debug_log("Error: mach_vm_read_overwrite failed with error %d (%s)", kr, mach_error_string(kr));
        return -1;
    }

    debug_log("read_memory_native: successfully read 0x%llx bytes", out_size);
    return (ssize_t)out_size;
}
///---------------------------
extern "C" ssize_t write_memory_native(int pid, mach_vm_address_t address, mach_vm_size_t size, unsigned char *buffer) {
    debug_log("write_memory_native: pid = %d, address = 0x%llx, size = 0x%llx", pid, address, size);

    task_t task;
    kern_return_t err;
    vm_prot_t original_protection;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    bool is_embeded_mode = pid == getpid();

    if (is_embeded_mode) {
        task = mach_task_self();
    } else {
        err = task_for_pid(mach_task_self(), pid, &task);
        if (err != KERN_SUCCESS) {
            debug_log("Error: task_for_pid failed with error %d (%s)", err, mach_error_string(err));
            return -1;
        }
    }

    if (!is_embeded_mode) {
        err = task_suspend(task);
        if (err != KERN_SUCCESS) {
            debug_log("Error: task_suspend failed with error %d (%s)", err, mach_error_string(err));
            return -1;
        }
    }

    mach_vm_address_t region_address = address;
    mach_vm_size_t region_size = size;
    err = mach_vm_region(task, &region_address, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name);
    if (err != KERN_SUCCESS) {
        debug_log("Error: mach_vm_region failed with error %d (%s) at address 0x%llx, size 0x%llx", err, mach_error_string(err), address, size);
        if (!is_embeded_mode) {
            task_resume(task);
        }
        return -1;
    }
    original_protection = info.protection;

    err = vm_protect(task, address, size, false, VM_PROT_READ | VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        debug_log("Error: vm_protect (write enable) failed with error %d (%s)", err, mach_error_string(err));
        if (!is_embeded_mode) {
            task_resume(task);
        }
        return -1;
    }

    err = mach_vm_write(task, address, (vm_offset_t)buffer, (mach_msg_type_number_t)size);
    if (err != KERN_SUCCESS) {
        debug_log("Error: mach_vm_write failed with error %d (%s)", err, mach_error_string(err));
        if (!is_embeded_mode) {
            task_resume(task);
        }
        return -1;
    }

    err = vm_protect(task, address, size, false, original_protection);
    if (err != KERN_SUCCESS) {
        debug_log("Warning: vm_protect (restore protection) failed with error %d (%s)", err, mach_error_string(err));
        if (!is_embeded_mode) {
            task_resume(task);
        }
        return -1;
    }

    if (!is_embeded_mode) {
        err = task_resume(task);
        if (err != KERN_SUCCESS) {
            debug_log("Error: task_resume failed with error %d (%s)", err, mach_error_string(err));
            return -1;
        }
    }

    debug_log("write_memory_native: successfully wrote 0x%llx bytes", size);
    return size;
}

//--------------
extern "C" void enumerate_regions_to_buffer(pid_t pid, char *buffer, size_t buffer_size) {
    debug_log("enumerate_regions_to_buffer: pid = %d, buffer_size = %zu", pid, buffer_size);

    task_t task;
    kern_return_t err;
    vm_address_t address = 0;
    vm_size_t size = 0;
    natural_t depth = 1;

    if (pid == getpid()) {
        task = mach_task_self();
    } else {
        err = task_for_pid(mach_task_self(), pid, &task);
        if (err != KERN_SUCCESS) {
            snprintf(buffer, buffer_size, "Failed to get task for pid %d\n", pid);
            debug_log("Error: task_for_pid failed with error %d (%s)", err, mach_error_string(err));
            return;
        }
    }

    size_t pos = 0;
    while (true) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

        if (vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS) {
            debug_log("Error: vm_region_recurse_64 failed at address 0x%llx", address);
            break;
        }

        if (info.is_submap) {
            depth++;
        } else {
            char protection[4] = "---";
            if (info.protection & VM_PROT_READ)
                protection[0] = 'r';
            if (info.protection & VM_PROT_WRITE)
                protection[1] = 'w';
            if (info.protection & VM_PROT_EXECUTE)
                protection[2] = 'x';

            pos += snprintf(buffer + pos, buffer_size - pos, "%llx-%llx %s\n", (unsigned long long)address, (unsigned long long)(address + size), protection);
            debug_log("enumerate_regions_to_buffer: region %llx-%llx, protection = %s", (unsigned long long)address, (unsigned long long)(address + size), protection);

            if (pos >= buffer_size - 1)
                break;

            address += size;
        }
    }
}

extern "C" ProcessInfo *enumprocess_native(size_t *count) {
    debug_log("enumprocess_native: start");

    int err;
    struct kinfo_proc *result;
    bool done;
    static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t length;

    result = NULL;
    done = false;

    do {
        length = 0;
        err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
        if (err == -1) {
            err = errno;
        }

        if (err == 0) {
            result = (struct kinfo_proc *)malloc(length);
                        if (result == NULL) {
                err = ENOMEM;
            }
        }

        if (err == 0) {
            err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, result, &length, NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && !done);

    if (err == 0 && result != NULL) {
        *count = length / sizeof(struct kinfo_proc);
        ProcessInfo *processes = (ProcessInfo *)malloc(*count * sizeof(ProcessInfo));

        for (size_t i = 0; i < *count; i++) {
            processes[i].pid = result[i].kp_proc.p_pid;
            processes[i].processname = strdup(result[i].kp_proc.p_comm);
            debug_log("enumprocess_native: pid = %d, processname = %s", processes[i].pid, processes[i].processname);
        }

        free(result);
        debug_log("enumprocess_native: successfully enumerated %zu processes", *count);
        return processes;
    } else {
        if (result != NULL) {
            free(result);
        }
        debug_log("enumprocess_native: failed with error %d", err);
    }
    return NULL;
}

extern "C" bool suspend_process(pid_t pid) {
    debug_log("suspend_process: pid = %d", pid);

    task_t task;
    kern_return_t err;
    bool is_embeded_mode = pid == getpid();
    if (is_embeded_mode) {
        debug_log("suspend_process: cannot suspend the current process");
        return false;
    }
    err = task_for_pid(mach_task_self(), pid, &task);
    if (err != KERN_SUCCESS) {
        debug_log("Error: task_for_pid failed with error %d (%s)", err, mach_error_string(err));
        return false;
    }
    err = task_suspend(task);
    if (err != KERN_SUCCESS) {
        debug_log("Error: task_suspend failed with error %d (%s)", err, mach_error_string(err));
        return false;
    }

    debug_log("suspend_process: successfully suspended process %d", pid);
    return true;
}

extern "C" bool resume_process(pid_t pid) {
    debug_log("resume_process: pid = %d", pid);

    task_t task;
    kern_return_t err;
    bool is_embeded_mode = pid == getpid();
    if (is_embeded_mode) {
        debug_log("resume_process: cannot resume the current process");
        return false;
    }
    err = task_for_pid(mach_task_self(), pid, &task);
    if (err != KERN_SUCCESS) {
        debug_log("Error: task_for_pid failed with error %d (%s)", err, mach_error_string(err));
        return false;
    }
    err = task_resume(task);
    if (err != KERN_SUCCESS) {
        debug_log("Error: task_resume failed with error %d (%s)", err, mach_error_string(err));
        return false;
    }

    debug_log("resume_process: successfully resumed process %d", pid);
    return true;
}