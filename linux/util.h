#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "hardcode.h"
#include "aarch64.h"
#include "android.h"

#define SEARCH_SIZE 200 * 1024
#define SEARCH_BYTES (SEARCH_SIZE * 1024)
#define IS_KERNEL_PTR(a) ((((uint64_t) a) & KERNEL_PTR) == KERNEL_PTR)
#define INIT_NAME "swapper/0"

struct cred;
struct kernel_cap_struct;
struct list_head;

struct callback_head {
    struct callback_head *next;
    void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct init_task_pattern {
	uint64_t                     stack;                /*     8     8 */
	atomic_t                   usage;                /*    16     4 */
	unsigned int               flags;                /*    20     4 */
};

struct tasks_pattern {
    struct list_head tasks;
    int prio;
    struct list_head pushable_tasks;
};

static const struct init_task_pattern pat = {
    .stack = 0x1fff,
    .usage = 0x2,
    .flags = PF_KTHREAD, 
};

static const struct tasks_pattern tpat = {
    .prio = MAX_PRIO,
};

typedef struct kernel_cap_struct {
    uint32_t cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

struct cred {
    atomic_t usage;
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
    unsigned	securebits;	/* SUID-less security management */
    kernel_cap_t	cap_inheritable; /* caps our children can inherit */
    kernel_cap_t	cap_permitted;	/* caps we're permitted */
    kernel_cap_t	cap_effective;	/* caps we can actually use */
    kernel_cap_t	cap_bset;	/* capability bounding set */
};

struct socket {
	int state;
	short			type;
	unsigned long		flags;
	void *wq;
	void		*file;
	void *sk;
	void *ops;
};

int mread(char *des, char *addr, size_t n);
                                                                                
int mwrite(char *src, char *addr, size_t n); 

void dump_hex(const void* data, size_t size, char *addr);

int locate_files();

int dump(char *addr);

int get_symaddr(const char *name, uint64_t *addr);

int get_files(char *task, char **files);

int locate_private_data(int sockfd, char **private_data);

int get_sock(int fd, char **sock);

int propagate_kallsyms(FILE *fp);

int count_lines(FILE *fp);

int get_ipv6_pinfo(int fd, char **pinet6);

static const int incr = sizeof(void *);

int propagate_syms_info();

void kallsyms_destruct();

// info retrieved while searching
struct tasks_info {
    char *loc_init_task;
    char *loc_curr_task;
    char *loc_init_files;
    int tasks_offset;
    int cred_offset;
    int comm_offset;
    int file_offset;
};

struct file_info {
    int fdtab_offset;
    int fd_offset;
    int privatedata_offset;
};

struct socket_info {
    int pinet6_offset;
};

struct sym_info {
    uint64_t addr;
    char name[256];
};

// global info structure
extern struct tasks_info info;
extern struct file_info finfo;
extern struct socket_info sinfo;
extern struct sym_info *kallsyms;
extern int kallsyms_num;
#endif
