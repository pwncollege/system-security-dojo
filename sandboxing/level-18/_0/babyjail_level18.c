#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}
#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>

long getvendor(char *name, size_t len) {
    int fd = open("/sys/devices/virtual/dmi/id/sys_vendor", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    long nbytes = read(fd, name, len - 1);
    if (nbytes == -1) {
        close(fd);
        return -1;
    }

    name[nbytes] = '\0';

    size_t read_len = strlen(name);
    if (read_len > 0 && name[read_len - 1] == '\n') {
        name[read_len - 1] = '\0';
    }

    close(fd);
    return nbytes;
}

char vendor[128];

int main(int argc, char **argv, char **envp)
{
    // assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    getvendor(vendor, 128);
    if (strcmp(vendor, "QEMU"))
    {
        puts("ERROR: in the dojo, this challenge MUST run in virtualization mode.");
        puts("Please run `vm connect` to launch and connect to the Virtual Machine, then run this challenge inside the VM.");
        puts("You can tell when you are running inside the VM by looking at the hostname in your shell prompt:.");
        puts("if it starts with \"vm_\", you are executing inside the Virtual Machine.");
        puts("");
        puts("You can connect to the VM from multiple terminals by launching `vm connect` in each terminal, and all files");
        puts("are shared between the VM and the normal container.");
        exit(1);
    }

    puts("This challenge will use mount namespace and pivot_root to put you into a jail in /tmp/jail-XXXXXX. You will be able to");
    puts("easily read a fake flag file inside this jail, not the real flag file outside of it. If you want the real flag, you must");
    puts("escape.\n");

    puts("You may pick a directory (with many restrictions), as given by the first argument to the program (argv[1]). This");
    puts("directory will be bind-mounted into your jail.\n");
    puts("You may upload custom shellcode to do whatever you want.\n");

    assert(argc > 1);

    for (int i = 3; i < 10000; i++) close(i);

    puts("Checking your data directory path for shenanigans...");
    assert(argv[1][0] == '/');
    assert(strstr(argv[1], ".") == NULL);
    assert(strstr(argv[1], "flag") == NULL);
    assert(strstr(argv[1], "root") == NULL);
    assert(strstr(argv[1], "tmp") == NULL);
    assert(strstr(argv[1], "var") == NULL);
    assert(strstr(argv[1], "run") == NULL);
    assert(strstr(argv[1], "dev") == NULL);
    assert(strstr(argv[1], "fd") == NULL);
    if (strstr(argv[1], "home")) assert(strcmp("/home/hacker", argv[1]) == 0);
    else
    {
        puts("... to minimize shenanigans, we only support your home dir or a non-writable leaf directory (no subdirs).");
        struct stat statbuf;
        struct dirent *dent;
        char dirpath[1024];
        DIR *dir;

        assert(lstat(argv[1], &statbuf) != -1);
        assert(S_ISDIR(statbuf.st_mode));
        assert(dir = opendir(argv[1]));
        while ((dent = readdir(dir)) != NULL)
        {
            if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) continue;
            snprintf(dirpath, 1024, "%s/%s", argv[1], dent->d_name);
            printf("... making sure %s is not a directory\n", dirpath);
            assert(stat(dirpath, &statbuf) != -1);
            assert(!S_ISDIR(statbuf.st_mode));
        }
        closedir(dir);
    }

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    puts("Checking that the challenge is running as root (otherwise things will fail)...");
    assert(geteuid() == 0);

    puts("Splitting off into our own mount namespace...");
    assert(unshare(CLONE_NEWNS) != -1);

    // create the new root
    puts("Creating a jail structure!");
    puts("... creating jail root...");
    assert(mkdtemp(new_root) != NULL);
    printf("... created jail root at `%s`.\n", new_root);

    // change the old root (/) to a private mount so that changes aren't propagated to parent mount namespaces
    // (note: rather than doing this propagation, pivot_root will just fail)
    puts("... changing the old / to a private mount so that pivot_root succeeds later.");
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

    puts("... bind-mounting the new root over itself so that it becomes a 'mount point' for pivot_root() later.");
    assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

    puts("... creating a directory in which pivot_root will put the old root filesystem.");
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    assert(mkdir(old_root, 0777) != -1);

    puts("... pivoting the root filesystem!");
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

    char dirpath[1024];
    snprintf(dirpath, 1024, "/old%s", argv[1]);
    printf("... bind-mounting (read-only) %s for you into /data in the jail.\n", dirpath);
    assert(mkdir("/data", 0755) != -1);
    assert(mount(dirpath, "/data", NULL, MS_BIND, NULL) != -1);
    assert(mount(NULL, "/data", NULL, MS_REMOUNT|MS_RDONLY|MS_BIND, NULL) != -1);

    // let's remove the old root mount
    puts("... unmounting old root directory.");
    assert(umount2("/old", MNT_DETACH) != -1);
    assert(rmdir("/old") != -1);

    // make things simpler for everyone to avoid strange behavior with permissions
    setresuid(0, 0, 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();

    printf("### Goodbye!\n");
}
