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

    for (int i = 3; i < 10000; i++) close(i);

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

    assert(mkdir("/bin", 0755) != -1);
    puts("... bind-mounting /bin into the jail.");
    assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/usr", 0755) != -1);
    puts("... bind-mounting /usr into the jail.");
    assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib", 0755) != -1);
    puts("... bind-mounting /lib into the jail.");
    assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib64", 0755) != -1);
    puts("... bind-mounting /lib64 into the jail.");
    assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");

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

    puts("Executing a shell inside the sandbox! Good luck!");
    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);

    printf("### Goodbye!\n");
}
