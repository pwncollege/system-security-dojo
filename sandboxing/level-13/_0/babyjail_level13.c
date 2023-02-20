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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

int child_pid;

void cleanup(int signal)
{
    puts("Time is up: terminating the child and parent!\n");
    kill(child_pid, 9);
    kill(getpid(), 9);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will fork into a jail. Inside of the child process' jail, you will only be able to communicate with the");
    puts("parent process. If you want the flag, you must convince the parent process to give it to you.\n");
    for (int i = 3; i < 10000; i++) close(i);

    puts("Creating a `socketpair` that the child and parent will use to communicate. This is a pair of file descriptors that are");
    puts("connected: data written to one can be read from the other, and vice-versa.\n");
    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    printf("The parent side of the socketpair is FD %d.\n", parent_socket);
    printf("The child side of the socketpair is FD %d.\n", child_socket);

    puts("Registering a cleanup function that will run 1 second from now and terminate both the parent and child.\n");
    alarm(1);
    signal(SIGALRM, cleanup);

    puts("Forking into a parent and child (sandbox) process.\n");
    child_pid = fork();
    if (!child_pid)
    {
        puts("The child will now close itself off from the world, except for the child side of the socketpair.\n");
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode == (void *)0x1337000);
        printf("The child mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

        scmp_filter_ctx ctx;

        puts("Restricting system calls (default: kill).\n");
        ctx = seccomp_init(SCMP_ACT_KILL);
        printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode, 0x1000);

        write(child_socket, "print_msg:Executing shellcode!", 128);

        ((void(*)())shellcode)();
    }

    else
    {
        puts("The parent is reading 0x1000 bytes of shellcode from stdin.\n");
        char shellcode[0x1000];
        read(0, shellcode, 0x1000);

        puts("The parent is sending the shellcode to the child.\n");
        write(parent_socket, shellcode, 0x1000);

        while (true)
        {
            char command[128] = { 0 };

            puts("The parent is waiting for a command from the child.\n");
            int command_size = read(parent_socket, command, 128);
            command[9] = '\0';

            char *command_argument = &command[10];
            int command_argument_size = command_size - 10;

            printf("The parent received command `%.10s` with an argument of %d bytes from the child.\n", command, command_argument_size);

            if (strcmp(command, "print_msg") == 0)
            {
                puts(command_argument);
            }
            else if (strcmp(command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                puts("Error: unknown command!\n");
                break;
            }
        }
    }
}