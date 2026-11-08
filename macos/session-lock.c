#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

#ifndef ZEEL_LOCK_PATH
#define ZEEL_LOCK_PATH "/private/var/run/com.bestrailgun.zeeload-gui.lock"
#endif

int main(int argc, char **argv) {
    if (argc < 2) return 64;

    int lock = open(ZEEL_LOCK_PATH, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (lock < 0) {
        perror("ZEELoad session lock");
        return 1;
    }
    if (flock(lock, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) fputs("已有极载 Mac 会话在运行，请先停止。\n", stderr);
        else perror("ZEELoad session lock");
        return 1;
    }

    // The supervisor holds fd 9. Its long-lived children close it on launch.
    if (lock != 9) {
        if (dup2(lock, 9) < 0) {
            perror("ZEELoad session lock");
            return 1;
        }
        close(lock);
    }
    execv(argv[1], argv + 1);
    perror("ZEELoad supervisor");
    return 1;
}
