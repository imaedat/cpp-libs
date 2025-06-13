#include "pipe.hpp"

#include <sys/wait.h>

int main()
{
    tbd::pipe p;

    auto pid = fork();

    if (pid == 0) {
        auto r = p.get_reader();
        auto msg = r.read();
        printf("receive: %s\n", msg.c_str());
        _exit(0);
    }

    auto w = p.get_writer();
    w.write("hello");

    int status;
    waitpid(pid, &status, 0);
}
