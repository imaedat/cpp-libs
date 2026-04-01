#include "descriptor.hpp"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <string>

using namespace std;
using namespace tbd;
using namespace std::string_literals;

template <typename C, typename P>
void fork_run(C&& c, P&& p)
{
    auto pid = fork();
    if (pid == 0) {
        c();
        _exit(0);
    }
    p();
    int status;
    waitpid(pid, &status, 0);
}

template <typename F>
void c2p(F&& gen)
{
    auto [r, w] = gen();
    fork_run([&w] { w.write("hello", 5); },
             [&r] {
                 char buf[32] = {0};
                 auto res = r.read(buf, 32);
                 assert(!!res);
                 assert((int)res == 5);
                 printf("read \"%s\"\n", buf);
             });
}

void ex_pipe()
{
    printf("pipe: ");
    c2p([] { return make_pipe(); });
}

void ex_sockpair()
{
    printf("sock: ");
    c2p([] { return make_socketpair(); });
}

void ex_fifo()
{
    printf("fifo: ");
    c2p([] {
        fifo r("./.fifo-tmp");
        fifo w("./.fifo-tmp", O_WRONLY);
        r.set_nonblock(false);
        return make_pair(move(r), move(w));
    });
}

void ex_mqueue()
{
    mq_unlink("/.mqueue");
    printf("mque: ");
    c2p([] { return make_pair(mqueue("/.mqueue", 1, 32), mqueue("/.mqueue", 1, 32)); });
}

void ex_epoll()
{
    tbd::epollfd epfd;
    tbd::timerfd timfd(100);
    epfd.add(timfd);
    auto ev = epfd.wait();
    assert(ev.size() >= 1);
    assert(ev[0].fd == *timfd);
}

void ex_poll()
{
    tbd::poll poll;
    tbd::timerfd timfd(100);
    poll.add(timfd);
    auto ev = poll.wait();
    assert(ev.size() >= 1);
    assert(ev[0].fd == *timfd);
}

void ex_eventfd()
{
    tbd::eventfd evfd;
    evfd.set_nonblock();
    try {
        evfd.read();
        assert(false);
    } catch (const system_error& e) {
        assert(e.code().value() == EAGAIN);
    }
    evfd.write(42);
    assert(evfd.read() == 42);
}

void ex_signalfd()
{
    tbd::signalfd sigfd({SIGUSR1});
    fork_run([&] { kill(getppid(), SIGUSR1); },  //
             [&] { assert(sigfd.get_last_signal() == SIGUSR1); });
}

void ex_timerfd()
{
    tbd::timerfd timfd(100);
    assert(timfd.read() == 1);
}

void ex_inotify()
{
    inotify infd;
    infd.add_watch(".", IN_CREATE);
    [[maybe_unused]] int r1 = system("touch .hello");
    try {
        auto evs = infd.read();
        for (const auto& ev : evs) {
            printf("inot: path %s, mask %x\n", ev.path.c_str(), ev.mask);
        }
    } catch (const std::exception& e) {
        printf("infd: %s\n", e.what());
    }
    [[maybe_unused]] int r2 = system("rm -f .hello");
}

void ex_memfd()
{
    tbd::memfd memfd("./memfd_demo");
    tbd::eventfd evfd;
    fork_run(
        [&] {
            memfd.write("hello", 5);
            evfd.write();
        },
        [&] {
            (void)evfd.read();
            lseek(*memfd, 0, SEEK_SET);
            char buf[8] = {0};
            auto n = (ssize_t)memfd.read(buf, 8);
            assert(n == 5);
            printf("memf: read \"%s\"\n", buf);
        });
}

void ex_mmap()
{
    memmap map("/proc/self/exe");
    char buf[8] = {0};
    memcpy(buf, (char*)map.data() + 1, 3);
    printf("mmap: read \"%s\"\n", buf);

    auto map2 = move(map);
    assert(map.data() == nullptr);

    map2 = memmap("/etc/passwd");
    map2.read(buf, 4);
    printf("mmap: read \"%s\"\n", buf);
}

void ex_shmem()
{
    static constexpr const char* name = "/shmem_demo";
    tbd::eventfd evfd;
    fork_run(
        [&] {
            tbd::shmem shm(name);
            memcpy(shm.data(), "hello", 5);
            evfd.write();
        },
        [&] {
            tbd::shmem shm(name);
            (void)evfd.read();
            char buf[8] = {0};
            shm.read(buf, 8);
            printf("shme: read \"%s\"\n", buf);
        });
}

int main()
{
    // communication channels
    ex_pipe();
    ex_sockpair();
    ex_fifo();
    ex_mqueue();

    // event notifying
    ex_epoll();
    ex_poll();
    ex_eventfd();
    ex_signalfd();
    ex_timerfd();
    ex_inotify();

    // memory io
    ex_memfd();
    ex_mmap();
    ex_shmem();

    return 0;
}
