#include "descriptor.hpp"

#include <assert.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <string>

using namespace std;
using namespace tbd;
using namespace std::string_literals;

#define DEFENV(var, init) static int var = (init)
// clang-format off
#define GETENV(var) if (auto *p = getenv(#var); p) { var = atoi(p); }
// clang-format on

DEFENV(VERBOSE, 0);

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
    auto rr = move(r);  // move ctor
    auto ww = move(w);
    r = move(rr);  // move assign
    w = move(ww);
    fork_run(
        [&w] {
            auto res = w.writev({{(void*)"hello", 5}, {(void*)", world", 7}});
            if (!res) {
                if (VERBOSE) {
                    printf("writev: %s\n", res.message().c_str());
                }
                auto res = w.write("hello", 5);
                assert(!!res);
            }
        },
        [&r] {
            char buf[32] = {0};
            auto res = r.read(buf, 32);
            assert(!!res);
            assert((int)res == 5 || (int)res == 12);
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

void ex_dgramsocket_(int domain, const dgramsocket::address& srvaddr)
{
    const char* sdom = domain == AF_UNIX ? "un" : "in";
    printf("dg%s: ", sdom);

    c2p([&] {
        auto r = dgramsocket::server(srvaddr);
        auto w = dgramsocket(srvaddr);
        w.disconnect();
        w.connect(srvaddr);
        return make_pair(move(r), move(w));
    });

    tbd::eventfd evfd;
    fork_run(
        [&] {
            dgramsocket cli(domain);
            evfd.read();
            cli.sendto("HELLO", 5, srvaddr);
            char buf[8] = {0};
            auto [_, peer] = cli.recvfrom(buf, 8);
            if (VERBOSE) {
                printf("dg%s: cli.recvfrom \"%s\", from %s\n", sdom, buf, peer.name().c_str());
            }
            assert(peer == srvaddr);
            assert(string(buf) == "WORLD");
        },
        [&] {
            auto srv = dgramsocket::server(srvaddr);
            evfd.write();
            char buf[8] = {0};
            auto [_, peer] = srv.recvfrom(buf, 8);
            if (VERBOSE) {
                printf("dg%s: srv.recvfrom \"%s\", from %s\n", sdom, buf, peer.name().c_str());
            }
            assert(string(buf) == "HELLO");
            srv.sendto("WORLD", 5, peer);
        });
}

void ex_dgramsocket()
{
    ex_dgramsocket_(AF_UNIX, dgramsocket::address::af_unix("unsock"));
    ex_dgramsocket_(AF_INET, dgramsocket::address::af_inet("127.0.0.1", 5555));
}

void make_tun()
{
    [[maybe_unused]] int r = system("rm -f .tun-ok");
    tun_device tun("tun42", "10.0.0.1", "255.255.255.0");
    auto t = move(tun);
    tun = move(t);
    tun.up();
    r = system("touch .tun-ok");

    char buf[1024];
    while (true) {
        auto res = tun.read(buf, 1024);
        if (!res)
            break;
        auto* iphdr = (struct iphdr*)buf;
        if (iphdr->protocol == IPPROTO_ICMP) {
            printf("\rtund: read %lu bytes\n", res.nbytes());
            break;
        }
    }

    r = system("rm -f .tun-ok");
}

void ex_tundevice()
{
    tbd::eventfd evfd;
    fork_run([&] { [[maybe_unused]] int r = system("sudo ./descriptor make-tun"); },  //
             [&] {
                 inotify infd;
                 infd.add_watch(".", IN_CREATE);
                 (void)infd.read();

                 if (VERBOSE) {
                     [[maybe_unused]] int r1 = system("ip link show type tun | head -n1");
                 }
                 [[maybe_unused]] int r2 =
                     system("timeout 0.1 ping -c 1 -s 1024 10.0.0.2 >/dev/null 2>&1");
             });
}

void ex_epoll()
{
    tbd::epollfd epfd;
    auto e = move(epfd);
    epfd = move(e);
    tbd::timerfd timfd(100);
    epfd.add(timfd);
    auto ev = epfd.wait();
    assert(ev.size() >= 1);
    assert(ev[0].fd == *timfd);
}

void ex_poll()
{
    tbd::poll poll;
    auto p = move(poll);
    poll = move(p);
    tbd::timerfd timfd(100);
    poll.add(timfd);
    auto ev = poll.wait();
    assert(ev.size() >= 1);
    assert(ev[0].fd == *timfd);
}

void ex_eventfd()
{
    tbd::eventfd evfd;
    auto e = move(evfd);
    evfd = move(e);
    evfd.set_nonblock();
    assert(evfd.read() == 0);
    evfd.write(42);
    assert(evfd.read() == 42);
}

void ex_signalfd()
{
    tbd::signalfd sigfd({SIGUSR1});
    auto s = move(sigfd);
    sigfd = move(s);
    fork_run([&] { kill(getppid(), SIGUSR1); },  //
             [&] { assert(sigfd.get_last_signal() == SIGUSR1); });
}

void ex_timerfd()
{
    tbd::timerfd timfd(100);
    auto t = move(timfd);
    timfd = move(t);
    assert(timfd.read() == 1);
}

void ex_inotify()
{
    [[maybe_unused]] int r0 = system("rm -f .hello");
    inotify infd;
    infd.add_watch(".", IN_CREATE);
    auto i = move(infd);
    infd = move(i);
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
    auto m = move(memfd);
    memfd = move(m);
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
            auto s = move(shm);
            shm = move(s);
            memcpy(shm.data(), "hello", 5);
            evfd.write();
        },
        [&] {
            tbd::shmem shm(name);
            auto s = move(shm);
            shm = move(s);
            (void)evfd.read();
            char buf[8] = {0};
            shm.read(buf, 8);
            printf("shme: read \"%s\"\n", buf);
        });
}

int main(int argc, char* argv[])
{
    GETENV(VERBOSE);

    if (argc > 1 && strcmp(argv[1], "make-tun") == 0) {
        make_tun();
        return 0;
    }

    // communication channels
    ex_pipe();
    ex_sockpair();
    ex_fifo();
    ex_mqueue();
    ex_dgramsocket();
    ex_tundevice();

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
