#include "event_engine.hpp"

#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <vector>

#include "signalfd.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

#if 0
#define gettid() syscall(SYS_gettid)

inline char* now()
{
    thread_local char buf[32] = {0};

    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    auto sec = count / (1000 * 1000);
    auto usec = count % (1000 * 1000);
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, 21, "%F %T.", &tm);
    sprintf(buf + 20, "%06ld", usec);
    return buf;
}

#define LOG(fmt, ...) printf("%s [%04ld] " fmt, now(), gettid(), ##__VA_ARGS__)
#endif

struct signal_event : public event
{
    tbd::signalfd sigfd_;
    engine* engine_;
    int last_sig_;

    signal_event(engine& eng)
        : sigfd_({SIGHUP, SIGQUIT})
        , engine_(&eng)
    {
        fd_ = sigfd_.handle();
        oneshot_ = false;
        engine_->register_event(this);
    }

    void top_half(bool) override
    {
        last_sig_ = sigfd_.get_last_signal();
        engine_->deregister(this);

        if (last_sig_ == SIGQUIT) {
            LOG("(signal top): receive signal: %s, exit\n", strsignal(last_sig_));
            throw 1;
        }
    }

    void bottom_half(bool) override
    {
        LOG("(signal bot): receive signal: %s\n", strsignal(last_sig_));
        engine_->register_event(this);
    }
};

struct socket_event : public event
{
    int peer_fd_;
    char msgbuf_[1024];
    engine* engine_;
    steady_clock::time_point timer_start_;
    bool recv_waiting_ = true;

    inline static constexpr long timeout_ms = 5000;
    // inline static constexpr long timeout_ms = 10;

    socket_event(engine& eng)
        : engine_(&eng)
    {
        int fds[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        fd_ = fds[0];
        peer_fd_ = fds[1];

        engine_->register_event(this, timeout_ms);
        timer_start_ = steady_clock::now();
    }

    socket_event(const socket_event&) = delete;
    socket_event(socket_event&&) = default;

    ~socket_event()
    {
        close(peer_fd_);
    }

    void top_half(bool timedout) override
    {
        if (timedout) {
#if 0
            engine_->deregister(this);
#endif
            LOG("(socket top): fd=%d, --- timed out! ---\n", fd_);
        } else {
            auto nread = read(fd_, msgbuf_, sizeof(msgbuf_));
            msgbuf_[nread] = '\0';
            LOG("(socket top): fd=%d, receive message: %s\n", fd_, msgbuf_);
        }
    }

    void bottom_half(bool timedout) override
    {
        auto elapsed = duration_cast<milliseconds>(steady_clock::now() - timer_start_).count();
        long wait_ms = timeout_ms;
        if (timedout) {
            if (recv_waiting_) {
                LOG("(socket bot): fd=%d, --- TIMED OUT! --- (elapsed [%lu])\n", fd_, elapsed);
            } else {
                LOG("(socket bot): fd=%d, work done (elapsed [%lu])\n", fd_, elapsed);
                recv_waiting_ = true;
            }
        } else {
            wait_ms = random() % 1000;
            // wait_ms = 10;
            LOG("(socket bot): fd=%d, work for %ld ms ...\n", fd_, wait_ms);
            recv_waiting_ = false;
        }

        if (fd_ >= 0) {
            if (timedout) {
                engine_->register_event(this, wait_ms);
            } else {
                engine_->register_timer(this, wait_ms);
            }
            timer_start_ = steady_clock::now();
        }
    }

    void send(string_view msg)
    {
        write(peer_fd_, msg.data(), msg.size());
    }
};

struct multithreaded_engine : public engine
{
    thread_pool pool_{4};

    void exec_bh(event* ev, bool timedout) override
    {
        pool_.submit([ev, timedout] { ev->bottom_half(timedout); });
    }
};

#define NSOCKS 100
// #define NSOCKS 2
#define MAXWAIT 100
#define NSIGHUPS 1000

int main()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGQUIT);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    srandom(time(nullptr));

    // engine eng;
    multithreaded_engine eng;

    signal_event sigev(eng);
    std::vector<socket_event> socks;
    socks.reserve(NSOCKS);
    for (size_t i = 0; i < NSOCKS; ++i) {
        socks.emplace_back(eng);
    }
    static constexpr const char* msg[] = {
        "AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDDDDDD", "EEEEEEEE", "FFFFFFFF", "GGGGGGGG",
        "HHHHHHHH", "IIIIIIII", "JJJJJJJJ", "KKKKKKKK", "LLLLLLLL", "MMMMMMMM", "NNNNNNNN",
        "OOOOOOOO", "PPPPPPPP", "QQQQQQQQ", "RRRRRRRR", "SSSSSSSS", "TTTTTTTT", "UUUUUUUU",
        "VVVVVVVV", "WWWWWWWW", "XXXXXXXX", "YYYYYYYY", "ZZZZZZZZ",
    };
    static constexpr size_t nmsgs = sizeof(msg) / sizeof(msg[0]);

    thread_pool pool(2);

    pool.submit([] {
        for (auto i = 0; i < NSIGHUPS; ++i) {
            usleep((1000 + random() % 5000) * 1000);
            kill(getpid(), SIGHUP);
        }

        usleep((1000 + random() % 5000) * 1000);
        kill(getpid(), SIGQUIT);
    });

    bool running = true;
    pool.submit([&] {
        while (running) {
            usleep((1 + random() % (MAXWAIT - 1)) * 1000);
            // usleep(10 * 1000);
            unsigned i = random() % NSOCKS;
            socks[i].send(msg[i % nmsgs]);
        }
    });

    try {
        eng.run_loop();
    } catch (...) {
        // ignore
    }

    running = false;
}
