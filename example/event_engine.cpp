#include "event_engine.hpp"

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <deque>
#include <vector>

#include "signalfd.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

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

#define LOG(fmt, ...) printf("%s [%04ld] " fmt, now(), syscall(SYS_gettid), ##__VA_ARGS__)

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
        if ((last_sig_ = sigfd_.get_last_signal()) == SIGQUIT) {
            LOG("(signal top): receive signal: %s, exit\n", strsignal(last_sig_));
            throw 1;
        }
    }

    void bottom_half(bool) override
    {
        LOG("(signal bot): receive signal: %s\n", strsignal(last_sig_));
    }
};

#undef PROVOKE_COLLISIONS

#ifdef PROVOKE_COLLISIONS
#    define TIMEOUT_MS 10
#    define WAIT_MS 10
#else
#    define TIMEOUT_MS 5000
#    define WAIT_MS (1 + random() % 999)
#endif

struct socket_event : public event
{
    enum state
    {
        IN_WAITING = 1,
        IN_WORKNG = 2,
    };

    int peer_fd_;
    char msgbuf_[1024];
    engine* engine_;
    steady_clock::time_point timer_start_;
    state state_, next_state_;

    unique_ptr<mutex> mtx_;
    deque<pair<long, string>> trace_;

    socket_event(engine& eng)
        : engine_(&eng)
        , mtx_(make_unique<typename std::decay<decltype(*mtx_)>::type>())
    {
        int fds[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        fd_ = fds[0];
        peer_fd_ = fds[1];
        oneshot_ = true;

        engine_->register_event(this, TIMEOUT_MS);
        timer_start_ = steady_clock::now();
        state_ = IN_WAITING;
    }

    socket_event(const socket_event&) = delete;
    socket_event(socket_event&&) = default;

    ~socket_event()
    {
        close(peer_fd_);
    }

    void trace(string_view point)
    {
        (void)point;
#if 1
        trace_.emplace_back(make_pair(syscall(SYS_gettid), point));
        if (trace_.size() > 20) {
            trace_.pop_front();
        }
#endif
    }

    void top_half(bool timedout) override
    {
        lock_guard<decltype(*mtx_)> lk(*mtx_);
        trace("TB");

        switch (state_) {
        case IN_WAITING:
            if (timedout) {
                trace("T1");
                LOG("(socket top): fd=%d, --- timed out! ---\n", fd_);
            } else {
                auto nread = read(fd_, msgbuf_, sizeof(msgbuf_));
                msgbuf_[nread] = '\0';
                trace("T2");
                LOG("(socket top): fd=%d, receive message: %s\n", fd_, msgbuf_);
            }
            break;

        case IN_WORKNG:
            // work done
            assert(timedout);
            trace("T3");
            break;

        default:
            break;
        }
    }

    void bottom_half(bool timedout) override
    {
        lock_guard<decltype(*mtx_)> lk(*mtx_);
        auto elapsed = duration_cast<milliseconds>(steady_clock::now() - timer_start_).count();
        int wait_ms = TIMEOUT_MS;

        switch (state_) {
        case IN_WAITING:
            if (timedout) {
                trace("B1");
                LOG("(socket bot): fd=%d, --- TIMED OUT! --- (elapsed [%lu])\n", fd_, elapsed);
                next_state_ = IN_WAITING;
            } else {
                trace("B2");
                wait_ms = WAIT_MS;
                LOG("(socket bot): fd=%d, work for %d ms ...\n", fd_, wait_ms);
                next_state_ = IN_WORKNG;
            }
            break;

        case IN_WORKNG:
            assert(timedout);
            trace("B3");
            LOG("(socket bot): fd=%d, work done (elapsed [%lu])\n", fd_, elapsed);
            next_state_ = IN_WAITING;
            break;

        default:
            break;
        }

        register_next(wait_ms);
        timer_start_ = steady_clock::now();
        state_ = next_state_;
        trace("BE");
    }

    void register_next(int wait_ms)
    {
        if (fd_ >= 0) {
            switch (next_state_) {
            case IN_WAITING:
                engine_->register_event(this, wait_ms);
                break;
            case IN_WORKNG:
                engine_->register_timer(this, wait_ms);
                break;
            default:
                break;
            }
        }
    }

    void send(string_view msg)
    {
        struct pollfd pfd;
        pfd.fd = peer_fd_;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int nfds = poll(&pfd, 1, 0);
        if (nfds < 0) {
            auto errsv = errno;
            perror("poll");
            exit(errsv);
        }
        if (nfds != 1) {
            auto elapsed = duration_cast<milliseconds>(steady_clock::now() - timer_start_).count();
            LOG("(socket bot): fd=%d, TIMER MISSING ... ? (elapsed [%lu])\n", fd_, elapsed);
            asm volatile("int3");
        }

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

#define NSIGHUPS 1000
#define MAXWAIT_MS 50

#ifdef PROVOKE_COLLISIONS
#    define NSOCKS 2
#    define INTERVAL_MS WAIT_MS
#else
#    define NSOCKS 200
#    define INTERVAL_MS (1 + random() % (MAXWAIT_MS - 1))
#endif

int main()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGTSTP);
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
            usleep(INTERVAL_MS * 1000);
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
