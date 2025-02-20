#include "event_engine.hpp"

#include <signal.h>
#include <stdio.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <chrono>

#include "signalfd.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

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

#if 0
struct timer_event : public event
{
    timer_event(engine& eng)
        : event(eng)
    {
        fd_ = timerfd_create(CLOCK_MONOTONIC, 0);
        reset_timer();
        engine_->register_event(fd_, this);
    }

    void top_half(int) override
    {
        int64_t count;
        read(fd_, &count, sizeof(count));
        engine_->deregister_event(fd_);
        printf("%05ld (timer  top): timer expired\n", gettid());
    }

    void bottom_half(int) override
    {
        printf("%05ld (timer  bot): set new timer\n", gettid());
        reset_timer();
        engine_->register_event(fd_, this);
    }

    void reset_timer()
    {
        // clang-format off
        struct itimerspec t{{0, 0}, {1, 0}};
        // clang-format on
        timerfd_settime(fd_, 0, &t, nullptr);
    }
};
#endif

struct signal_event : public event
{
    tbd::signalfd sigfd_;
    int last_sig_;

    signal_event(engine& eng)
        : event(eng)
        , sigfd_({SIGHUP, SIGQUIT})
    {
        fd_ = sigfd_.handle();
        engine_->register_event(this);
    }

    void top_half(int, bool) override
    {
        last_sig_ = sigfd_.get_last_signal();
        engine_->deregister_event(this);

        if (last_sig_ == SIGQUIT) {
            LOG("(signal top): receive signal: %s, exit\n", strsignal(last_sig_));
            throw 1;
        }
    }

    void bottom_half(int, bool) override
    {
        LOG("(signal bot): receive signal: %s\n", strsignal(last_sig_));
        engine_->register_event(this);
    }
};

struct socket_event : public event
{
    int peer_fd_;
    char msgbuf_[1024];

    socket_event(engine& eng)
        : event(eng)
    {
        int fds[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        fd_ = fds[0];
        peer_fd_ = fds[1];

        engine_->register_event(this, 1000);
    }

    ~socket_event()
    {
        close(peer_fd_);
    }

    void top_half(int, bool timedout) override
    {
        if (!timedout) {
            auto nread = read(fd_, msgbuf_, sizeof(msgbuf_));
            msgbuf_[nread] = '\0';
            LOG("(socket top): fd=%d, receive message: %s\n", fd_, msgbuf_);
        }
    }

    void bottom_half(int, bool timedout) override
    {
        if (timedout) {
            LOG("(socket bot): fd=%d, timed out!\n", fd_);
        } else {
            auto ms = random() % 1000;
            LOG("(socket bot): fd=%d, work for %ld ms ...\n", fd_, ms);
            usleep(ms * 1000);
            LOG("(socket bot): fd=%d, work done\n", fd_);
        }

        if (fd_ >= 0) {
            engine_->register_event(this, 1000);
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
        pool_.submit([ev, timedout] { ev->bottom_half(ev->handle(), timedout); });
    }
};

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

    // timer_event timer(eng);
    signal_event sigev(eng);
    socket_event sock(eng);
    socket_event sock2(eng);
    socket_event sock3(eng);
    socket_event sock4(eng);

    thread_pool pool(2);

    pool.submit([] {
        for (auto i = 0; i < 10; ++i) {
            usleep((1000 + random() % 5000) * 1000);
            kill(getpid(), SIGHUP);
        }

        usleep((1000 + random() % 5000) * 1000);
        kill(getpid(), SIGQUIT);
    });

    bool running = true;
    pool.submit([&] {
        while (running) {
            usleep((random() % 1000) * 1000);
            auto target = random() % 4;
            if (target == 0) {
                sock.send("Hello!");
            } else if (target == 1) {
                sock2.send("World!");
            } else if (target == 2) {
                sock3.send("Foobar!");
            } else {
                sock4.send("Hoge-Piyo!");
            }
        }
    });

    try {
        eng.run_loop();
    } catch (...) {
        // ignore
    }

    running = false;
}
