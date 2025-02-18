#include "event_engine.hpp"

#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "thread_pool.hpp"

using namespace std;
using namespace tbd;

#define gettid() syscall(SYS_gettid)

struct socket_event : public event
{
    int fd_;
    int peer_fd_;
    engine* eng_;

    socket_event(engine& eng)
        : eng_(&eng)
    {
        int fds[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        fd_ = fds[0];
        peer_fd_ = fds[1];

        eng_->register_event(fd_, this);
    }

    int handle() const noexcept override
    {
        return fd_;
    }

    void top_half(int) override
    {
        //
    }

    void bottom_half(int) override
    {
        char msg[1024];
        read(fd_, msg, sizeof(msg));
        printf("%05ld (socket bot): receive message: %s\n", gettid(), msg);
        eng_->register_event(fd_, this);
    }

    void notify(string_view msg)
    {
        write(peer_fd_, msg.data(), msg.size());
    }
};

struct timer_event : public event
{
    int fd_;
    engine* eng_;

    timer_event(engine& eng)
        : fd_(::timerfd_create(CLOCK_MONOTONIC, 0))
        , eng_(&eng)
    {
        reset_timer();
        eng_->register_event(fd_, this);
    }

    int handle() const noexcept override
    {
        return fd_;
    }

    void top_half(int) override
    {
        int64_t count;
        read(fd_, &count, sizeof(count));
        // printf("%05ld (timer  top): timer expired\n", gettid());
    }

    void bottom_half(int) override
    {
        printf("%05ld (timer  bot): set new timer\n", gettid());
        reset_timer();
        eng_->register_event(fd_, this);
    }

    void reset_timer()
    {
        // clang-format off
        struct itimerspec t{{0, 0}, {1, 0}};
        // clang-format on
        timerfd_settime(fd_, 0, &t, nullptr);
    }
};

struct signal_event : public event
{
    int fd_;
    engine* eng_;

    signal_event(engine& eng)
        : eng_(&eng)
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        fd_ = signalfd(-1, &mask, 0);

        eng_->register_event(fd_, this);
    }

    int handle() const noexcept override
    {
        return fd_;
    }

    void top_half(int) override
    {
        //
    }

    void bottom_half(int) override
    {
        struct signalfd_siginfo siginfo;
        read(fd_, &siginfo, sizeof(siginfo));
        printf("%05ld (signal bot): receive signal: SIGUSR1\n", gettid());
        eng_->register_event(fd_, this);
    }
};

struct threaded_engine : public engine
{
    thread_pool pool_;

    void exec_bh(event* ev) override
    {
        pool_.submit([ev] { ev->bottom_half(ev->handle()); });
    }
};

int main()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    srandom(time(nullptr));

    // engine eng;
    threaded_engine eng;

    socket_event sock(eng);
    timer_event timer(eng);
    signal_event sigev(eng);

    thread_pool pool;

    pool.submit([&sock] {
        while (true) {
            usleep((random() % 3000) * 1000);
            sock.notify("Hello!");
        }
    });

    pool.submit([] {
        while (true) {
            usleep((1000 + random() % 5000) * 1000);
            kill(getpid(), SIGUSR1);
        }
    });

    eng.run_loop();
}
