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

struct signal_event : public event
{
    int last_sig_;

    signal_event(engine& eng)
        : event(eng)
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGHUP);
        sigaddset(&mask, SIGQUIT);
        fd_ = signalfd(-1, &mask, 0);

        engine_->register_event(fd_, this);
    }

    void top_half(int) override
    {
        struct signalfd_siginfo siginfo;
        read(fd_, &siginfo, sizeof(siginfo));
        engine_->deregister_event(fd_);

        last_sig_ = siginfo.ssi_signo;

        if (last_sig_ == SIGQUIT) {
            printf("%05ld (signal top): receive signal: %s, exit\n", gettid(),
                   strsignal(last_sig_));
            throw 1;
        }
    }

    void bottom_half(int) override
    {
        printf("%05ld (signal bot): receive signal: %s\n", gettid(), strsignal(last_sig_));
        engine_->register_event(fd_, this);
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

        engine_->register_event(fd_, this);
    }

    ~socket_event()
    {
        close(peer_fd_);
    }

    void top_half(int) override
    {
        auto nread = read(fd_, msgbuf_, sizeof(msgbuf_));
        engine_->deregister_event(fd_);
        msgbuf_[nread] = '\0';
        printf("%05ld (socket top): receive message: %s\n", gettid(), msgbuf_);
    }

    void bottom_half(int) override
    {
        auto ms = random() % 1000;
        printf("%05ld (socket bot): work for %ld ms ...\n", gettid(), ms);
        usleep(ms * 1000);
        engine_->register_event(fd_, this);
    }

    void send(string_view msg)
    {
        write(peer_fd_, msg.data(), msg.size());
    }
};

struct multithreaded_engine : public engine
{
    thread_pool pool_{4};

    void exec_bh(event* ev) override
    {
        pool_.submit([ev] { ev->bottom_half(ev->handle()); });
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

    timer_event timer(eng);
    signal_event sigev(eng);
    socket_event sock(eng);

    thread_pool pool;

    pool.submit([] {
        for (auto i = 0; i < 4; ++i) {
            usleep((1000 + random() % 5000) * 1000);
            kill(getpid(), SIGHUP);
        }

        usleep((1000 + random() % 5000) * 1000);
        kill(getpid(), SIGQUIT);
    });

    bool running = true;
    pool.submit([&sock, &running] {
        while (running) {
            usleep((random() % 3000) * 1000);
            sock.send("Hello!");
        }
    });

    try {
        eng.run_loop();
    } catch (...) {
        // ignore
    }

    running = false;
    pool.force_stop();
}
