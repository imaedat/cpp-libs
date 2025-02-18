#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <cstring>
#include <system_error>

namespace tbd {

namespace detail {
void close(int& fd)
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}
}  // namespace detail

class engine;
class event
{
  public:
    event(const event&) = delete;
    event& operator=(const event&) = delete;
    event(event&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    event& operator=(event&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
            swap(engine_, rhs.engine_);
        }
        return *this;
    }

    virtual ~event()
    {
        detail::close(fd_);
    }

    int handle() const noexcept
    {
        return fd_;
    }

    virtual void top_half(int)
    {
        // urgent work
    }

    virtual void bottom_half(int)
    {
        // non-urgent, follow-up work
    }

  protected:
    int fd_ = -1;
    engine* engine_ = nullptr;

    event(engine& eng)
        : engine_(&eng)
    {}
};

class engine
{
  public:
    engine()
        : epollfd_(::epoll_create1(0))
    {
        if (epollfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    virtual ~engine()
    {
        detail::close(epollfd_);
    }

    void register_event(int fd, event* ev, bool oneshot = true)
    {
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        eev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | (oneshot ? EPOLLONESHOT : 0U);
        eev.data.ptr = ev;
        int op = EPOLL_CTL_ADD;
    again:
        int ret = ::epoll_ctl(epollfd_, op, fd, &eev);
        if (ret < 0) {
            if (errno == EEXIST) {
                op = EPOLL_CTL_MOD;
                goto again;
            }
            throw std::system_error(errno, std::generic_category());
        }
    }

    void deregister_event(int fd)
    {
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void run_one(int wait_ms = -1)
    {
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        int nfds = ::epoll_wait(epollfd_, &eev, 1, wait_ms);
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        if (nfds == 0) {
            return;
        }

        assert(nfds == 1);
        auto* ev = (event*)eev.data.ptr;
        ev->top_half(ev->handle());

        exec_bh(ev);
    }

    void run_loop()
    {
        while (true) {
            run_one();
        }
    }

  protected:
    int epollfd_ = -1;

    virtual void exec_bh(event* ev)
    {
        ev->bottom_half(ev->handle());
    }
};

}  // namespace tbd

#endif
