#ifndef TIMERFD_HPP_
#define TIMERFD_HPP_

#include <fcntl.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <system_error>

namespace tbd {

class timerfd
{
  public:
    timerfd() : fd_(::timerfd_create(CLOCK_MONOTONIC, 0))
    {
        if (fd_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "timerfd::timerfd: timerfd_create");
        }
    }

    explicit timerfd(long after_ms) : timerfd()
    {
        settime(after_ms);
    }

    timerfd(const timerfd&) = delete;
    timerfd& operator=(const timerfd&) = delete;

    timerfd(timerfd&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    timerfd& operator=(timerfd&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
        }
        return *this;
    }

    ~timerfd()
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int handle() const noexcept
    {
        return fd_;
    }

    void set_nonblock(bool set = true)
    {
        if (::fcntl(fd_, F_SETFL, (set ? O_NONBLOCK : 0)) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "timerfd::set_nonblock: fcntl");
        }
    }

    void settime(long after_ms, bool cyclic = false)
    {
        static constexpr long ns_scale = 1000 * 1000 * 1000;

        auto nsec = after_ms * 1000 * 1000;
        long sec = 0;
        if (nsec >= ns_scale) {
            sec = nsec / ns_scale;
            nsec %= ns_scale;
        }
        struct itimerspec t{{(cyclic ? sec : 0), (cyclic ? nsec : 0)}, {sec, nsec}};
        if (::timerfd_settime(fd_, 0, &t, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "timerfd::settime: timerfd_settime");
        }
    }

    void cancel()
    {
        struct itimerspec t{{0, 0}, {0, 0}};
        if (::timerfd_settime(fd_, 0, &t, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "timerfd::cancel: timerfd_settime");
        }
    }

    void clear() noexcept
    {
        uint64_t count;
        (void)::read(fd_, &count, sizeof(count));
    }

  private:
    int fd_ = -1;
};

}  // namespace tbd

#endif
