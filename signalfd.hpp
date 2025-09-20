#ifndef SIGNALFD_HPP_
#define SIGNALFD_HPP_

#include <fcntl.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <system_error>
#include <vector>

namespace tbd {

class signalfd
{
  public:
    explicit signalfd(const std::vector<int>& signals)
    {
        sigset_t mask;
        sigemptyset(&mask);
        for (auto sig : signals) {
            sigaddset(&mask, sig);
        }
        fd_ = ::signalfd(-1, &mask, 0);
    }

    signalfd(const signalfd&) = delete;
    signalfd& operator=(const signalfd&) = delete;
    signalfd(signalfd&& rhs) noexcept
        : fd_(std::exchange(rhs.fd_, -1))
    {
    }
    signalfd& operator=(signalfd&& rhs) noexcept
    {
        if (this != &rhs) {
            close_();
            fd_ = std::exchange(rhs.fd_, -1);
        }
        return *this;
    }

    ~signalfd() noexcept
    {
        close_();
    }

    int handle() const noexcept
    {
        return fd_;
    }

    void set_nonblock(bool set = true)
    {
        int ret = ::fcntl(fd_, F_GETFL, nullptr);
        if (ret >= 0) {
            int flags = set ? (ret | O_NONBLOCK) : (ret & ~O_NONBLOCK);
            if (::fcntl(fd_, F_SETFL, flags) == 0) {
                return;
            }
        }
        throw std::system_error(errno, std::generic_category());
    }

    int get_last_signal() const
    {
        struct signalfd_siginfo siginfo;
        auto nread = ::read(fd_, &siginfo, sizeof(siginfo));
        if (nread < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        return siginfo.ssi_signo;
    }

  private:
    int fd_ = -1;

    void close_() noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
};

}  // namespace tbd

#endif
