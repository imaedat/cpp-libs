#ifndef CHANNEL_HPP_
#define CHANNEL_HPP_

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>

namespace tbd {

// multi-producer, single-consumer channel

template <typename T>
class sender;
template <typename T>
class receiver;

template <typename T>
std::pair<sender<T>, receiver<T>> new_channel()
{
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
        throw std::system_error(errno, std::generic_category());
    }
    return {sender<T>(sv[0]), receiver<T>(sv[1])};
}

template <typename T>
class receiver
{
  public:
    // not copyable
    receiver(const receiver&)
#ifdef CHANNEL_ENABLE_COPY_CONSTRUCTIBLE
    {
        throw std::logic_error("!!! receiver copy ctor should not be called !!!");
    }
#else
        = delete;
#endif
    receiver& operator=(const receiver&) = delete;

    // movable
    receiver(receiver&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    receiver& operator=(receiver&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
        }
        return *this;
    }

    ~receiver()
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    std::optional<T> recv() const
    {
        T msg;
        auto nread = ::read(fd_, &msg, sizeof(T));
        if (nread == sizeof(T)) {
            return msg;
        }

        if (nread == 0) {
            return std::nullopt;
        }

        throw std::system_error(errno, std::generic_category());
    }

    int native_handle() const
    {
        return fd_;
    }

  private:
    int fd_ = -1;
    explicit receiver(int fd) noexcept
        : fd_(fd)
    {}

    friend std::pair<sender<T>, receiver<T>> new_channel<T>();
};

template <typename T>
class sender
{
  public:
    // copyable
    sender(const sender& rhs) noexcept
    {
        *this = rhs;
    }
    sender& operator=(const sender& rhs) noexcept
    {
        if (this != &rhs && rhs.refcnt_) {
            dec_ref();
            rhs.refcnt_->fetch_add(1);
            refcnt_ = rhs.refcnt_;
            fd_ = rhs.fd_;
        }
        return *this;
    }

    // movable
    sender(sender&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    sender& operator=(sender&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(refcnt_, rhs.refcnt_);
            swap(fd_, rhs.fd_);
        }
        return *this;
    }

    ~sender()
    {
        dec_ref();
        fd_ = -1;
    }

    template <typename U,
              std::enable_if_t<std::is_same<T, typename std::remove_reference<U>::type>::value,
                               std::nullptr_t> = nullptr>
    void send(U&& msg) const
    {
        if (::write(fd_, &msg, sizeof(T)) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

  private:
    std::atomic<uint64_t>* refcnt_ = nullptr;
    int fd_ = -1;

    explicit sender(int fd)
        : refcnt_(new std::atomic<uint64_t>(1))
        , fd_(fd)
    {}

    void dec_ref()
    {
        if (refcnt_ && refcnt_->fetch_sub(1) == 1) {
            ::close(fd_);
            delete refcnt_;
            refcnt_ = nullptr;
        }
    }

    friend std::pair<sender<T>, receiver<T>> new_channel<T>();
};

}  // namespace tbd

#endif
