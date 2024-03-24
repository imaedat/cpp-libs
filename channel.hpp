#ifndef CHANNEL_HPP_
#define CHANNEL_HPP_

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace tbd {

// multi-producer, single-consumer channel

template <typename T> class sender;
template <typename T> class receiver;

template <typename T>
std::pair<sender<T>, receiver<T>> new_channel()
{
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
        throw std::system_error(errno, std::generic_category());
    }
    return {sender<T>(sv[0]), receiver<T>(sv[1])};
}

// non-copyable, but movable
template <typename T>
class receiver
{
  public:
    receiver(const receiver&)
#ifdef CHANNEL_ENABLE_COPY_CONSTRUCTIBLE
    {
        throw std::logic_error("!!! receiver copy ctor should not be called !!!");
    }
#else
        = delete;
#endif
    receiver& operator=(const receiver&) = delete;
    receiver(receiver&& rhs)
    {
        *this = std::move(rhs);
    }
    receiver& operator=(receiver&& rhs)
    {
        if (this != &rhs) {
            fd_ = rhs.fd_;
            rhs.fd_ = -1;
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

    T recv() const
    {
        T msg;
        if (::read(fd_, &msg, sizeof(T)) < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        return msg;
    }

    int native_handle() const
    {
        return fd_;
    }

  private:
    int fd_ = -1;
    explicit receiver(int fd) : fd_(fd) {}

    friend std::pair<sender<T>, receiver<T>> new_channel<T>();
};

// copyable
template <typename T>
class sender
{
  public:
    sender(const sender& rhs)
    {
        *this = rhs;
    }
    sender& operator=(const sender& rhs)
    {
        if (this != &rhs) {
            fd_ = rhs.fd_;
        }
        return *this;
    }
    sender(sender&& rhs)
    {
        *this = std::move(rhs);
    }
    sender& operator=(sender&& rhs)
    {
        if (this != &rhs) {
            fd_.swap(rhs.fd_);
        }
        return *this;
    }
    ~sender()
    {
        // FIXME not thread-safe
        if (!!fd_ && *fd_ >= 0 && fd_.use_count() == 1) {
            ::close(*fd_);
            fd_.reset();
        }
    }

    void send(const T& msg) const
    {
        if (::write(*fd_, &msg, sizeof(T)) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

  private:
    std::shared_ptr<int> fd_;
    explicit sender(int fd) : fd_(new int(fd)) {}

    friend std::pair<sender<T>, receiver<T>> new_channel<T>();
};

}  // namespace tbd

#endif
