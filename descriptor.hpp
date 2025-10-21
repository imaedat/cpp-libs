#ifndef DESCRIPTOR_HPP_
#define DESCRIPTOR_HPP_

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tbd {

/****************************************************************************
 * base classes
 */
namespace detail {
[[noreturn]] void throw_syserr(int err, std::string_view fn = "")
{
    throw std::system_error(err, std::generic_category(), fn.data());
}

class fd_wrapper
{
  public:
    fd_wrapper() noexcept = default;
    fd_wrapper(int fd)
        : fd_(fd)
    {
        if (fd_ < 0) {
            throw_syserr(errno ? errno : EBADF);
        }
    }

    fd_wrapper(const fd_wrapper&) = delete;
    fd_wrapper& operator=(const fd_wrapper&) = delete;
    fd_wrapper(fd_wrapper&& rhs) noexcept
        : fd_(std::exchange(rhs.fd_, -1))
    {
    }
    fd_wrapper& operator=(fd_wrapper&& rhs) noexcept
    {
        if (this != &rhs) {
            close();
            fd_ = std::exchange(rhs.fd_, -1);
        }
        return *this;
    }

    ~fd_wrapper() noexcept
    {
        close();
    }

    int release() noexcept
    {
        return std::exchange(fd_, -1);
    }

    void close() noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    explicit operator bool() const noexcept
    {
        return fd_ >= 0;
    }

    explicit operator int() const noexcept
    {
        return fd_;
    }

    int operator*() const noexcept
    {
        return fd_;
    }

  private:
    int fd_ = -1;
};
}  // namespace detail

class descriptor
{
  public:
    explicit descriptor(int fd)
        : fd_(fd)
    {
    }
    descriptor(descriptor&&) noexcept = default;
    descriptor& operator=(descriptor&&) noexcept = default;
    virtual ~descriptor() noexcept = default;

    void close() noexcept
    {
        fd_.close();
    }

    int handle() const noexcept
    {
        return (int)fd_;
    }

    int operator*() const noexcept
    {
        return (int)fd_;
    }

    int set_nonblock(bool set = true) const
    {
        int old_flags = ::fcntl(*fd_, F_GETFL);
        if (old_flags < 0) {
            detail::throw_syserr(errno, "fcntl");
        }

        if ((set && !(old_flags & O_NONBLOCK)) || (!set && (old_flags & O_NONBLOCK))) {
            if (::fcntl(*fd_, F_SETFL,
                        (set ? (old_flags | O_NONBLOCK) : (old_flags & ~O_NONBLOCK))) < 0) {
                detail::throw_syserr(errno, "fcntl");
            }
        }

        return old_flags;
    }

    bool is_nonblock() const
    {
        int flags = ::fcntl(*fd_, F_GETFL);
        if (flags < 0) {
            detail::throw_syserr(errno, "fcntl");
        }
        return !!(flags & O_NONBLOCK);
    }

    bool wait_readable(int timeout_ms = -1) const
    {
        return poll_(POLLIN | POLLRDHUP, timeout_ms);
    }

    bool is_readable() const
    {
        return wait_readable(0);
    }

    bool wait_writable(int timeout_ms = -1) const
    {
        return poll_(POLLOUT, timeout_ms);
    }

    bool is_writable() const
    {
        return wait_writable(0);
    }

    virtual size_t read(void* buffer, size_t size) const
    {
        ssize_t nread = 0;
        if ((nread = ::read(*fd_, buffer, size)) < 0) {
            detail::throw_syserr(errno, "read");
        }
        return (size_t)nread;
    }

    virtual size_t write(const void* buffer, size_t size) const
    {
        ssize_t nwritten = 0;
        if ((nwritten = ::write(*fd_, buffer, size)) < 0) {
            detail::throw_syserr(errno, "write");
        }
        return (size_t)nwritten;
    }

  protected:
    detail::fd_wrapper fd_;

    descriptor() noexcept = default;

    bool poll_(int events, int timeout_ms = 0) const
    {
        struct pollfd fds;
        fds.fd = (int)fd_;
        fds.events = events;
        fds.revents = 0;
        int nfds = ::poll(&fds, 1, timeout_ms);
        if (nfds < 0 || fds.revents & POLLNVAL) {
            detail::throw_syserr((nfds < 0) ? errno : EINVAL, "poll");
        }
        return nfds >= 1;
    }
};

/****************************************************************************
 * communication channels
 */
std::pair<descriptor, descriptor> make_pipe()
{
    int fds[2];
    if (::pipe(fds) < 0) {
        detail::throw_syserr(errno, "pipe");
    }
    // { reader, writer }
    return {descriptor(fds[0]), descriptor(fds[1])};
}

std::pair<descriptor, descriptor> make_socketpair()
{
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        detail::throw_syserr(errno, "socketpair");
    }
    return {descriptor(sv[0]), descriptor(sv[1])};
}

class fifo : public descriptor
{
  public:
    explicit fifo(std::string_view path, int open_flag = O_RDONLY | O_NONBLOCK)
        : path_(path)
    {
        if (::mkfifo(path_.c_str(), 0666) < 0) {
            if (errno != EEXIST) {
                detail::throw_syserr(errno, "mkfifo");
            }
        }
        fd_ = detail::fd_wrapper(::open(path_.c_str(), open_flag));
    }

    fifo(fifo&&) noexcept = default;
    fifo& operator=(fifo&&) noexcept = default;

    ~fifo() noexcept
    {
        ::unlink(path_.c_str());
    }

  private:
    std::string path_;
};

class mqueue : public descriptor
{
  public:
    explicit mqueue(std::string_view name)
        : name_(name)
    {
        fd_ = detail::fd_wrapper(::mq_open(name_.c_str(), O_RDWR | O_CREAT, 0666, nullptr));
        if (::mq_getattr(*fd_, &attr_) < 0) {
            detail::throw_syserr(errno, "mq_getattr");
        }
    }

    mqueue(std::string_view name, size_t maxmsg, size_t msgsize)
        : name_(name)
    {
        attr_.mq_maxmsg = maxmsg;
        attr_.mq_msgsize = msgsize;
        fd_ = detail::fd_wrapper(::mq_open(name_.c_str(), O_RDWR | O_CREAT, 0666, &attr_));
        if (::mq_getattr(*fd_, &attr_) < 0) {
            detail::throw_syserr(errno, "mq_getattr");
        }
    }

    mqueue(mqueue&&) noexcept = default;
    mqueue& operator=(mqueue&&) noexcept = default;

    ~mqueue() noexcept
    {
        ::mq_unlink(name_.c_str());
    }

    size_t maxmsg() const noexcept
    {
        return attr_.mq_maxmsg;
    }

    size_t msgsize() const noexcept
    {
        return attr_.mq_msgsize;
    }

    size_t read(void* buffer, size_t size, unsigned* prio) const
    {
        ssize_t nread = 0;
        if ((nread = ::mq_receive(*fd_, (char*)buffer, size, prio)) < 0) {
            detail::throw_syserr(errno, "mq_receive");
        }
        return (size_t)nread;
    }

    size_t read(void* buffer, size_t size) const override
    {
        return read(buffer, size, nullptr);
    }

    size_t write(const void* buffer, size_t size, unsigned prio) const
    {
        int nwritten = 0;
        if ((nwritten = ::mq_send(*fd_, (const char*)buffer, size, prio)) < 0) {
            detail::throw_syserr(errno, "mq_send");
        }
        return (size_t)nwritten;
    }

    size_t write(const void* buffer, size_t size) const override
    {
        return write(buffer, size, 0);
    }

  private:
    std::string name_;
    struct mq_attr attr_;
};

/****************************************************************************
 * event notifying
 */
class epollfd : public descriptor
{
    static constexpr uint32_t DEFAULT_EVENTS = EPOLLIN | EPOLLRDHUP | EPOLLPRI;

  public:
    epollfd()
        : descriptor(::epoll_create1(0))
    {
    }

    epollfd(epollfd&&) noexcept = default;
    epollfd& operator=(epollfd&&) noexcept = default;

    void add(const descriptor& desc, uint32_t events = DEFAULT_EVENTS, void* ptr = nullptr)
    {
        add(*desc, events, ptr);
    }

    void add(int fd, uint32_t events = DEFAULT_EVENTS, void* ptr = nullptr)
    {
        add_or_mod(EPOLL_CTL_ADD, fd, events, ptr);
        ++nregistered_;
    }

    void mod(const descriptor& desc, uint32_t events = DEFAULT_EVENTS, void* ptr = nullptr)
    {
        mod(*desc, events, ptr);
    }

    void mod(int fd, uint32_t events = DEFAULT_EVENTS, void* ptr = nullptr)
    {
        add_or_mod(EPOLL_CTL_MOD, fd, events, ptr);
    }

    void del(const descriptor& desc)
    {
        del(*desc);
    }

    void del(int fd)
    {
        if (::epoll_ctl(*fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
            detail::throw_syserr(errno, "epoll_ctl");
        }
        --nregistered_;
    }

    struct event
    {
        uint32_t events = 0;
        int fd = -1;
        void* ptr = nullptr;
    };

    std::vector<event> wait(int timeout_ms = -1)
    {
        struct epoll_event evs[nregistered_];
        auto nfds = ::epoll_wait(*fd_, evs, nregistered_, timeout_ms);
        if (nfds < 0) {
            detail::throw_syserr(errno, "epoll_wait");
        }

        std::vector<event> events;
        events.reserve(nfds);
        for (int i = 0; i < nfds; ++i) {
            events.emplace_back(event{evs[i].events, evs[i].data.fd, evs[i].data.ptr});
        }
        return events;
    }

    size_t read(void*, size_t) = delete;
    size_t write(const void*, size_t) = delete;

  private:
    size_t nregistered_ = 0;

    void add_or_mod(int op, int fd, int events, void* ptr)
    {
        struct epoll_event ev = {};
        ev.events = events;
        if (ptr) {
            ev.data.ptr = ptr;
        } else {
            ev.data.fd = fd;
        }
        if (::epoll_ctl(*fd_, op, fd, &ev) < 0) {
            detail::throw_syserr(errno, "epoll_ctl");
        }
    }
};

// extra
class poll
{
    static constexpr short DEFAULT_EVENTS = POLLIN | POLLRDHUP | POLLPRI;

  public:
    poll() noexcept = default;
    explicit poll(const descriptor& desc, short events = DEFAULT_EVENTS)
        : poll(*desc, events)
    {
    }
    explicit poll(int fd, short events = DEFAULT_EVENTS)
        : poll()
    {
        add(fd, events);
    }

    void add(const descriptor& desc, short events = DEFAULT_EVENTS)
    {
        add(*desc, events);
    }

    void add(int fd, short events = DEFAULT_EVENTS)
    {
        watchees_.emplace(fd, events);
    }

    void del(const descriptor& desc) noexcept
    {
        del(*desc);
    }

    void del(int fd) noexcept
    {
        watchees_.erase(fd);
    }

    struct revent
    {
        int fd = -1;
        short revents = 0;
    };

    std::vector<revent> wait(int timeout_ms = -1)
    {
        struct pollfd fds[watchees_.size()];
        auto it = watchees_.cbegin();
        for (size_t i = 0; i < watchees_.size(); ++i, ++it) {
            const auto& [fd, events] = *it;
            fds[i].fd = fd;
            fds[i].events = events;
            fds[i].revents = 0;
        }

        int nfds = ::poll(fds, watchees_.size(), timeout_ms);
        if (nfds < 0) {
            detail::throw_syserr(errno, "poll");
        }

        std::vector<revent> revents;
        revents.reserve(nfds);
        for (size_t i = 0; i < watchees_.size(); ++i) {
            if (fds[i].revents) {
                revents.emplace_back(revent{fds[i].fd, fds[i].revents});
            }
        }
        return revents;
    }

  private:
    std::unordered_map<int, short> watchees_;
};

class eventfd : public descriptor
{
  public:
    static constexpr uint64_t EFD_MAX_VALUE = 0xfffffffffffffffe;

    explicit eventfd(bool use_as_semaphore = false)
        : descriptor(::eventfd(0, (use_as_semaphore ? EFD_SEMAPHORE : 0)))
    {
    }

    eventfd(eventfd&&) noexcept = default;
    eventfd& operator=(eventfd&&) noexcept = default;

    uint64_t read() const
    {
        uint64_t value;
        descriptor::read(&value, sizeof(value));
        return value;
    }

    void write(uint64_t value = 1) const
    {
        descriptor::write(&value, sizeof(value));
    }
};

class memfd : public descriptor
{
  public:
    explicit memfd(std::string_view name)
        : descriptor(::memfd_create(name.data(), 0))
    {
    }

    memfd(memfd&&) noexcept = default;
    memfd& operator=(memfd&&) noexcept = default;
};

class signalfd : public descriptor
{
  public:
    explicit signalfd(const std::vector<int>& signals)
    {
        sigset_t mask;
        ::sigemptyset(&mask);
        for (auto sig : signals) {
            ::sigaddset(&mask, sig);
        }
        fd_ = detail::fd_wrapper(::signalfd(-1, &mask, 0));
    }

    signalfd(signalfd&&) noexcept = default;
    signalfd& operator=(signalfd&&) noexcept = default;

    int get_last_signal() const
    {
        struct signalfd_siginfo siginfo;
        read(&siginfo, sizeof(siginfo));
        return siginfo.ssi_signo;
    }

    size_t write(const void*, size_t) = delete;
};

class timerfd : public descriptor
{
  public:
    timerfd()
        : descriptor(::timerfd_create(CLOCK_MONOTONIC, 0))
    {
    }

    explicit timerfd(long after_ms)
        : timerfd()
    {
        settime(after_ms);
    }

    timerfd(timerfd&&) noexcept = default;
    timerfd& operator=(timerfd&&) noexcept = default;

    void settime(long after_ms, bool cyclic = false) const
    {
        static constexpr long ns_scale = 1000 * 1000 * 1000;

        clear();

        auto nsec = after_ms * 1000 * 1000;
        long sec = 0;
        if (nsec >= ns_scale) {
            sec = nsec / ns_scale;
            nsec %= ns_scale;
        }
        struct itimerspec t = {{(cyclic ? sec : 0), (cyclic ? nsec : 0)}, {sec, nsec}};
        if (::timerfd_settime(*fd_, 0, &t, nullptr) < 0) {
            detail::throw_syserr(errno, "timerfd_settime");
        }
    }

    void cancel() const
    {
        settime(0);
    }

    void clear() const
    {
        if (is_readable()) {
            uint64_t count;
            read(&count, sizeof(count));
        }
    }

    size_t write(const void*, size_t) = delete;
};

class inotify : public descriptor
{
  public:
    inotify()
        : descriptor(::inotify_init())
    {
    }

    inotify(inotify&&) noexcept = default;
    inotify& operator=(inotify&&) noexcept = default;

    void add_watch(std::string_view path, uint32_t mask)
    {
        int wd = ::inotify_add_watch(*fd_, path.data(), mask);
        if (wd < 0) {
            detail::throw_syserr(errno, "inotify_add_watch");
        }
        watches_.emplace(wd, path);
    }

    void rm_watch(std::string_view path)
    {
        auto it = std::find_if(watches_.begin(), watches_.end(),
                               [&path](const auto& pair) { return pair.second == path; });
        if (it == watches_.end()) {
            return;
        }
        int wd = it->first;
        if (::inotify_rm_watch(*fd_, wd) < 0) {
            detail::throw_syserr(errno, "inotify_rm_watch");
        }
        watches_.erase(wd);
    }

    struct event
    {
        uint32_t mask = 0;
        std::string path;
    };

    std::vector<event> read() const
    {
        static constexpr size_t STRUCT_SIZE = sizeof(struct inotify_event);
        static constexpr size_t EVENT_SIZE = STRUCT_SIZE + NAME_MAX + 1;

        std::vector<uint8_t> buffer(EVENT_SIZE);
        auto nread = descriptor::read(buffer.data(), EVENT_SIZE);

        std::vector<event> events;
        auto* p = buffer.data();
        struct inotify_event* ev = nullptr;
        for (; p < buffer.data() + nread; p += STRUCT_SIZE + ev->len) {
            ev = (struct inotify_event*)p;
            auto it = watches_.find(ev->wd);
            assert(it != watches_.end());
            std::string path = it->second;
            if (ev->len > 0) {
                path.append("/").append(ev->name);
            }
            events.emplace_back(event{ev->mask, std::move(path)});
        }

        return events;
    }

    size_t write(const void*, size_t) = delete;

  private:
    std::unordered_map<int, std::string> watches_;
};

}  // namespace tbd

/****************************************************************************
 * io_uring
 */
#include <liburing.h>
namespace tbd {
class iouring
{
  public:
    struct callback
    {
        void* data = nullptr;
        virtual ~callback() noexcept = default;
        virtual void operator()(int res) = 0;
    };

    explicit iouring(size_t entries = 256)
    {
        if (::io_uring_queue_init(entries, &ring_, 0) < 0) {
            detail::throw_syserr(errno, "io_uring_queue_init");
        }
        eventfd_.set_nonblock();
        ::io_uring_register_eventfd(&ring_, *eventfd_);
    }

    ~iouring() noexcept
    {
        ::io_uring_queue_exit(&ring_);
    }

    int handle() const noexcept
    {
        return *eventfd_;
    }

    bool prep_read(const descriptor& fd, void* buffer, size_t size, callback* cb = nullptr)
    {
        auto* sqe = ::io_uring_get_sqe(&ring_);
        if (!sqe) {
            return false;
        }
        ::io_uring_prep_read(sqe, *fd, buffer, size, 0);
        if (cb) {
            ::io_uring_sqe_set_data(sqe, cb);
        }
        return true;
    }

    void submit()
    {
        ::io_uring_submit(&ring_);
    }

    void wait_cqe()
    {
        struct io_uring_cqe* cqe;
        if (::io_uring_wait_cqe(&ring_, &cqe) < 0) {
            detail::throw_syserr(errno, "io_uring_wait_cqe");
        }
    }

    void foreach_cqe()
    {
        unsigned head;
        struct io_uring_cqe* cqe;
        io_uring_for_each_cqe(&ring_, head, cqe)
        {
            if (auto* cb = (callback*)::io_uring_cqe_get_data(cqe)) {
                (*cb)(cqe->res);
            }
            ::io_uring_cqe_seen(&ring_, cqe);
        }

        // consume eventfd
        (void)eventfd_.read();
    }

  private:
    struct io_uring ring_;
    eventfd eventfd_;
};

}  // namespace tbd

#endif
