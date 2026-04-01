#ifndef DESCRIPTOR_HPP_
#define DESCRIPTOR_HPP_

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
#include <cassert>
#include <cerrno>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tbd {

/****************************************************************************
 * base classes
 */
namespace detail {
[[noreturn]] inline void throw_syserr(int err, std::string_view fn = "")
{
    throw std::system_error(err, std::generic_category(), fn.data());
}

class fd_wrapper
{
  public:
    fd_wrapper() noexcept = default;
    explicit fd_wrapper(int fd)
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
inline std::pair<descriptor, descriptor> make_pipe()
{
    int fds[2];
    if (::pipe(fds) < 0) {
        detail::throw_syserr(errno, "pipe");
    }
    // { reader, writer }
    return {descriptor(fds[0]), descriptor(fds[1])};
}

inline std::pair<descriptor, descriptor> make_socketpair()
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

    fifo(fifo&& rhs) noexcept
        : descriptor(std::move(rhs))
        , path_(std::exchange(rhs.path_, ""))
    {
    }
    fifo& operator=(fifo&& rhs) noexcept
    {
        if (this != &rhs) {
            unlink_();
            descriptor::operator=(std::move(rhs));
            path_ = std::exchange(rhs.path_, "");
        }
        return *this;
    }

    ~fifo() noexcept
    {
        unlink_();
    }

  private:
    std::string path_;

    void unlink_()
    {
        if (!path_.empty()) {
            ::unlink(path_.c_str());
            path_.clear();
        }
    }
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

    mqueue(mqueue&& rhs) noexcept
        : descriptor(std::move(rhs))
        , name_(std::exchange(rhs.name_, ""))
        , attr_(std::exchange(rhs.attr_, {}))
    {
    }
    mqueue& operator=(mqueue&& rhs) noexcept
    {
        if (this != &rhs) {
            unlink_();
            descriptor::operator=(std::move(rhs));
            name_ = std::exchange(rhs.name_, "");
            attr_ = std::exchange(rhs.attr_, {});
        }
        return *this;
    }

    ~mqueue() noexcept
    {
        unlink_();
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
        if (::mq_send(*fd_, (const char*)buffer, size, prio) < 0) {
            detail::throw_syserr(errno, "mq_send");
        }
        return size;
    }

    size_t write(const void* buffer, size_t size) const override
    {
        return write(buffer, size, 0);
    }

  private:
    std::string name_;
    struct mq_attr attr_ = {};

    void unlink_()
    {
        if (!name_.empty()) {
            ::mq_unlink(name_.c_str());
            name_.clear();
        }
    }
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

    void del(const descriptor& desc, std::error_code& ec) noexcept
    {
        del(*desc, ec);
    }

    void del(int fd, std::error_code& ec) noexcept
    {
        if (::epoll_ctl(*fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
            ec = std::error_code(errno, std::generic_category());
            return;
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
        std::vector<event> events;
        if (nregistered_ > 0) {
            events_.resize(nregistered_);

        again:
            auto nfds = ::epoll_wait(*fd_, events_.data(), nregistered_, timeout_ms);
            if (nfds < 0) {
                if (errno == EINTR) {
                    goto again;
                }
                detail::throw_syserr(errno, "epoll_wait");
            }

            events.reserve(nfds);
            for (int i = 0; i < nfds; ++i) {
                events.emplace_back(
                    event{events_[i].events, events_[i].data.fd, events_[i].data.ptr});
            }
        }
        return events;
    }

    size_t read(void*, size_t) = delete;
    size_t write(const void*, size_t) = delete;

  private:
    size_t nregistered_ = 0;
    std::vector<struct epoll_event> events_;

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

    std::vector<revent> wait(int timeout_ms = -1) const
    {
        std::vector<revent> revents;
        if (!watchees_.empty()) {
            std::vector<struct pollfd> fds(watchees_.size());
            auto it = watchees_.cbegin();
            for (size_t i = 0; i < watchees_.size(); ++i, ++it) {
                const auto& [fd, events] = *it;
                fds[i].fd = fd;
                fds[i].events = events;
                fds[i].revents = 0;
            }

        again:
            int nfds = ::poll(fds.data(), watchees_.size(), timeout_ms);
            if (nfds < 0) {
                if (errno == EINTR) {
                    goto again;
                }
                detail::throw_syserr(errno, "poll");
            }

            revents.reserve(nfds);
            for (size_t i = 0; i < watchees_.size(); ++i) {
                if (fds[i].revents) {
                    revents.emplace_back(revent{fds[i].fd, fds[i].revents});
                }
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
        uint64_t value = 0;
        descriptor::read(&value, sizeof(value));
        return value;
    }

    void write(uint64_t value = 1) const
    {
        descriptor::write(&value, sizeof(value));
    }
};

class signalfd : public descriptor
{
  public:
    explicit signalfd(const std::vector<int>& signals, bool block_on_ctor = true)
    {
        sigset_t mask;
        ::sigemptyset(&mask);
        for (auto sig : signals) {
            ::sigaddset(&mask, sig);
        }
        if (block_on_ctor && ::pthread_sigmask(SIG_BLOCK, &mask, nullptr) < 0) {
            detail::throw_syserr(errno, "pthread_sigmask");
        }
        fd_ = detail::fd_wrapper(::signalfd(-1, &mask, 0));
    }

    signalfd(signalfd&&) noexcept = default;
    signalfd& operator=(signalfd&&) noexcept = default;

    int get_last_signal() const
    {
        struct signalfd_siginfo siginfo = {};
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
        static constexpr long long ns_scale = 1000 * 1000 * 1000;

        clear();

        auto nsec = 1000LL * 1000 * after_ms;
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
            (void)read();
        }
    }

    uint64_t read() const
    {
        uint64_t count = 0;
        descriptor::read(&count, sizeof(count));
        return count;
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

/****************************************************************************
 * memory io
 */
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

class memmap : public descriptor
{
  public:
    explicit memmap(std::string_view filename, size_t length = 0, int prot = PROT_READ,
                    int flags = MAP_PRIVATE)
        : memmap(::open(filename.data(), O_RDONLY), length, prot, flags)
    {
    }

    memmap(memmap&& rhs) noexcept
        : descriptor(std::move(rhs))
        , length_(std::exchange(rhs.length_, 0))
        , area_(std::exchange(rhs.area_, nullptr))
    {
    }
    memmap& operator=(memmap&& rhs) noexcept
    {
        if (this != &rhs) {
            unmap_();
            descriptor::operator=(std::move(rhs));
            length_ = std::exchange(rhs.length_, 0);
            area_ = std::exchange(rhs.area_, nullptr);
        }
        return *this;
    }

    ~memmap() noexcept
    {
        unmap_();
    }

    void* data() noexcept
    {
        return area_;
    }

    size_t length() const noexcept
    {
        return length_;
    }

  protected:
    memmap(int fd, size_t length, int prot = PROT_READ | PROT_WRITE, int flags = MAP_SHARED)
        : descriptor(fd)
        , length_(length)
    {
        if (length_ == 0) {
            struct stat sb;
            if (::fstat(*fd_, &sb) < 0) {
                throw std::system_error(errno, std::generic_category());
            }
            length_ = sb.st_size;
        }

        if ((area_ = ::mmap(nullptr, length_, prot, flags, *fd_, 0)) == MAP_FAILED) {
            throw std::system_error(errno, std::generic_category());
        }

        if (prot == PROT_READ) {
            (void)::posix_madvise(area_, length_, POSIX_MADV_WILLNEED);
        }
    }

  private:
    size_t length_ = 0;
    void* area_ = nullptr;

    void unmap_() noexcept
    {
        if (area_) {
            ::munmap(area_, length_);
            area_ = nullptr;
        }
    }
};

class shmem : public memmap
{
    static constexpr size_t LENGTH = 4096;

  public:
    explicit shmem(std::string_view name, size_t length = LENGTH, int oflag = O_RDWR | O_CREAT)
        : memmap(shmem_init(name, length, oflag), length, PROT_READ | PROT_WRITE, MAP_SHARED)
        , name_(name)
    {
    }

    shmem(shmem&& rhs) noexcept
        : memmap(std::move(rhs))
        , name_(std::exchange(rhs.name_, ""))
    {
    }
    shmem& operator=(shmem&& rhs) noexcept
    {
        if (this != &rhs) {
            unlink_();
            memmap::operator=(std::move(rhs));
            name_ = std::exchange(rhs.name_, "");
        }
        return *this;
    }

    ~shmem() noexcept
    {
        unlink_();
    }

  private:
    std::string name_;

    void unlink_() noexcept
    {
        if (!name_.empty()) {
            ::shm_unlink(name_.c_str());
            name_.clear();
        }
    }

    static int shmem_init(std::string_view name, size_t length, int oflag)
    {
        int fd = ::shm_open(name.data(), oflag, 0666);
        if (fd < 0) {
            detail::throw_syserr(errno, "shm_open");
        }
        if (::ftruncate(fd, length) < 0) {
            detail::throw_syserr(errno, "ftruncate");
        }
        return fd;
    }
};

}  // namespace tbd

#endif
