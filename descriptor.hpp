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
#include <sys/random.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string>
#include <system_error>
#include <type_traits>
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

class io_result
{
    std::error_code ec_{};
    ssize_t nbytes_ = 0;

  public:
    explicit io_result(int err = 0, ssize_t n = 0)
        : ec_(n < 0 ? err : 0, std::generic_category())
        , nbytes_(n)
    {
    }

    explicit operator bool() const noexcept
    {
        return !static_cast<bool>(ec_);
    }

    template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    explicit operator T() const noexcept
    {
        return static_cast<T>(nbytes());
    }

    int code() const noexcept
    {
        return ec_.value();
    }

    std::string message() const
    {
        return ec_.message();
    }

    ssize_t nbytes() const noexcept
    {
        return nbytes_;
    }

    bool would_block() const noexcept
    {
        return ec_.value() == EAGAIN || ec_.value() == EWOULDBLOCK;
    }
};

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

    explicit operator bool() const noexcept
    {
        return static_cast<bool>(fd_);
    }

    int operator*() const noexcept
    {
        return static_cast<int>(fd_);
    }

    int handle() const noexcept
    {
        return *fd_;
    }

    template <typename... Args>
    int fcntl(Args&&... args) const
    {
        int ret = ::fcntl(*fd_, args...);
        if (ret < 0) {
            detail::throw_syserr(errno, "fcntl");
        }
        return ret;
    }

    int set_nonblock(bool set = true) const
    {
        int oldflag = fcntl(F_GETFL);
        if ((set && !(oldflag & O_NONBLOCK)) || (!set && (oldflag & O_NONBLOCK))) {
            fcntl(F_SETFL, (set ? (oldflag | O_NONBLOCK) : (oldflag & ~O_NONBLOCK)));
        }
        return oldflag;
    }

    bool is_nonblock() const
    {
        return !!(fcntl(F_GETFL) & O_NONBLOCK);
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

class reader : virtual public descriptor
{
  public:
    explicit reader(int fd)
        : descriptor(fd)
    {
    }
    reader(reader&& rhs) noexcept = default;
    reader& operator=(reader&& rhs) noexcept
    {
        if (this != &rhs) {
            descriptor::operator=(std::move(rhs));
        }
        return *this;
    }

    bool wait_readable(int timeout_ms = -1) const
    {
        return poll_(POLLIN | POLLRDHUP, timeout_ms);
    }

    bool is_readable() const
    {
        return wait_readable(0);
    }

    virtual io_result read(void* buffer, size_t size) const
    {
        auto nread = ::read(*fd_, buffer, size);
        return io_result{nread < 0 ? errno : 0, nread};
    }

  protected:
    reader() = default;
};

class writer : virtual public descriptor
{
  public:
    explicit writer(int fd)
        : descriptor(fd)
    {
    }
    writer(writer&& rhs) noexcept = default;
    writer& operator=(writer&& rhs) noexcept
    {
        if (this != &rhs) {
            descriptor::operator=(std::move(rhs));
        }
        return *this;
    }

    bool wait_writable(int timeout_ms = -1) const
    {
        return poll_(POLLOUT, timeout_ms);
    }

    bool is_writable() const
    {
        return wait_writable(0);
    }

    virtual io_result write(const void* buffer, size_t size) const
    {
        auto nwritten = ::write(*fd_, buffer, size);
        return io_result{nwritten < 0 ? errno : 0, nwritten};
    }

  protected:
    writer() = default;
};

class readwriter
    : public reader
    , public writer
{
  public:
    explicit readwriter(int fd)
        : descriptor(fd)
        , reader(fd)
        , writer(fd)
    {
    }
    readwriter(readwriter&& rhs) noexcept
        : descriptor(std::move(rhs))
        , reader(std::move(rhs))
        , writer(std::move(rhs))
    {
    }
    readwriter& operator=(readwriter&& rhs) noexcept
    {
        if (this != &rhs) {
            descriptor::operator=(std::move(rhs));
            // reader::operator=(std::move(rhs));
            // writer::operator=(std::move(rhs));
        }
        return *this;
    }

  protected:
    readwriter() = default;
};

/****************************************************************************
 * communication channels
 */
inline std::pair<reader, writer> make_pipe()
{
    int fds[2];
    if (::pipe(fds) < 0) {
        detail::throw_syserr(errno, "pipe");
    }
    return {reader(fds[0]), writer(fds[1])};
}

inline std::pair<readwriter, readwriter> make_socketpair()
{
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        detail::throw_syserr(errno, "socketpair");
    }
    return {readwriter(sv[0]), readwriter(sv[1])};
}

class fifo : public readwriter
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
        , readwriter(std::move(rhs))
        , path_(std::exchange(rhs.path_, ""))
    {
    }
    fifo& operator=(fifo&& rhs) noexcept
    {
        if (this != &rhs) {
            unlink_();
            readwriter::operator=(std::move(rhs));
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

    void unlink_() noexcept
    {
        if (!path_.empty()) {
            ::unlink(path_.c_str());
            path_.clear();
        }
    }
};

class mqueue : public readwriter
{
  public:
    explicit mqueue(std::string_view name)
        : readwriter(::mq_open(name.data(), O_RDWR | O_CREAT, 0666, nullptr))
        , name_(name)
    {
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
        , readwriter(std::move(rhs))
        , name_(std::exchange(rhs.name_, ""))
        , attr_(std::exchange(rhs.attr_, {}))
    {
    }
    mqueue& operator=(mqueue&& rhs) noexcept
    {
        if (this != &rhs) {
            unlink_();
            readwriter::operator=(std::move(rhs));
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

    io_result read(void* buffer, size_t size, unsigned* prio) const
    {
        auto nread = ::mq_receive(*fd_, (char*)buffer, size, prio);
        return io_result{nread < 0 ? errno : 0, nread};
    }

    io_result read(void* buffer, size_t size) const override
    {
        return read(buffer, size, nullptr);
    }

    io_result write(const void* buffer, size_t size, unsigned prio) const
    {
        auto ret = ::mq_send(*fd_, (const char*)buffer, size, prio);
        return io_result{ret == 0 ? 0 : errno, (ssize_t)(ret == 0 ? size : ret)};
    }

    io_result write(const void* buffer, size_t size) const override
    {
        return write(buffer, size, 0);
    }

  private:
    std::string name_;
    struct mq_attr attr_ = {};

    void unlink_() noexcept
    {
        if (!name_.empty()) {
            ::mq_unlink(name_.c_str());
            name_.clear();
        }
    }
};

class unixsocket : public readwriter
{
    using addrptr_t = struct sockaddr*;
    struct anon_addr_tag
    {};

  public:
    class address
    {
        struct sockaddr_un addr_ = {};

      public:
        address() noexcept = default;
        address(const std::string& name)
        {
            if (name.size() + 2 > sizeof(addr_.sun_path)) {
                detail::throw_syserr(EINVAL);
            }
            addr_.sun_family = AF_UNIX;
            ::memcpy(&addr_.sun_path[1], name.c_str(), name.size() + 1);
        }
        address(const char* name)
            : address(std::string(name))
        {
        }
        address(const struct sockaddr_un& addr) noexcept
            : addr_(addr)
        {
        }
        address(const address&) = default;
        address& operator=(const address&) = default;
        address(address&& rhs) noexcept
            : addr_(rhs.addr_)
        {
            rhs.clear();
        }
        address& operator=(address&& rhs) noexcept
        {
            if (this != &rhs) {
                clear();
                addr_ = rhs.addr_;
                rhs.clear();
            }
            return *this;
        }

        const struct sockaddr_un* data() const noexcept
        {
            return &addr_;
        }

        bool empty() const noexcept
        {
            return addr_.sun_family == AF_UNSPEC;
        }

        void clear() noexcept
        {
            ::explicit_bzero(&addr_, sizeof(struct sockaddr_un));
        }

        std::string name() const
        {
            return std::string(&addr_.sun_path[1]);
        }

        bool operator==(const address& rhs) const noexcept
        {
            return ::memcmp(&addr_, &rhs.addr_, sizeof(struct sockaddr_un)) == 0;
        }
        bool operator!=(const address& rhs) const noexcept
        {
            return !(*this == rhs);
        }

        static constexpr size_t len() noexcept
        {
            return sizeof(struct sockaddr_un);
        }

        static address getrandom() noexcept
        {
            uint64_t rand;
            [[maybe_unused]] auto _ = ::getrandom(&rand, sizeof(rand), GRND_NONBLOCK);
            struct sockaddr_un addr = {};
            addr.sun_family = AF_UNIX;
            addr.sun_path[1] = '\\';
            char* p = &addr.sun_path[2];
            std::to_chars(p, p + sizeof(addr.sun_path) - 2, rand, 16);
            return addr;
        }
    };

    static unixsocket server(const std::string& name)
    {
        unixsocket sock(anon_addr_tag{});
        sock.bind_(name);
        return sock;
    }

    explicit unixsocket(const std::string& peer = "")
        : descriptor(newsock())
    {
        bind_(address::getrandom());

        if (!peer.empty()) {
            address addr(peer);
            if (auto err = connect_(addr); err != 0) {
                detail::throw_syserr(err, "connect");
            }
            peer_ = std::move(addr);
        }
    }

    unixsocket(unixsocket&& rhs) noexcept
        : descriptor(std::move(rhs))
        , readwriter(std::move(rhs))
        , peer_(std::move(rhs.peer_))
    {
    }
    unixsocket& operator=(unixsocket&& rhs) noexcept
    {
        if (this != &rhs) {
            readwriter::operator=(std::move(rhs));
            peer_ = std::move(rhs.peer_);
        }
        return *this;
    }

    address getsockname() const
    {
        address addr;
        socklen_t len = addr.len();
        if (::getsockname(*fd_, (addrptr_t)addr.data(), &len) < 0) {
            detail::throw_syserr(errno, "getsockname");
        }
        return addr;
    }

    void disconnect()
    {
        if (!peer_.empty()) {
            const auto& addr = getsockname();
            fd_ = detail::fd_wrapper(newsock());
            bind_(addr);
            peer_.clear();
        }
    }

    void connect(const address& peer)
    {
        disconnect();
        if (auto err = connect_(peer); err != 0) {
            detail::throw_syserr(err, "connect");
        }
        peer_ = peer;
    }

    io_result read(void* buffer, size_t size) const override
    {
        if (peer_.empty()) {
            address addr;
            socklen_t len = addr.len();
            auto nrecv = ::recvfrom(*fd_, buffer, size, 0, (addrptr_t)addr.data(), &len);
            if (nrecv < 0) {
                return io_result{errno, nrecv};
            }
            if (auto err = connect_(addr); err != 0) {
                return io_result{err, -1};
            }
            peer_ = addr;
            return io_result{0, nrecv};
        }
        return reader::read(buffer, size);
    }

    std::pair<io_result, address> recvfrom(void* buffer, size_t size) const
    {
        address addr;
        socklen_t len = addr.len();
        auto nrecv = ::recvfrom(*fd_, buffer, size, 0, (addrptr_t)addr.data(), &len);
        return {io_result{nrecv < 0 ? errno : 0, nrecv}, addr};
    }

    io_result sendto(const void* buffer, size_t size, const address& addr) const
    {
        auto nsend = ::sendto(*fd_, buffer, size, 0, (addrptr_t)addr.data(), addr.len());
        return io_result{nsend < 0 ? errno : 0, nsend};
    }

  private:
    mutable address peer_;

    explicit unixsocket(const anon_addr_tag&)
        : descriptor(newsock())
    {
    }

    void bind_(const address& addr) const
    {
        if (::bind(*fd_, (addrptr_t)addr.data(), addr.len()) < 0) {
            detail::throw_syserr(errno, "bind");
        }
    }

    int connect_(const address& peer) const
    {
        return ::connect(*fd_, (addrptr_t)peer.data(), peer.len()) < 0 ? errno : 0;
    }

    static int newsock() noexcept
    {
        return ::socket(AF_UNIX, SOCK_DGRAM, 0);
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

    io_result read(void*, size_t) = delete;

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

class eventfd : public readwriter
{
  public:
    static constexpr uint64_t EFD_MAX_VALUE = 0xfffffffffffffffe;

    explicit eventfd(bool use_as_semaphore = false)
        : descriptor(::eventfd(0, (use_as_semaphore ? EFD_SEMAPHORE : 0)))
    {
    }

    eventfd(eventfd&& rhs) noexcept
        : descriptor(std::move(rhs))
        , readwriter(std::move(rhs))
    {
    }
    eventfd& operator=(eventfd&& rhs) noexcept = default;

    uint64_t read() const
    {
        uint64_t value = 0;
        if (auto res = reader::read(&value, sizeof(value)); !res && !res.would_block()) {
            detail::throw_syserr(res.code(), "read");
        }
        return value;
    }

    void write(uint64_t value = 1) const
    {
        if (auto res = writer::write(&value, sizeof(value)); !res && !res.would_block()) {
            detail::throw_syserr(res.code(), "write");
        }
    }
};

class signalfd : public reader
{
  public:
    enum class blocks
    {
        none = 0,
        list,
        all,
    };

    explicit signalfd(const std::vector<int>& signals, blocks blk = blocks::list)
    {
        bool do_block = true;
        sigset_t set;
        switch (blk) {
        case blocks::list:
            ::sigemptyset(&set);
            std::for_each(signals.begin(), signals.end(), [&](auto s) { ::sigaddset(&set, s); });
            break;
        case blocks::all:
            ::sigfillset(&set);
            break;
        default:
            do_block = false;
            break;
        }
        if (do_block && ::pthread_sigmask(SIG_BLOCK, &set, nullptr) < 0) {
            detail::throw_syserr(errno, "pthread_sigmask");
        }

        sigset_t mask;
        ::sigemptyset(&mask);
        std::for_each(signals.begin(), signals.end(), [&](auto s) { ::sigaddset(&mask, s); });
        fd_ = detail::fd_wrapper(::signalfd(-1, &mask, 0));
    }

    signalfd(signalfd&& rhs) noexcept
        : descriptor(std::move(rhs))
        , reader(std::move(rhs))
    {
    }
    signalfd& operator=(signalfd&&) noexcept = default;

    int get_last_signal() const
    {
        struct signalfd_siginfo siginfo = {};
        if (auto res = read(&siginfo, sizeof(siginfo)); !res && !res.would_block()) {
            detail::throw_syserr(res.code(), "read");
        }
        return siginfo.ssi_signo;
    }
};

class timerfd : public reader
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

    timerfd(timerfd&& rhs) noexcept
        : descriptor(std::move(rhs))
        , reader(std::move(rhs))
    {
    }
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
        if (auto res = reader::read(&count, sizeof(count)); !res && !res.would_block()) {
            detail::throw_syserr(errno, "read");
        }
        return count;
    }
};

class inotify : public reader
{
  public:
    inotify()
        : descriptor(::inotify_init())
    {
    }

    inotify(inotify&& rhs) noexcept
        : descriptor(std::move(rhs))
        , reader(std::move(rhs))
        , watches_(std::exchange(rhs.watches_, {}))
    {
    }
    inotify& operator=(inotify&& rhs) noexcept = default;

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
        alignas(alignof(struct inotify_event)) std::array<uint8_t, 8192> buffer;
        auto res = reader::read(buffer.data(), buffer.size());
        if (!res && !res.would_block()) {
            detail::throw_syserr(res.code(), "read");
        }

        std::vector<event> events;
        struct inotify_event* ev = nullptr;
        for (auto* p = buffer.data(); p < buffer.data() + res.nbytes();
             p += sizeof(struct inotify_event) + ev->len) {
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

  private:
    std::unordered_map<int, std::string> watches_;
};

/****************************************************************************
 * memory io
 */
class memfd : public readwriter
{
  public:
    explicit memfd(std::string_view name)
        : descriptor(::memfd_create(name.data(), 0))
    {
    }

    memfd(memfd&& rhs) noexcept
        : descriptor(std::move(rhs))
        , readwriter(std::move(rhs))
    {
    }
    memfd& operator=(memfd&& rhs) noexcept = default;
};

class memmap : public readwriter
{
  public:
    explicit memmap(std::string_view filename, size_t length = 0, int prot = PROT_READ,
                    int flags = MAP_PRIVATE)
        : memmap(::open(filename.data(), O_RDONLY), length, prot, flags)
    {
    }

    memmap(memmap&& rhs) noexcept
        : descriptor(std::move(rhs))
        , readwriter(std::move(rhs))
        , length_(std::exchange(rhs.length_, 0))
        , area_(std::exchange(rhs.area_, nullptr))
    {
    }
    memmap& operator=(memmap&& rhs) noexcept
    {
        if (this != &rhs) {
            unmap_();
            readwriter::operator=(std::move(rhs));
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
                detail::throw_syserr(errno, "fstat");
            }
            length_ = sb.st_size;
        }

        if ((area_ = ::mmap(nullptr, length_, prot, flags, *fd_, 0)) == MAP_FAILED) {
            detail::throw_syserr(errno, "mmap");
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
            length_ = 0;
        }
    }
};

class shmem : public memmap
{
    static constexpr size_t LENGTH = 4096;

  public:
    explicit shmem(std::string_view name, size_t length = LENGTH, int oflag = O_RDWR | O_CREAT)
        : descriptor(shmem_init(name, length, oflag))
        , memmap(/* dummy*/ -1, length, PROT_READ | PROT_WRITE, MAP_SHARED)
        , name_(name)
    {
    }

    shmem(shmem&& rhs) noexcept
        : descriptor(std::move(rhs))
        , memmap(std::move(rhs))
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
