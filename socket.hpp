#ifndef SOCKET_HPP_
#define SOCKET_HPP_

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
//
#include <openssl/err.h>
#include <openssl/ssl.h>
// XXX
#include <stdio.h>
#include <sys/syscall.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace tbd {

#define THROW_SYSERR(e) throw std::system_error(e, std::generic_category(), __func__)

#define SYSCALL(func, ...)                                                                         \
    do {                                                                                           \
        int rv = func(__VA_ARGS__);                                                                \
        if (rv < 0) {                                                                              \
            throw std::system_error(errno, std::generic_category(), #func);                        \
        }                                                                                          \
    } while (0)

#define THROW_SSLERR(f)                                                                            \
    do {                                                                                           \
        auto err = ::ERR_get_error();                                                              \
        throw std::runtime_error(std::string((f)) +                                                \
                                 " failed: " + ::ERR_error_string(err, nullptr));                  \
    } while (0)

#define USE_GETADDRINFO

namespace detail {
int set_nonblock(int fd, bool set = true)
{
    int old_flags = ::fcntl(fd, F_GETFL);
    if (old_flags < 0) {
        THROW_SYSERR(errno);
    }
    if ((set && !(old_flags & O_NONBLOCK)) || (!set && (old_flags & O_NONBLOCK))) {
        SYSCALL(::fcntl, fd, F_SETFL, (set ? (old_flags | O_NONBLOCK) : (old_flags & ~O_NONBLOCK)));
    }

    return old_flags;
}

int write_compat(int fd, const void* buf, int size)
{
    return (int)::write(fd, buf, (size_t)size);
}

int read_compat(int fd, void* buf, int size)
{
    return (int)::read(fd, buf, (size_t)size);
}
}  // namespace detail

/****************************************************************************
 * Resolver
 */
class resolver
{
  public:
    static resolver& get_instance()
    {
        static resolver instance_;
        return instance_;
    }

    /**
     * DNS forward lookup
     */
    int64_t lookup(std::string_view host)
    {
        static const std::regex re{
            "^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"};

        if (std::regex_match(host.data(), re)) {
            return inet_addr(host.data());
        }

        auto it = host_addrs_.find(std::string(host));
        if (it != host_addrs_.cend()) {
            return inet_addr(it->second.c_str());
        }

        // 本当は名前引きの処理がブロックするので良くない
#ifdef USE_GETADDRINFO
        struct addrinfo hints, *result = nullptr;
        ::memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        auto err = ::getaddrinfo(host.data(), nullptr, &hints, &result);
        if (err == 0 && result) {
            uint32_t ipaddr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
            ::freeaddrinfo(result);
            return ipaddr;
        }
#else
        struct hostent ret, *result = nullptr;
        char buf[1024] = {0};
        [[maybe_unused]] int h_errnop;
        int err = ::gethostbyname_r(host.data(), &ret, buf, sizeof(buf), &result, &h_errnop);
        if (err == 0 && result) {
            return *(uint32_t*)result->h_addr_list[0];
        }
#endif

        return -ENOENT;
    }

    /**
     * DNS reverse lookup
     */
    std::string reverse_lookup(std::string_view ipaddr)
    {
        auto it = std::find_if(host_addrs_.cbegin(), host_addrs_.cend(),
                               [&ipaddr](const auto& kv) { return kv.second == ipaddr; });
        if (it != host_addrs_.cend()) {
            return it->first;
        }

        struct sockaddr_in addr;
        char host[NI_MAXHOST] = {0};
        ::memset(&addr, 0, sizeof(addr));
        if (::inet_pton(AF_INET, ipaddr.data(), &addr.sin_addr) != 1) {
            return "";
        }
        if (::getnameinfo((struct sockaddr*)&addr, sizeof(addr), host, sizeof(host), nullptr, 0,
                          0) != 0) {
            return "";
        }

        return host;
    }

    void clear_entries()
    {
        host_addrs_.clear();
    }

    void add_entry(std::string_view host, std::string_view addr)
    {
        host_addrs_.emplace(host, addr);
    }

  private:
    // { hostname => ipaddr }
    std::unordered_map<std::string, std::string> host_addrs_;

    resolver() = default;
};

/****************************************************************************
 * base class
 */
class socket_base
{
  public:
    socket_base(const socket_base&) = delete;
    socket_base& operator=(const socket_base&) = delete;
    socket_base(socket_base&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    socket_base& operator=(socket_base&& rhs) noexcept
    {
        if (this != &rhs) {
            raw_fd_ = rhs.raw_fd_;
            rhs.raw_fd_ = -1;
        }
        return *this;
    }

    virtual ~socket_base()
    {
        close();
    }

    void close()
    {
        if (raw_fd_ >= 0) {
            ::shutdown(raw_fd_, SHUT_RDWR);
            ::close(raw_fd_);
            raw_fd_ = -1;
        }
    }

    virtual int native_handle() const noexcept
    {
        return raw_fd_;
    }

    int set_nonblock(bool set = true)
    {
        return detail::set_nonblock(native_handle(), set);
    }

    void bind(std::string_view ipaddr, uint16_t port = 0)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ipaddr.empty() ? INADDR_ANY : inet_addr(ipaddr.data());
        addr.sin_port = htons(port);
        SYSCALL(::bind, native_handle(), (const struct sockaddr*)&addr, sizeof(addr));
    }

    void setsockopt(int so_optname, int val)
    {
        setsockopt_(SOL_SOCKET, so_optname, val);
    }

    void settcpopt(int tcp_optname, int val)
    {
        setsockopt_(IPPROTO_TCP, tcp_optname, val);
    }

    std::pair<std::string, uint16_t> local_endpoint() const
    {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        SYSCALL(::getsockname, native_handle(), (struct sockaddr*)&addr, &addrlen);
        char addr_s[20] = {0};
        const char* p = ::inet_ntop(AF_INET, &addr.sin_addr, addr_s, sizeof(addr_s));
        if (!p) {
            THROW_SYSERR(errno);
        }
        return {addr_s, ntohs(addr.sin_port)};
    }

    std::pair<std::string, uint16_t> remote_endpoint() const
    {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        SYSCALL(::getpeername, native_handle(), (struct sockaddr*)&addr, &addrlen);
        char addr_s[20] = {0};
        const char* p = ::inet_ntop(AF_INET, &addr.sin_addr, addr_s, sizeof(addr_s));
        if (!p) {
            THROW_SYSERR(errno);
        }
        return {addr_s, ntohs(addr.sin_port)};
    }

  protected:
    int raw_fd_ = -1;

    socket_base() = default;

    bool is_readable() const
    {
        return poll_(POLLIN);
    }

    bool wait_readable(int timeout_ms = -1) const
    {
        return poll_(POLLIN, timeout_ms);
    }

    bool is_writable() const
    {
        return poll_(POLLOUT);
    }

    bool wait_writable(int timeout_ms = -1) const
    {
        return poll_(POLLOUT, timeout_ms);
    }

  private:
    void setsockopt_(int level, int optname, int val)
    {
        SYSCALL(::setsockopt, native_handle(), level, optname, &val, (socklen_t)sizeof(val));
    }

    bool poll_(int events, int timeout_ms = 0) const
    {
        struct pollfd fds;
        fds.fd = native_handle();
        fds.events = events;
        fds.revents = 0;
        int nfds = ::poll(&fds, 1, timeout_ms);
        if (nfds < 0) {
            THROW_SYSERR(errno);
        }
        if (fds.revents & POLLNVAL) {
            THROW_SYSERR(EINVAL);
        }
        return nfds >= 1;
    }
};

/****************************************************************************
 * which can send, recv
 */
class io_socket : virtual public socket_base
{
  public:
    io_socket(const io_socket&) = delete;
    io_socket& operator=(const io_socket&) = delete;
    io_socket(io_socket&&) noexcept = default;
    io_socket& operator=(io_socket&&) noexcept = default;

    virtual std::error_code send(const void* buf, size_t size, size_t* nsent = nullptr) = 0;
    virtual std::error_code send(std::string_view msg, size_t* nsent = nullptr) = 0;
    virtual std::error_code recv_some(void* buf, size_t size, int timeout_ms,
                                      size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv_some(void* buf, size_t size, size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv(void* buf, size_t size, int timeout_ms,
                                 size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv(void* buf, size_t size, size_t* nrecv = nullptr) = 0;

  protected:
    io_socket() = default;

    virtual std::error_code handle_error(ssize_t nbytes)
    {
        if (nbytes > 0) {
            return std::error_code();
        }
        if (nbytes == 0) {
            return std::error_code(ENOENT, std::generic_category());
        }

        return std::error_code(errno, std::generic_category());
    }
};

template <typename Handle>
class io_helper : public io_socket
{
  public:
    /**
     * send
     */
    std::error_code send(const void* buf, size_t size, size_t* nsent = nullptr) override
    {
        auto n = write_fn_(io_handle(), buf, size);
        if (nsent) {
            *nsent = n;
        }
        return handle_error(n);
    }

    std::error_code send(std::string_view msg, size_t* nsent = nullptr) override
    {
        return send(msg.data(), msg.size(), nsent);
    }

    /**
     * recv
     */
    std::error_code recv_some(void* buf, size_t size, int timeout_ms,
                              size_t* nrecv = nullptr) override
    {
        bool ok = wait_readable(timeout_ms);
        if (!ok) {
            return std::error_code(ETIMEDOUT, std::generic_category());
        }

        auto n = read_fn_(io_handle(), buf, size);
        // asm volatile("int3");
        if (nrecv) {
            *nrecv = n;
        }
        return handle_error(n);
    }

    std::error_code recv_some(void* buf, size_t size, size_t* nrecv = nullptr) override
    {
        return recv_some(buf, size, -1, nrecv);
    }

    std::error_code recv(void* buf, size_t size, int timeout_ms, size_t* nrecv = nullptr) override
    {
        using namespace std::chrono;

        size_t nbytes = 0;
        size_t want = size;
        int remains = timeout_ms;
        std::error_code ec;
        char* p = (char*)buf;
        while (want > 0) {
            auto t1 = steady_clock::now();
            ec = recv_some(p, size, remains, &nbytes);
            auto t2 = steady_clock::now();
            if (ec) {
                break;
            }
            p += nbytes;
            want -= nbytes;
            auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
            remains = (timeout_ms < 0) ? -1 : std::max(remains - elapsed, 0L);
        }

        if (nrecv) {
            *nrecv = p - (char*)buf;
        }
        return ec;
    }

    std::error_code recv(void* buf, size_t size, size_t* nrecv = nullptr) override
    {
        return recv(buf, size, -1, nrecv);
    }

  protected:
    int (*write_fn_)(Handle, const void*, int);
    int (*read_fn_)(Handle, void*, int);

    virtual Handle io_handle() const noexcept = 0;
};

template <typename Handle>
class io_socket_tmpl : public io_helper<Handle>
{
};

template <>
class io_socket_tmpl<int> : public io_helper<int>
{
  public:
    io_socket_tmpl<int>(io_socket_tmpl<int>&&) noexcept = default;
    io_socket_tmpl<int>& operator=(io_socket_tmpl<int>&&) noexcept = default;

    ~io_socket_tmpl<int>()
    {
    }

  protected:
    io_socket_tmpl<int>()
    {
        write_fn_ = detail::write_compat;
        read_fn_ = detail::read_compat;
    }

    int io_handle() const noexcept override
    {
        return native_handle();
    }
};

using tcp_socket = io_socket_tmpl<int>;

/****************************************************************************
 * which can connect
 */
class connector
{
  public:
    virtual bool connect_nb() = 0;
    virtual void connect(int timeout_ms = -1) = 0;
};

/****************************************************************************
 * TCP
 */
// tcp_client --------------------------------------------------------------
class tcp_client
    : public tcp_socket
    , public connector
{
  public:
    tcp_client(std::string_view peer, uint16_t port)
        : peer_(peer)
        , port_(port)
    {
        raw_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (raw_fd_ < 0) {
            THROW_SYSERR(errno);
        }
        set_nonblock();
    }

    // non-blocking connect
    bool connect_nb() override
    {
        switch (conn_state_) {
        case 0: {
            int err = connect_(peer_, port_);
            if (err != 0 && err != EINPROGRESS) {
                THROW_SYSERR(err);
            }
            conn_state_ = 1;
            return false;
        }

        case 1: {
            if (!is_writable()) {
                return false;
            }
            auto ec = last_error();
            if (ec) {
                THROW_SYSERR(ec.value());
            }
            conn_state_ = 2;
            return true;
        }

        default:
            return true;
        }
    }

    // blocking connect
    void connect(int timeout_ms = -1) override
    {
        connect_nb();
        if (!wait_writable(timeout_ms)) {
            THROW_SYSERR(ETIMEDOUT);
        }
        assert(conn_state_ == 1);
        auto ec = last_error();
        if (ec) {
            THROW_SYSERR(ec.value());
        }
        conn_state_ = 2;
    }

  private:
    std::string peer_;
    uint16_t port_;
    int conn_state_ = 0;

    int connect_(std::string_view host, uint16_t port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        auto ipaddr = resolver::get_instance().lookup(host);
        if (ipaddr < 0) {
            return -(ipaddr);
        }
        addr.sin_addr.s_addr = (uint32_t)ipaddr;

        int rv = ::connect(native_handle(), (const struct sockaddr*)&addr, sizeof(addr));
        return (rv == 0) ? 0 : errno;
    }

    std::error_code last_error() const
    {
        int err;
        socklen_t len = sizeof(err);
        SYSCALL(::getsockopt, native_handle(), SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            return std::error_code();
        } else {
            return std::error_code(err, std::generic_category());
        }
    }
};

// tcp_session -------------------------------------------------------------
class tcp_session : public tcp_socket
{
  public:
    tcp_session(tcp_session&&) = default;

  private:
    explicit tcp_session(int sockfd)
    {
        raw_fd_ = sockfd;
    }

    friend class tcp_server;
};

/****************************************************************************
 * which can accept
 */
template <typename ProtocolServer, typename Handle>
class acceptor
{
  public:
    // polymorphism by CRTP
    io_socket_tmpl<Handle> accept(int timeout_ms = -1)
    {
        return static_cast<ProtocolServer*>(this)->accept_impl(timeout_ms);
    }

    std::optional<io_socket_tmpl<Handle>> accept_nb()
    {
        return static_cast<ProtocolServer*>(this)->accept_nb_impl();
    }
};

// tcp_server --------------------------------------------------------------
class tcp_server
    : public socket_base
    , public acceptor<tcp_server, int>
{
  public:
    tcp_server(std::string_view addr, uint16_t port, int backlog = 1024)
    {
        raw_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (raw_fd_ < 0) {
            THROW_SYSERR(errno);
        }
        setsockopt(SO_REUSEADDR, 1);
        bind(addr, port);
        listen_(backlog);
        set_nonblock();
    }

    explicit tcp_server(uint16_t port, int backlog = 1024)
        : tcp_server("", port, backlog)
    {
    }

  protected:
    // blocking accept
    tcp_session accept_impl(int timeout_ms = -1)
    {
        bool ok = wait_readable(timeout_ms);
        if (!ok) {
            THROW_SYSERR(ETIMEDOUT);
        }
        int newfd = accept_();
        if (newfd < 0) {
            THROW_SYSERR(-newfd);
        }

        return tcp_session(newfd);
    }

    // non-blocking accept
    std::optional<tcp_session> accept_nb_impl()
    {
        int newfd = accept_();
        if (newfd < 0) {
            int err = -newfd;
            if (err == EAGAIN || err == EWOULDBLOCK) {
                return std::nullopt;
            }
            THROW_SYSERR(err);
        }

        return tcp_session(newfd);
    }

    friend class acceptor<tcp_server, int>;

  private:
    void listen_(size_t backlog = 1024)
    {
        SYSCALL(::listen, native_handle(), backlog);
    }

    int accept_()
    {
        struct sockaddr_in peer;
        socklen_t addrlen = sizeof(peer);
        int newfd = ::accept(native_handle(), (struct sockaddr*)&peer, &addrlen);
        if (newfd >= 0) {
            detail::set_nonblock(newfd);
            return newfd;
        } else {
            return -errno;
        }
    }
};

/****************************************************************************
 * SSL/TLS objects
 */
class ssl;

/**
 * shareable SSL_CTX
 */
class ssl_ctx
{
  public:
    explicit ssl_ctx(bool is_server = false)
    {
        using namespace std::literals::string_literals;

        if (!(ctx_ = ::SSL_CTX_new(is_server ? ::TLS_server_method() : ::TLS_client_method()))) {
            THROW_SSLERR("SSL_CTX_new");
        }

        ::SSL_CTX_set_default_verify_paths(ctx_);
        if (::SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) != 1) {
            auto err = ::ERR_get_error();
            ::SSL_CTX_free(ctx_);
            throw std::runtime_error("SSL_CTX_set_min_proto_version failed: "s +
                                     ::ERR_error_string(err, nullptr));
        }
    }

    // copyable
    ssl_ctx(const ssl_ctx& rhs)
    {
        *this = rhs;
    }
    ssl_ctx& operator=(const ssl_ctx& rhs)
    {
        if (this != &rhs) {
            ::SSL_CTX_free(ctx_);
            ctx_ = rhs.ctx_;
            if (ctx_) {
                ::SSL_CTX_up_ref(ctx_);
            }
        }
        return *this;
    }
    // movable
    ssl_ctx(ssl_ctx&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    ssl_ctx& operator=(ssl_ctx&& rhs) noexcept
    {
        if (this != &rhs) {
            ::SSL_CTX_free(ctx_);
            ctx_ = rhs.ctx_;
            rhs.ctx_ = nullptr;
        }
        return *this;
    }

    ~ssl_ctx()
    {
        ::SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }

    SSL_CTX* get() const noexcept
    {
        return ctx_;
    }
    SSL_CTX* operator->() const noexcept
    {
        return get();
    }
    SSL_CTX& operator*() const noexcept
    {
        return *get();
    }

    void load_certificate(std::string_view certfile, std::string_view keyfile)
    {
        if (!certfile.empty() && !keyfile.empty()) {
            if (::SSL_CTX_use_certificate_file(ctx_, certfile.data(), SSL_FILETYPE_PEM) != 1 ||
                ::SSL_CTX_use_PrivateKey_file(ctx_, keyfile.data(), SSL_FILETYPE_PEM) != 1) {
                THROW_SSLERR("SSL_CTX_use_certificate_file");
            }
        }
    }

    static int verify_callback(int preverified, X509_STORE_CTX* ctx)
    {
        (void)ctx;
        return preverified;
    }

    void load_ca_file(std::string_view cafile)
    {
        if (!cafile.empty()) {
            if (!::SSL_CTX_load_verify_locations(ctx_, cafile.data(), nullptr)) {
                THROW_SSLERR("SSL_CTX_load_verify_locations");
            }
            ::SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, verify_callback);
        }
    }

    ssl new_ssl(int) const;

  private:
    SSL_CTX* ctx_ = nullptr;
};

/**
 * per-session SSL
 */
class ssl
{
  public:
    explicit ssl(const ssl_ctx& ctx)
        : ctx_(ctx)
    {
        if (!(ssl_ = ::SSL_new(ctx_.get()))) {
            THROW_SSLERR("SSL_new");
        }
    }

    ssl(const ssl_ctx& ctx, int fd)
        : ssl(ctx)
    {
        set_fd(fd);
    }

    // not copyable
    ssl(const ssl&) = delete;
    ssl& operator=(const ssl&) = delete;
    // movable
    ssl(ssl&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    ssl& operator=(ssl&& rhs) noexcept
    {
        if (this != &rhs) {
            ctx_ = std::move(rhs.ctx_);
            ssl_ = rhs.ssl_;
            rhs.ssl_ = nullptr;
        }
        return *this;
    }

    ~ssl()
    {
        if (ssl_) {
            ::SSL_shutdown(ssl_);
            ::SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }

    void set_fd(int fd)
    {
        if (!::SSL_set_fd(ssl_, fd)) {
            THROW_SSLERR("SSL_new");
        }
    }

    SSL* get() const noexcept
    {
        return ssl_;
    }
    SSL* operator->() const noexcept
    {
        return get();
    }
    SSL& operator*() const noexcept
    {
        return *get();
    }

    const ssl_ctx& get_ctx() noexcept
    {
        return ctx_;
    }

    void set_peername_to_verify(std::string_view peer)
    {
        if (!::SSL_set_tlsext_host_name(ssl_, peer.data()) || !::SSL_set1_host(ssl_, peer.data())) {
            THROW_SSLERR("SSL_set_tlsext_host_name");
        }
    }

  private:
    ssl_ctx ctx_;
    SSL* ssl_ = nullptr;
};

ssl ssl_ctx::new_ssl(int fd) const
{
    return ssl(*this, fd);
}

/****************************************************************************
 * secure socket w/ SSL/TLS
 */
class secure_socket_base : virtual public socket_base
{
  public:
    secure_socket_base(const secure_socket_base&) = delete;
    secure_socket_base& operator=(const secure_socket_base&) = delete;
    secure_socket_base(secure_socket_base&&) noexcept = default;
    secure_socket_base& operator=(secure_socket_base&&) noexcept = default;

  protected:
    ssl_ctx ctx_;
    ssl ssl_;

    explicit secure_socket_base(const ssl_ctx& ctx)
        : ctx_(ctx)
        , ssl_(ctx_)
    {
    }

    explicit secure_socket_base(ssl& ssl)
        : ctx_(ssl.get_ctx())
        , ssl_(std::move(ssl))
    {
    }
};

/****************************************************************************
 * for SSL_write, SSL_read
 */
template <>
class io_socket_tmpl<SSL*>
    : public io_helper<SSL*>
    , public secure_socket_base
{
  public:
    io_socket_tmpl<SSL*>(io_socket_tmpl<SSL*>&&) noexcept = default;
    io_socket_tmpl<SSL*>& operator=(io_socket_tmpl<SSL*>&&) noexcept = default;

  protected:
    explicit io_socket_tmpl<SSL*>(const ssl_ctx& ctx)
        : secure_socket_base(ctx)
    {
        setup();
    }

    explicit io_socket_tmpl<SSL*>(ssl& ssl)
        : secure_socket_base(ssl)
    {
        setup();
    }

    SSL* io_handle() const noexcept override
    {
        return ssl_.get();
    }

    std::error_code handle_error(ssize_t nbytes) override
    {
        if (nbytes > 0) {
            return std::error_code();
        }
        if (nbytes == 0) {
            return std::error_code(ENOENT, std::generic_category());
        }

        int err = ::SSL_get_error(ssl_.get(), nbytes);
        if (err == SSL_ERROR_NONE) {
            return std::error_code();
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return std::error_code(ENOENT, std::generic_category());
        } else if (err == SSL_ERROR_WANT_READ) {
            return std::error_code(EAGAIN, std::generic_category());
        } else if (err == SSL_ERROR_SSL) {
            return std::error_code(EPROTO, std::generic_category());
        }
        return std::error_code(errno, std::generic_category());
    }

    // blocking handshake
    void handshake_(int timeout_ms = -1)
    {
        using namespace std::chrono;
        int remains = timeout_ms;
        while (remains != 0) {
            auto t1 = steady_clock::now();
            if (handshake_nb_()) {
                print_cipher();
                return;
            }
            if (!wait_readable(remains)) {
                break;
            }
            auto t2 = steady_clock::now();
            auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
            remains = (timeout_ms < 0) ? -1 : std::max(timeout_ms - elapsed, 0L);
        }

        THROW_SYSERR(ETIMEDOUT);
    }

    // non-blocking handshake
    bool handshake_nb_()
    {
        auto ret = handshake_fn_(ssl_.get());
        if (ret < 1) {
            auto result = ::SSL_get_verify_result(ssl_.get());
            if (result != X509_V_OK) {
                throw std::runtime_error(::X509_verify_cert_error_string(result));
            }
        }

        int err = ::SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_NONE) {
            print_cipher();
            return true;
        } else if (err == SSL_ERROR_WANT_READ) {
            return false;
        }
        throw std::system_error(errno, std::generic_category());
    }

  private:
    int (*handshake_fn_)(SSL*);

    void setup()
    {
        write_fn_ = ::SSL_write;
        read_fn_ = ::SSL_read;

        if (::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_client_method()) {
            handshake_fn_ = ::SSL_connect;
        } else {
            handshake_fn_ = ::SSL_accept;
        }
    }

    void print_cipher() const
    {
#if 0
        const char* version = ::SSL_get_version(ssl_.get());
        const auto* cipher = ::SSL_get_current_cipher(ssl_.get());
        const char* cipher_name = ::SSL_CIPHER_get_name(cipher);
        printf(" *** [%04ld] %s, %s ***\n", syscall(SYS_gettid), version, cipher_name);
#endif
    }
};

using secure_socket = io_socket_tmpl<SSL*>;

/****************************************************************************
 * TLS
 */
// tls_client --------------------------------------------------------------
class tls_client
    : public secure_socket
    , public connector
{
  public:
    tls_client(const ssl_ctx& ctx, std::string_view peer, uint16_t port)
        : secure_socket(ctx)
        , tcp_(peer, port)
    {
        assert(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_client_method());
        ssl_.set_fd(tcp_.native_handle());
    }

    int native_handle() const noexcept override
    {
        return tcp_.native_handle();
    }

    void connect(int timeout_ms = -1) override
    {
        using namespace std::chrono;
        auto t1 = steady_clock::now();
        tcp_.connect(timeout_ms);
        auto t2 = steady_clock::now();
        conn_state_ = 1;
        auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
        auto remains = (timeout_ms < 0) ? -1 : timeout_ms - elapsed;
        handshake_(remains);
        conn_state_ = 2;
    }

    bool connect_nb() override
    {
        switch (conn_state_) {
        case 0: {
            if (tcp_.connect_nb()) {
                conn_state_ = 1;
            }
            return false;
        }
        case 1: {
            // FIXME exception unsafe
            if (handshake_nb_()) {
                conn_state_ = 2;
                return true;
            }
            return false;
        }
        default:
            return true;
        }
    }

  private:
    tcp_client tcp_;
    int conn_state_ = 0;
};

// tls_session -------------------------------------------------------------
class tls_session : public secure_socket
{
  public:
    tls_session(tls_session&&) noexcept = default;
    tls_session& operator=(tls_session&&) noexcept = default;

    int native_handle() const noexcept override
    {
        return tcp_.native_handle();
    }

  private:
    tcp_socket tcp_;

    explicit tls_session(ssl&& ssl, tcp_socket&& sess)
        : secure_socket(ssl)
        , tcp_(std::move(sess))
    {
    }

    friend class tls_server;
};

// tls_server --------------------------------------------------------------
class tls_server
    : public secure_socket_base
    , public acceptor<tls_server, SSL*>
{
  public:
    tls_server(const ssl_ctx& ctx, std::string_view addr, uint16_t port, int backlog = 1024)
        : secure_socket_base(ctx)
        , tcp_(addr, port, backlog)
    {
    }

    explicit tls_server(const ssl_ctx& ctx, uint16_t port, int backlog = 1024)
        : tls_server(ctx, "", port, backlog)
    {
    }

    int native_handle() const noexcept override
    {
        return tcp_.native_handle();
    }

  protected:
    tls_session accept_impl(int timeout_ms = -1)
    {
        using namespace std::chrono;
        auto t1 = steady_clock::now();
        auto new_tcp = tcp_.accept(timeout_ms);
        auto t2 = steady_clock::now();
        accept_state_ = 1;
        auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
        auto remains = (timeout_ms < 0) ? -1 : timeout_ms - elapsed;
        auto new_ssl = ctx_.new_ssl(new_tcp.native_handle());
        tls_session new_tls(std::move(new_ssl), std::move(new_tcp));
        new_tls.handshake_(remains);
        accept_state_ = 0;
        return new_tls;
    }

    std::optional<tls_session> accept_nb_impl()
    {
        switch (accept_state_) {
        case 0: {
            auto new_tcp = tcp_.accept_nb();
            if (new_tcp) {
                auto new_ssl = ctx_.new_ssl(new_tcp->native_handle());
                new_tls_in_progress_ = tls_session(std::move(new_ssl), std::move(*new_tcp));
                accept_state_ = 1;
            }
            return std::nullopt;
        }
        case 1: {
            // FIXME exception unsafe
            if (new_tls_in_progress_->handshake_nb_()) {
                auto new_tls = std::move(*new_tls_in_progress_);
                new_tls_in_progress_ = std::nullopt;
                accept_state_ = 0;
                return new_tls;
            }
            return std::nullopt;
        }
        default:
            break;
        }
    }

  private:
    tcp_server tcp_;

    int accept_state_ = 0;
    std::optional<tls_session> new_tls_in_progress_{std::nullopt};

    friend class acceptor<tls_server, SSL*>;
};

}  // namespace tbd

#endif
