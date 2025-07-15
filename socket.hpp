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

#ifdef SOCKET_VERBOSE
#    include <stdio.h>
#    include <sys/syscall.h>
#endif

#include <algorithm>
#include <chrono>
#include <memory>
#include <regex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace tbd {

#define THROW_SYSERR(e, f) throw std::system_error((e), std::generic_category(), (f))

#define SYSCALL(func, ...)                                                                         \
    ({                                                                                             \
        int ret = func(__VA_ARGS__);                                                               \
        if (ret < 0) {                                                                             \
            THROW_SYSERR(errno, #func);                                                            \
        }                                                                                          \
        ret;                                                                                       \
    })

#define THROW_SSLERR(f)                                                                            \
    throw std::runtime_error(std::string(f) + " " + ::ERR_error_string(::ERR_get_error(), nullptr));

#define USE_GETADDRINFO

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

    resolver() noexcept = default;
};

namespace detail {
ssize_t ssl_read(SSL* s, void* buf, size_t size) noexcept
{
    size_t nbytes = 0;
    ssize_t ret = ::SSL_read_ex(s, buf, size, &nbytes);
    return (ret > 0) ? (ssize_t)nbytes : ret;
}

ssize_t ssl_write(SSL* s, const void* buf, size_t size) noexcept
{
    size_t nbytes = 0;
    ssize_t ret = ::SSL_write_ex(s, buf, size, &nbytes);
    return (ret > 0) ? (ssize_t)nbytes : ret;
}
}  // namespace detail

/****************************************************************************
 * base class
 */
class socket_base
{
  public:
    socket_base(const socket_base&) = delete;
    socket_base& operator=(const socket_base&) = delete;
    socket_base(socket_base&& rhs) noexcept
        : raw_fd_(std::exchange(rhs.raw_fd_, -1))
    {
    }
    socket_base& operator=(socket_base&& rhs) noexcept
    {
        if (this != &rhs) {
            raw_fd_ = std::exchange(rhs.raw_fd_, -1);
        }
        return *this;
    }

    virtual ~socket_base() noexcept
    {
        close();
    }

    virtual void close() noexcept
    {
        if (raw_fd_ >= 0) {
            ::shutdown(raw_fd_, SHUT_RDWR);
            ::close(raw_fd_);
            raw_fd_ = -1;
        }
    }

    int release() noexcept
    {
        return std::exchange(raw_fd_, -1);
    }

    virtual int native_handle() const noexcept
    {
        return raw_fd_;
    }

    int set_nonblock(bool set = true)
    {
        int old_flags = SYSCALL(::fcntl, native_handle(), F_GETFL);
        if ((set && !(old_flags & O_NONBLOCK)) || (!set && (old_flags & O_NONBLOCK))) {
            SYSCALL(::fcntl, native_handle(), F_SETFL,
                    (set ? (old_flags | O_NONBLOCK) : (old_flags & ~O_NONBLOCK)));
        }
        return old_flags;
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
            THROW_SYSERR(errno, "inet_ntop");
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
            THROW_SYSERR(errno, "inet_ntop");
        }
        return {addr_s, ntohs(addr.sin_port)};
    }

  protected:
    int raw_fd_ = -1;

    socket_base() noexcept = default;

    bool is_readable() const
    {
        return poll_(POLLIN | POLLRDHUP);
    }

    bool wait_readable(int timeout_ms = -1) const
    {
        return poll_(POLLIN | POLLRDHUP, timeout_ms);
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
        int nfds = SYSCALL(::poll, &fds, 1, timeout_ms);
        if (fds.revents & POLLNVAL) {
            THROW_SYSERR(EINVAL, "poll");
        }
        return nfds >= 1;
    }
};

/****************************************************************************
 * read/write interface
 */
class io_socket : virtual public socket_base
{
  public:
    io_socket(io_socket&& rhs) noexcept
        : socket_base(std::move(rhs))
    {
    }
    io_socket& operator=(io_socket&& rhs) noexcept
    {
        if (this != &rhs) {
            socket_base::operator=(std::move(rhs));
        }
        return *this;
    }

    virtual std::error_code recv_some(void* buf, size_t size, int timeout_ms,
                                      size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv_some(void* buf, size_t size, size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv(void* buf, size_t size, int timeout_ms,
                                 size_t* nrecv = nullptr) = 0;
    virtual std::error_code recv(void* buf, size_t size, size_t* nrecv = nullptr) = 0;
    virtual std::error_code send(const void* buf, size_t size, size_t* nsent = nullptr) = 0;
    virtual std::error_code send(std::string_view msg, size_t* nsent = nullptr) = 0;

  protected:
    io_socket() noexcept = default;
};

/****************************************************************************
 * connect interface
 */
class connector : virtual public io_socket
{
  public:
    virtual void connect(int timeout_ms = -1) = 0;
    virtual bool connect_nb() = 0;
};

/****************************************************************************
 * accept interface
 */
class acceptor : virtual public socket_base
{
  public:
    virtual std::unique_ptr<io_socket> accept(int timeout_ms = -1) = 0;
    virtual std::unique_ptr<io_socket> accept_nb() = 0;
};

/****************************************************************************
 * issue IO with Handle
 */
template <typename Handle>
class io_socket_tmpl : virtual public io_socket
{
  public:
    io_socket_tmpl(io_socket_tmpl&& rhs) noexcept
        : socket_base(std::move(rhs))
        , read_fn_(std::exchange(rhs.read_fn_, nullptr))
        , write_fn_(std::exchange(rhs.write_fn_, nullptr))
    {
    }
    io_socket_tmpl& operator=(io_socket_tmpl&& rhs) noexcept
    {
        if (this != &rhs) {
            io_socket::operator=(std::move(rhs));
            read_fn_ = std::exchange(rhs.read_fn_, nullptr);
            write_fn_ = std::exchange(rhs.write_fn_, nullptr);
        }
        return *this;
    }

    std::error_code recv_some(void* buf, size_t size, int timeout_ms,
                              size_t* nrecv = nullptr) override
    {
        if (!wait_readable(timeout_ms)) {
            return std::error_code(ETIMEDOUT, std::generic_category());
        }
        auto n = read_fn_(io_handle(), buf, size);
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
        size_t wants = size;
        int remains = timeout_ms;
        std::error_code ec;
        char* p = (char*)buf;
        while (wants > 0) {
            auto t1 = steady_clock::now();
            ec = recv_some(p, wants, remains, &nbytes);
            auto t2 = steady_clock::now();
            if (ec) {
                break;
            }
            assert(wants >= nbytes);
            wants -= nbytes;
            p += nbytes;
            auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
            remains = (timeout_ms < 0) ? -1 : (int)std::max(remains - elapsed, 0L);
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

  protected:
    ssize_t (*read_fn_)(Handle, void*, size_t) = nullptr;
    ssize_t (*write_fn_)(Handle, const void*, size_t) = nullptr;

    io_socket_tmpl(ssize_t (*rfn)(Handle, void*, size_t),
                   ssize_t (*wfn)(Handle, const void*, size_t))
        : read_fn_(rfn)
        , write_fn_(wfn)
    {
    }

    virtual Handle io_handle() const noexcept = 0;

    virtual std::error_code handle_error(ssize_t nbytes) const noexcept
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

/****************************************************************************
 * TCP socket, issue IO with Handle = int (read, write)
 */
class tcp_socket : public io_socket_tmpl<int>
{
  public:
    tcp_socket(tcp_socket&& rhs) noexcept
        : socket_base(std::move(rhs))
        , io_socket_tmpl<int>(std::exchange(rhs.read_fn_, nullptr),
                              std::exchange(rhs.write_fn_, nullptr))
    {
    }
    tcp_socket& operator=(tcp_socket&& rhs) noexcept
    {
        if (this != &rhs) {
            socket_base::operator=(std::move(rhs));
            read_fn_ = std::exchange(rhs.read_fn_, nullptr);
            write_fn_ = std::exchange(rhs.write_fn_, nullptr);
        }
        return *this;
    }

  protected:
    tcp_socket() noexcept
        : io_socket_tmpl<int>(::read, ::write)
    {
    }

    tcp_socket(int fd) noexcept
        : tcp_socket()
    {
        raw_fd_ = fd;
    }

    int io_handle() const noexcept override
    {
        return native_handle();
    }

    friend class tcp_server;
};

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
        raw_fd_ = SYSCALL(::socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    }

    // blocking connect
    void connect(int timeout_ms = -1) override
    {
        if (!connect_nb()) {
            if (!wait_writable(timeout_ms)) {
                THROW_SYSERR(ETIMEDOUT, "connect");
            }
            check_last_error();
            conn_state_ = 2;
        }
    }

    // non-blocking connect
    bool connect_nb() override
    {
        switch (conn_state_) {
        case 0: {
            int err = connect_();
            if (err != 0 && err != EINPROGRESS) {
                THROW_SYSERR(err, "connect");
            }
            conn_state_ = 1;
            [[fallthrough]];
        }
        case 1: {
            if (!is_writable()) {
                return false;
            }
            check_last_error();
            conn_state_ = 2;
            [[fallthrough]];
        }
        default:
            return true;
        }
    }

  private:
    std::string peer_;
    uint16_t port_;
    int conn_state_ = 0;

    int connect_()
    {
        auto ipaddr = resolver::get_instance().lookup(peer_);
        if (ipaddr < 0) {
            return -(ipaddr);
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = (uint32_t)ipaddr;

        int rv = ::connect(native_handle(), (const struct sockaddr*)&addr, sizeof(addr));
        return (rv == 0) ? 0 : errno;
    }

    void check_last_error()
    {
        int err;
        socklen_t len = sizeof(err);
        SYSCALL(::getsockopt, native_handle(), SOL_SOCKET, SO_ERROR, &err, &len);
        if (err > 0) {
            conn_state_ = 0;
            THROW_SYSERR(err, "connect");
        }
    }
};

// tcp_server --------------------------------------------------------------
class tcp_server : public acceptor
{
  public:
    tcp_server(std::string_view addr, uint16_t port, int backlog = 1024)
    {
        raw_fd_ = SYSCALL(::socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        setsockopt(SO_REUSEADDR, 1);
        bind(addr, port);
        SYSCALL(::listen, native_handle(), backlog);
    }

    explicit tcp_server(uint16_t port, int backlog = 1024)
        : tcp_server("", port, backlog)
    {
    }

    // blocking accept
    std::unique_ptr<io_socket> accept(int timeout_ms = -1) override
    {
        if (!wait_readable(timeout_ms)) {
            THROW_SYSERR(ETIMEDOUT, "accept");
        }
        int new_fd = accept_();
        if (new_fd < 0) {
            THROW_SYSERR(-new_fd, "accept");
        }

        tcp_socket new_tcp(new_fd);
        return std::make_unique<tcp_socket>(std::move(new_tcp));
    }

    // non-blocking accept
    std::unique_ptr<io_socket> accept_nb() override
    {
        int new_fd = accept_();
        if (new_fd < 0) {
            int err = -new_fd;
            if (err == EAGAIN || err == EWOULDBLOCK) {
                return nullptr;
            }
            THROW_SYSERR(err, "accept");
        }

        tcp_socket new_tcp(new_fd);
        return std::make_unique<tcp_socket>(std::move(new_tcp));
    }

  private:
    int accept_()
    {
        struct sockaddr_in peer;
        socklen_t addrlen = sizeof(peer);
        int new_fd = ::accept4(native_handle(), (struct sockaddr*)&peer, &addrlen, SOCK_NONBLOCK);
        return (new_fd >= 0) ? new_fd : -errno;
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
        if (!(ctx_ = ::SSL_CTX_new(is_server ? ::TLS_server_method() : ::TLS_client_method()))) {
            THROW_SSLERR("SSL_CTX_new");
        }

        ::SSL_CTX_set_default_verify_paths(ctx_);
        ::SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
        ::SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
    }

    // copyable
    ssl_ctx(const ssl_ctx& rhs) noexcept
    {
        *this = rhs;
    }
    ssl_ctx& operator=(const ssl_ctx& rhs) noexcept
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
            ctx_ = std::exchange(rhs.ctx_, nullptr);
        }
        return *this;
    }

    ~ssl_ctx() noexcept
    {
        if (ctx_) {
            ::SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
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
            // ::SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, verify_callback);
        }
    }

    ssl new_ssl(io_socket&) const;

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

    ssl(const ssl_ctx& ctx, io_socket& sock)
        : ssl(ctx)
    {
        set_fd(sock.release());
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
            ssl_ = std::exchange(rhs.ssl_, nullptr);
        }
        return *this;
    }

    ~ssl() noexcept
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
            THROW_SSLERR("SSL_set_fd");
        }
    }

    int get_fd() const noexcept
    {
        return ::SSL_get_fd(ssl_);
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

    void set_verify_hostname(std::string_view peer)
    {
        if (!::SSL_set_tlsext_host_name(ssl_, peer.data()) || !::SSL_set1_host(ssl_, peer.data())) {
            THROW_SSLERR("SSL_set_tlsext_host_name");
        }
    }

  private:
    ssl_ctx ctx_;
    SSL* ssl_ = nullptr;
};

ssl ssl_ctx::new_ssl(io_socket& sock) const
{
    return ssl(*this, sock);
}

/****************************************************************************
 * secure socket w/ SSL/TLS
 */
class secure_socket_base : virtual public socket_base
{
  public:
    secure_socket_base(const secure_socket_base&) = delete;
    secure_socket_base& operator=(const secure_socket_base&) = delete;
    secure_socket_base(secure_socket_base&& rhs) noexcept
        : socket_base(std::move(rhs))
        , ctx_(std::move(rhs.ctx_))
        , ssl_(std::move(rhs.ssl_))
    {
    }
    secure_socket_base& operator=(secure_socket_base&& rhs) noexcept
    {
        if (this != &rhs) {
            socket_base::operator=(std::move(rhs));
            ctx_ = std::move(rhs.ctx_);
            ssl_ = std::move(rhs.ssl_);
        }
        return *this;
    }

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

    secure_socket_base(ssl_ctx&& ctx, ssl&& ssl)
        : ctx_(std::move(ctx))
        , ssl_(std::move(ssl))
    {
    }
};

/****************************************************************************
 * TLS socket, issue IO with Handle = SSL* (SSL_read, SSL_write)
 */
class tls_socket
    : public io_socket_tmpl<SSL*>
    , public secure_socket_base
{
  public:
    tls_socket(tls_socket&& rhs) noexcept
        : socket_base(std::move(rhs))
        , io_socket_tmpl<SSL*>(std::exchange(rhs.read_fn_, nullptr),
                               std::exchange(rhs.write_fn_, nullptr))
        , secure_socket_base(std::move(rhs.ctx_), std::move(rhs.ssl_))
        , is_server_(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_server_method())
        , handshake_fn_(is_server_ ? ::SSL_accept : ::SSL_connect)
    {
    }
    tls_socket& operator=(tls_socket&& rhs) noexcept
    {
        if (this != &rhs) {
            socket_base::operator=(std::move(rhs));
            read_fn_ = std::exchange(rhs.read_fn_, nullptr);
            write_fn_ = std::exchange(rhs.write_fn_, nullptr);
            ctx_ = std::move(rhs.ctx_);
            ssl_ = std::move(rhs.ssl_);
            is_server_ = rhs.is_server_;
            handshake_fn_ = std::exchange(rhs.handshake_fn_, nullptr);
        }
        return *this;
    }

  protected:
    explicit tls_socket(const ssl_ctx& ctx)
        : io_socket_tmpl<SSL*>(detail::ssl_read, detail::ssl_write)
        , secure_socket_base(ctx)
        , is_server_(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_server_method())
        , handshake_fn_(is_server_ ? ::SSL_accept : ::SSL_connect)
    {
    }

    explicit tls_socket(ssl&& ssl)
        : io_socket_tmpl<SSL*>(detail::ssl_read, detail::ssl_write)
        , secure_socket_base(ssl)
        , is_server_(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_server_method())
        , handshake_fn_(is_server_ ? ::SSL_accept : ::SSL_connect)
    {
        raw_fd_ = ssl_.get_fd();
    }

    SSL* io_handle() const noexcept override
    {
        return ssl_.get();
    }

    std::error_code handle_error(ssize_t nbytes) const noexcept override
    {
        return (nbytes > 0) ? std::error_code()
                            : std::error_code(ssl_error_code(nbytes), std::generic_category());
    }

    // blocking handshake
    void handshake_(int timeout_ms = -1)
    {
        using namespace std::chrono;
        int remains = timeout_ms;
        while (remains != 0) {
            auto t1 = steady_clock::now();
            if (handshake_nb_()) {
                return;
            }
            if (!socket_base::wait_readable(remains)) {
                break;
            }
            auto t2 = steady_clock::now();
            auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
            remains = (timeout_ms < 0) ? -1 : (int)std::max(timeout_ms - elapsed, 0L);
        }

        THROW_SYSERR(ETIMEDOUT, (is_server_ ? "SSL_accept" : "SSL_connect"));
    }

    // non-blocking handshake
    bool handshake_nb_()
    {
        auto ret = handshake_fn_(ssl_.get());
        if (ret >= 1) {
            print_cipher();
            return true;
        }

        int err = ssl_error_code(ret);
        assert(err != 0);
        if (err == EAGAIN) {
            return false;
        }
        const auto* fname = is_server_ ? "SSL_accept" : "SSL_connect";
        if (err == EPROTO) {
            THROW_SSLERR(fname);
        } else {
            THROW_SYSERR(err, fname);
        }
    }

  private:
    bool is_server_ = false;
    int (*handshake_fn_)(SSL*) = nullptr;

    int ssl_error_code(int ret) const noexcept
    {
        static constexpr int UNEXPECTED_EOF = 294;

        switch (::SSL_get_error(ssl_.get(), ret)) {
        case SSL_ERROR_NONE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return EAGAIN;
        case SSL_ERROR_ZERO_RETURN:
            return ENOENT;
        case SSL_ERROR_SSL:
            return (::ERR_GET_REASON(::ERR_get_error()) == UNEXPECTED_EOF) ? ENOENT : EPROTO;
        default:
            return errno;
        }
    }

    void print_cipher() const noexcept
    {
#ifdef SOCKET_VERBOSE
        const char* version = ::SSL_get_version(ssl_.get());
        const char* cipher = ::SSL_CIPHER_get_name(::SSL_get_current_cipher(ssl_.get()));
        printf(" *** [%04ld] %s Handshake: %s, %s ***\n", syscall(SYS_gettid),
               (is_server_ ? "Server" : "Client"), version, cipher);
#endif
    }

    friend class tls_server;
};

// tls_client --------------------------------------------------------------
class tls_client
    : public tls_socket
    , public connector
{
  public:
    tls_client(const ssl_ctx& ctx, std::string_view peer, uint16_t port)
        : tls_socket(ctx)
        , tcp_(peer, port)
    {
        assert(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_client_method());
        ssl_.set_fd(tcp_.native_handle());
    }

    void close() noexcept override
    {
        tcp_.close();
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
        int remains = (timeout_ms < 0) ? -1 : (int)std::max(timeout_ms - elapsed, 0L);
        handshake_(remains);
        conn_state_ = 2;
    }

    bool connect_nb() override
    {
        switch (conn_state_) {
        case 0: {
            if (!tcp_.connect_nb()) {
                return false;
            }
            conn_state_ = 1;
            [[fallthrough]];
        }
        case 1: {
            // FIXME exception unsafe
            if (!handshake_nb_()) {
                return false;
            }
            conn_state_ = 2;
            [[fallthrough]];
        }
        default:
            return true;
        }
    }

  private:
    tcp_client tcp_;
    int conn_state_ = 0;
};

// tls_server --------------------------------------------------------------
class tls_server
    : public secure_socket_base
    , public acceptor
{
  public:
    tls_server(const ssl_ctx& ctx, std::string_view addr, uint16_t port, int backlog = 1024)
        : secure_socket_base(ctx)
        , tcp_(addr, port, backlog)
    {
        assert(::SSL_CTX_get_ssl_method(ctx_.get()) == ::TLS_server_method());
    }

    explicit tls_server(const ssl_ctx& ctx, uint16_t port, int backlog = 1024)
        : tls_server(ctx, "", port, backlog)
    {
    }

    void close() noexcept override
    {
        tcp_.close();
    }

    int native_handle() const noexcept override
    {
        return tcp_.native_handle();
    }

    std::unique_ptr<io_socket> accept(int timeout_ms = -1) override
    {
        using namespace std::chrono;
        auto t1 = steady_clock::now();
        auto new_tcp = tcp_.accept(timeout_ms);
        auto t2 = steady_clock::now();
        accept_state_ = 1;
        auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
        int remains = (timeout_ms < 0) ? -1 : (int)std::max(timeout_ms - elapsed, 0L);
        auto new_ssl = ctx_.new_ssl(*new_tcp);
        tls_socket new_tls(std::move(new_ssl));
        new_tls.handshake_(remains);
        accept_state_ = 0;
        return std::make_unique<tls_socket>(std::move(new_tls));
    }

    std::unique_ptr<io_socket> accept_nb() override
    {
        switch (accept_state_) {
        case 0: {
            auto new_tcp = tcp_.accept_nb();
            if (!new_tcp) {
                return nullptr;
            }
            new_tls_ = std::make_unique<tls_socket>(tls_socket(ctx_.new_ssl(*new_tcp)));
            accept_state_ = 1;
            [[fallthrough]];
        }
        case 1: {
            // FIXME exception unsafe
            if (!new_tls_->handshake_nb_()) {
                return nullptr;
            }
            accept_state_ = 0;
            return std::unique_ptr<io_socket>(static_cast<io_socket*>(new_tls_.release()));
        }
        default:
            break;
        }

        return nullptr;
    }

  private:
    tcp_server tcp_;
    int accept_state_ = 0;
    std::unique_ptr<tls_socket> new_tls_ = nullptr;
};

}  // namespace tbd

#endif
