#ifndef RESOLVER_HPP_
#define RESOLVER_HPP_

#include <assert.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>

#include <stdexcept>
#include <string>
#include <system_error>

namespace tbd {

/**********************************************************************
 * base resolver
 */
class resolver
{
  public:
    explicit resolver(std::string_view host)
        : resolve_state_(0)
        , host_(host)
        , ipaddr_(-ENOENT)
    {
        ::memset(&hints_, 0, sizeof(hints_));
        hints_.ai_family = AF_INET;

        ::memset(&req_, 0, sizeof(req_));
        req_.ar_name = host_.c_str();
        req_.ar_service = nullptr;
        req_.ar_request = &hints_;
        req_.ar_result = nullptr;

        list_[0] = &req_;

        ::memset(&sigev_, 0, sizeof(sigev_));
        sigev_.sigev_notify = SIGEV_NONE;
    }

    virtual ~resolver() noexcept
    {
        free_result();
    }

    int64_t lookup(int timeout_ms = -1)
    {
        auto addr = lookup_nb();
        return (addr >= 0) ? addr : poll(timeout_ms);
    }

    int64_t lookup_nb()
    {
        switch (resolve_state_) {
        case 0: {
            if (int err = ::getaddrinfo_a(GAI_NOWAIT, list_, 1, &sigev_)) {
                // EAI_AGAIN, EAI_MEMORY, EAI_SYSTEM
                throw std::runtime_error(std::string("getaddrinfo_a: ") + ::gai_strerror(err));
            }
            resolve_state_ = 1;
            [[fallthrough]];
        }
        case 1: {
            return poll(0);
        }
        default:
            return ipaddr_;
        }
    }

  protected:
    int resolve_state_ = 0;
    std::string host_;
    int64_t ipaddr_ = -ENOENT;
    struct gaicb req_ = {};
    struct addrinfo hints_ = {};
    struct gaicb* list_[1] = {nullptr};
    struct sigevent sigev_ = {};

    virtual int64_t poll(int timeout_ms = 0)
    {
        assert(resolve_state_ == 1);

        // gai_suspend: 0 | EAI_ALLDONE | EAI_INTR => go through, EAI_AGAIN => EAGAIN
        struct timespec ts;
        if (timeout_ms >= 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1'000'000;
        }
        if (::gai_suspend(list_, 1, timeout_ms >= 0 ? &ts : nullptr) == EAI_AGAIN) {
            return -EAGAIN;
        }

        // gai_error: 0 => go through, EAI_INPROGRESS => EAGAIN, EAI_CANCELED => exception
        if (int err = ::gai_error(&req_)) {
            return on_rejected(err);
        }

        // ar_result
        return on_resolved();
    }

    int64_t on_resolved() noexcept
    {
        ipaddr_ = ((struct sockaddr_in*)req_.ar_result->ai_addr)->sin_addr.s_addr;
        resolve_state_ = 2;
        free_result();
        return ipaddr_;
    }

    int64_t on_rejected(int err)
    {
        if (err == EAI_INPROGRESS) {
            return -EAGAIN;
        }

        free_result();
#if 0
        if (err == EAI_NONAME) {
            resolve_state_ = 2;
            return -ENOENT;
        }
#endif
        resolve_state_ = 0;
        throw std::runtime_error(std::string("getaddrinfo_a: ") + ::gai_strerror(err));
    }

    void free_result() noexcept
    {
        if (req_.ar_result) {
            ::freeaddrinfo(req_.ar_result);
            req_.ar_result = nullptr;
        }
    }
};

/**********************************************************************
 * with notifier
 */
class resolver_notif : public resolver
{
    static constexpr char MAGIC_NUMBER[4] = {'R', 'S', 'L', 'V'};

  public:
    virtual ~resolver_notif() noexcept
    {
        ::memset(magic_, 0, sizeof(magic_));

        if (eventfd_ >= 0) {
            ::close(eventfd_);
            eventfd_ = -1;
        }
    }

    int poll_handle() const noexcept
    {
        // to wait completion, poll **WRITABLE** (compatible to connect(2))
        return eventfd_;
    }

  protected:
    char magic_[4] = {0};
    int eventfd_ = -1;

    explicit resolver_notif(std::string_view host)
        : resolver(host)
    {
        ::memcpy(magic_, MAGIC_NUMBER, sizeof(magic_));

        eventfd_ = ::eventfd(0, 0);
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        static constexpr eventfd_t EVFD_MAX_VALUE = 0xfffffffffffffffe;
        ::eventfd_write(eventfd_, EVFD_MAX_VALUE);

        sigev_.sigev_value.sival_ptr = this;
    }

    void notify() const noexcept
    {
        static eventfd_t value;
        ::eventfd_read(eventfd_, &value);
    }

#if 0
    int64_t poll(int timeout_ms = -1) override
    {
        struct pollfd fds;
        fds.fd = eventfd_;
        fds.events = POLLOUT;
        fds.revents = 0;
    again:
        int nfds = ::poll(&fds, 1, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) {
                goto again;
            } else {
                throw std::system_error(errno, std::generic_category());
            }
        }
        if (nfds >= 1 && fds.revents & POLLOUT) {
            return on_completed();
        }
        return -EAGAIN;
    }
#endif

    static void assert_is_alive(const resolver_notif* self)
    {
        if (::memcmp(self->magic_, MAGIC_NUMBER, 4) != 0) {
            throw std::runtime_error("resolver_notif: instance is already destructed");
        }
    }
};

/**********************************************************************
 * with signal notify
 */
class resolver_sig : public resolver_notif
{
    inline static const int NOTIFY_SIGNAL = SIGRTMIN + 1;

  public:
    explicit resolver_sig(std::string_view host)
        : resolver_notif(host)
    {
        sigev_.sigev_notify = SIGEV_SIGNAL;
        sigev_.sigev_signo = NOTIFY_SIGNAL;

        ::memset(&action_, 0, sizeof(action_));
        action_.sa_sigaction = signal_handler;
        action_.sa_flags = SA_RESTART | SA_SIGINFO;
        if (::sigaction(NOTIFY_SIGNAL, &action_, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "sigaction");
        }
    }

  private:
    struct sigaction action_;

    static void signal_handler(int sig, siginfo_t* info, void*)
    {
        // dump_siginfo(sig, info);

        if (sig != NOTIFY_SIGNAL) {
            return;  // ignore other signals?
        }

        auto self = (resolver_sig*)info->si_value.sival_ptr;
        assert_is_alive(self);
        self->notify();
    }

    static void dump_siginfo(int sig, const siginfo_t* info) noexcept
    {
        printf("signal_handler\n");
        printf("sig = %d\n", sig);
        printf(" si_signo   = %d\n", info->si_signo);
        printf(" si_errno   = %d\n", info->si_errno);
        printf(" si_code    = %08x\n", info->si_code);
        // printf(" si_trapno  = %d\n", info->si_trapno);
        printf(" si_pid     = %d\n", info->si_pid);
        printf(" si_uid     = %d\n", info->si_uid);
        printf(" si_status  = %d\n", info->si_status);
        printf(" si_int     = %d\n", info->si_int);
        printf(" si_ptr     = %p\n", info->si_ptr);
        printf(" si_overrun = %d\n", info->si_overrun);
        printf(" si_timerid = %d\n", info->si_timerid);
        printf(" si_fd      = %d\n", info->si_fd);
        printf(" si_syscall = %d\n", info->si_syscall);
        printf(" si_arch    = %u\n", info->si_arch);
        printf("\n");
    }
};

/**********************************************************************
 * with thread notify
 */
class resolver_thr : public resolver_notif
{
  public:
    explicit resolver_thr(std::string_view host)
        : resolver_notif(host)
    {
        sigev_.sigev_notify = SIGEV_THREAD;
        sigev_.sigev_notify_function = notify_fn;
    }

  private:
    static void notify_fn(union sigval sival)
    {
        auto self = (resolver_thr*)sival.sival_ptr;
        assert_is_alive(self);
        self->notify();
    }
};

}  // namespace tbd

#endif
