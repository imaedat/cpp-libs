#ifndef RESOLVER_HPP_
#define RESOLVER_HPP_

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <chrono>
#include <future>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace tbd {

namespace {
struct gai_result
{
    int error_code = 0;
    uint32_t ipaddr = 0;
};
gai_result getaddrinfo(std::string_view host)
{
    gai_result result;

    struct addrinfo hints, *res = nullptr;
    ::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    result.error_code = ::getaddrinfo(host.data(), nullptr, &hints, &res);
    if (result.error_code == 0) {
        result.ipaddr = (uint32_t)((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    }
    if (res) {
        freeaddrinfo(res);
    }
    return result;
}
}  // namespace

/**********************************************************************
 * base resolver interface
 *
 * resolver_base(v)
 *   resolver
 *   async_resolver_base(v)
 *     async_resolver
 *     notifiable_resolver
 */
class resolver_base
{
  protected:
    class cache
    {
        static constexpr unsigned CACHE_TTL_SEC = 60 * 60;

        struct string_like_hash
        {
            using is_transparent = void;
            size_t operator()(const std::string& s) const noexcept
            {
                return std::hash<std::string>{}(s);
            }
            size_t operator()(std::string_view sv) const noexcept
            {
                return std::hash<std::string_view>{}(sv);
            }
            size_t operator()(const char* s) const noexcept
            {
                return std::hash<std::string_view>{}(s);
            }
        };

        struct string_like_equal
        {
            using is_transparent = void;
            bool operator()(const std::string& s1, const std::string& s2) const noexcept
            {
                return s1 == s2;
            }
            bool operator()(const std::string& s1, std::string_view s2) const noexcept
            {
                return s1 == s2;
            }
            bool operator()(std::string_view s1, const std::string& s2) const noexcept
            {
                return s1 == s2;
            }
            bool operator()(const std::string& s1, const char* s2) const noexcept
            {
                return s1 == s2;
            }
            bool operator()(const char* s1, const std::string& s2) const noexcept
            {
                return s1 == s2;
            }
        };

        struct entry
        {
            uint32_t ipaddr;
            std::chrono::steady_clock::time_point timestamp;

            bool is_expired(int ttl) const noexcept
            {
                using namespace std::chrono;
                return steady_clock::now() - timestamp >= seconds(ttl);
            }
        };

      public:
        static cache& get_instance() noexcept
        {
            static cache instance_;
            return instance_;
        }

        void clear()
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            cache_.clear();
        }

        void add_or_replace(std::string_view hostname, uint32_t ipaddr)
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            cache_.insert_or_assign(hostname.data(),
                                    entry{ipaddr, std::chrono::steady_clock::now()});
        }

        void add_or_replace(std::string_view hostname, std::string_view ipaddr)
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            cache_.insert_or_assign(hostname.data(), entry{::inet_addr(ipaddr.data()),
                                                           std::chrono::steady_clock::now()});
        }

        void remove_by_name(std::string_view hostname)
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            cache_.erase(hostname.data());
        }

        void remove_by_addr(std::string_view ipaddr)
        {
            uint32_t addr = ::inet_addr(ipaddr.data());
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            for (auto it = cache_.begin(); it != cache_.end();) {
                if (it->second.ipaddr == addr) {
                    it = cache_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        std::optional<uint32_t> find_addr_by_name(std::string_view hostname)
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            auto it = cache_.find(hostname.data());
            if (it == cache_.end()) {
                return std::nullopt;
            }

            if (it->second.is_expired(ttl_)) {
                cache_.erase(it);
                return std::nullopt;
            }

            return it->second.ipaddr;
        }

        std::vector<std::string> find_names_by_addr(std::string_view ipaddr)
        {
            return find_names_by_addr(::inet_addr(ipaddr.data()));
        }

        std::vector<std::string> find_names_by_addr(uint32_t ipaddr)
        {
            std::vector<std::string> names;
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            for (auto it = cache_.begin(); it != cache_.end();) {
                if (it->second.ipaddr != ipaddr) {
                    ++it;
                } else if (it->second.is_expired(ttl_)) {
                    it = cache_.erase(it);
                } else {
                    names.emplace_back(it->first);
                    ++it;
                }
            }
            return names;
        }

        void set_ttl(int new_ttl)
        {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            ttl_ = new_ttl;
        }

      private:
        std::mutex mtx_;
        std::unordered_map<std::string, entry, string_like_hash, string_like_equal> cache_;
        int ttl_ = CACHE_TTL_SEC;
    };  // class cache

  public:
    virtual ~resolver_base() noexcept = default;

    template <typename T>
    void add_cache(std::string_view hostname, T ipaddr) const
    {
        cache::get_instance().add_or_replace(hostname, ipaddr);
    }

    void remove_cached_name(std::string_view hostname) const
    {
        cache::get_instance().remove_by_name(hostname);
    }

    void remove_cached_addr(std::string_view ipaddr) const
    {
        cache::get_instance().remove_by_addr(ipaddr);
    }

  protected:
    enum state
    {
        unresolved = 0,
        resolving,
        resolved,
    };

    inline static const std::regex re_ipaddr{
        "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"};

    std::string host_;
    uint32_t ipaddr_ = 0;
    state resolve_state_ = state::unresolved;

    explicit resolver_base(std::string_view host)
        : host_(host)
        , ipaddr_(0)
        , resolve_state_(state::unresolved)
    {
    }

    bool matches_ipaddr()
    {
        if (std::regex_match(host_.data(), re_ipaddr)) {
            resolve_state_ = state::resolved;
            ipaddr_ = inet_addr(host_.data());
            return true;
        }
        return false;
    }

    bool is_cached()
    {
        if (auto addr = cache::get_instance().find_addr_by_name(host_)) {
            resolve_state_ = state::resolved;
            ipaddr_ = *addr;
            return true;
        }
        return false;
    }
};  // calss resolver_base

/**********************************************************************
 * basic blocking resolver
 */
class resolver : public resolver_base
{
  public:
    explicit resolver(std::string_view host)
        : resolver_base(host)
    {
    }

    uint32_t lookup()
    {
        if (resolve_state_ != state::resolved && !matches_ipaddr() && !is_cached()) {
            auto result = getaddrinfo(host_);
            if (result.error_code) {
                throw std::runtime_error(std::string("getaddrinfo: ") +
                                         ::gai_strerror(result.error_code));
            }
            ipaddr_ = result.ipaddr;
            resolve_state_ = state::resolved;
            cache::get_instance().add_or_replace(host_, ipaddr_);
        }
        return ipaddr_;
    }
};

/**********************************************************************
 * async resolver interface
 */
class async_resolver_base : public resolver_base
{
  public:
    virtual std::optional<uint32_t> lookup(int timeout_ms = -1)
    {
        auto addr = lookup_nb();
        return addr ? addr : poll(timeout_ms);
    }

    virtual std::optional<uint32_t> lookup_nb()
    {
        switch (resolve_state_) {
        case state::unresolved: {
            if (matches_ipaddr() || is_cached()) {
                return ipaddr_;
            }
            async_request();
            [[fallthrough]];
        }
        case state::resolving: {
            return poll();
        }
        default:
            return ipaddr_;
        }
    }

  protected:
    explicit async_resolver_base(std::string_view host)
        : resolver_base(host)
    {
    }

    virtual void async_request() = 0;
    virtual std::optional<uint32_t> poll(int timeout_ms = 0) = 0;
};

/**********************************************************************
 * async resolver w/o notifier
 */
class async_resolver : public async_resolver_base
{
  public:
    explicit async_resolver(std::string_view host)
        : async_resolver_base(host)
    {
        ::memset(&hints_, 0, sizeof(hints_));
        hints_.ai_family = AF_INET;

        ::memset(&req_, 0, sizeof(req_));
        req_.ar_name = host_.c_str();
        req_.ar_service = nullptr;
        req_.ar_request = &hints_;
        req_.ar_result = nullptr;

        list_[0] = &req_;
    }

    ~async_resolver() noexcept
    {
        free_result();
    }

  private:
    struct gaicb req_ = {};
    struct addrinfo hints_ = {};
    struct gaicb* list_[1] = {nullptr};

    void async_request() override
    {
        // getaddrinfo_a: 0, EAI_AGAIN, EAI_MEMORY, EAI_SYSTEM
        if (int err = ::getaddrinfo_a(GAI_NOWAIT, list_, 1, nullptr)) {
            throw std::runtime_error(std::string("getaddrinfo_a: ") + ::gai_strerror(err));
        }
        resolve_state_ = state::resolving;
    }

    std::optional<uint32_t> poll(int timeout_ms = 0) override
    {
        assert(resolve_state_ == state::resolving);

        // gai_suspend: 0 | EAI_ALLDONE | EAI_INTR => go through, EAI_AGAIN => EAGAIN
        struct timespec ts, *tsptr = nullptr;
        if (timeout_ms >= 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1'000'000;
            tsptr = &ts;
        }
        if (int err = ::gai_suspend(list_, 1, tsptr)) {
            if (err == EAI_AGAIN) {
                return std::nullopt;
            }
        }

        // gai_error: 0 => go through, EAI_INPROGRESS => EAGAIN, EAI_CANCELED => exception
        if (int err = ::gai_error(&req_)) {
            if (err == EAI_INPROGRESS) {
                return std::nullopt;
            }
            free_result();
            resolve_state_ = state::unresolved;
            throw std::runtime_error(std::string("getaddrinfo_a: ") + ::gai_strerror(err));
        }

        ipaddr_ = ((struct sockaddr_in*)req_.ar_result->ai_addr)->sin_addr.s_addr;
        resolve_state_ = state::resolved;
        free_result();
        cache::get_instance().add_or_replace(host_, ipaddr_);
        return ipaddr_;
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
 * async resolver w/ notifier
 */
class notifiable_resolver : public async_resolver_base
{
  public:
    explicit notifiable_resolver(std::string_view host)
        : async_resolver_base(host)
    {
        eventfd_ = ::eventfd(0, 0);
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        static constexpr eventfd_t EVFD_MAX_VALUE = 0xfffffffffffffffe;
        ::eventfd_write(eventfd_, EVFD_MAX_VALUE);
    }

    ~notifiable_resolver() noexcept
    {
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

  private:
    int eventfd_ = -1;
    std::future<int> future_;

    void async_request() override
    {
        future_ = std::async(std::launch::async, [this]() {
            auto result = getaddrinfo(host_);
            if (!result.error_code) {
                ipaddr_ = result.ipaddr;
            }
            eventfd_t value;
            ::eventfd_read(eventfd_, &value);
            return result.error_code;
        });

        resolve_state_ = state::resolving;
    }

    std::optional<uint32_t> poll(int timeout_ms = 0) override
    {
        assert(resolve_state_ == state::resolving);

        auto status = future_.wait_for(std::chrono::milliseconds(timeout_ms));
        if (status == std::future_status::timeout) {
            return std::nullopt;
        }

        auto err = future_.get();
        if (err) {
            resolve_state_ = state::unresolved;
            throw std::runtime_error(std::string("getaddrinfo: ") + ::gai_strerror(err));
        }

        resolve_state_ = state::resolved;
        cache::get_instance().add_or_replace(host_, ipaddr_);
        return ipaddr_;
    }
};

}  // namespace tbd

#endif
