#ifndef COROUTINE_HPP_
#define COROUTINE_HPP_

#ifdef COROUTINE_USE_SETJMP
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 0
#include <setjmp.h>
#include <signal.h>
#else
#include <ucontext.h>
#endif

#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#include <type_traits>
#include <variant>

#ifndef COROUTINE_STACK_SIZE
#define COROUTINE_STACK_SIZE (64 * 1024)
#endif

namespace tbd {

namespace detail {
struct co_null_type
{};

template <typename T>
inline constexpr bool always_false_v = false;
}  // namespace detail

template <typename G = detail::co_null_type, typename A = detail::co_null_type>
class coroutine_env
{
    using co_gen_type = std::optional<G>;
    using co_arg_type = std::optional<A>;
    inline static constexpr char MAGIC[] = {0x7f, 'C', 'O', 'E'};

    struct state;
    class context
    {
      public:
        co_arg_type yield(co_gen_type&& g = {}) const
        {
            assert_state();
            state_->env_->last_value_ = std::forward<co_gen_type>(g);
#ifdef COROUTINE_USE_SETJMP
            if (::setjmp(state_->uctx_) == 0) {
                ::longjmp(*state_->env_->uctx_, 1);
            }
#else
            if (::swapcontext(&state_->uctx_, state_->env_->uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(), "context: swapcontext");
            }
#endif
            return std::move(state_->value_);
        }

        co_arg_type operator()(co_gen_type&& g = {}) const
        {
            return yield(std::forward<co_gen_type>(g));
        }

        void exit(co_gen_type&& g = {}) const
        {
            assert_state();
            state_->finished_ = true;
            yield(std::forward<co_gen_type>(g));
        }

      private:
        state* state_ = nullptr;

        explicit context(state* state) noexcept
            : state_(state)
        {
        }

        void assert_state() const
        {
            if (!state_) {
                throw std::invalid_argument("context: invalid state");
            }
            if (!state_->env_ || ::memcmp(state_->env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("context: env expired");
            }
        }

        friend class state;
    };  // context

    using coro_without_init = std::function<void(const context&)>;
    using coro_with_init = std::function<void(const context&, co_arg_type&&)>;
    using coro_fn = std::variant<coro_without_init, coro_with_init>;

    struct state
    {
        coro_fn fn_;
        size_t stack_size_;
        char* stack_ = nullptr;
        bool finished_ = true;
        coroutine_env<G, A>* env_ = nullptr;
#ifdef COROUTINE_USE_SETJMP
        stack_t ss_;
        jmp_buf uctx_;
#else
        ucontext_t uctx_;
#endif
        co_arg_type value_;
        std::exception_ptr exception_;

        state(coro_fn&& fn, size_t ss, coroutine_env<G, A>* env)
            : fn_(std::forward<coro_fn>(fn))
            , stack_size_(ss)
            , stack_(nullptr)
            , finished_(false)
            , env_(env)
        {
#ifndef COROUTINE_USE_SETJMP
            if (::getcontext(&uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(), "state: getcontext");
            }
#endif

            size_t pagesz = ::sysconf(_SC_PAGE_SIZE);
            stack_size_ = (stack_size_ + pagesz - 1) & ~(pagesz - 1);  // align
            if (auto err = ::posix_memalign((void**)&stack_, pagesz, pagesz + stack_size_)) {
                throw std::system_error(err, std::generic_category(), "state: posix_memalign");
            }
            if (::mprotect(stack_, pagesz, PROT_NONE) < 0) {  // guard page
                auto err = errno;
                ::free(stack_);
                stack_ = nullptr;
                throw std::system_error(err, std::generic_category(), "state: mprotect");
            }

#ifdef COROUTINE_USE_SETJMP
            ss_.ss_sp = stack_ + pagesz;
            ss_.ss_size = stack_size_;
            ss_.ss_flags = 0;
#else
            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = env_->uctx_;
            auto ptr = (uintptr_t)this;
            ::makecontext(&uctx_, (void (*)()) & entry, 2, (unsigned)(ptr >> 32),
                          (unsigned)(ptr & 0xffffffffU));
#endif
        }

        state(const state&) = delete;
        state& operator=(const state&) = delete;
        state(state&&) = delete;
        state& operator=(state&&) = delete;
        ~state() noexcept
        {
            if (stack_) {
                ::mprotect(stack_, ::sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE);
                ::free(stack_);
                stack_ = nullptr;
            }
        }

        static void entry(unsigned hi, unsigned lo) noexcept
        {
            auto* state = (coroutine_env<G, A>::state*)(((uintptr_t)hi << 32) | lo);
            try {
                if (auto fn = std::get_if<coro_without_init>(&state->fn_)) {
                    (*fn)(context(state));
                } else if (auto fn = std::get_if<coro_with_init>(&state->fn_)) {
                    (*fn)(context(state), std::move(state->value_));
                }
            } catch (...) {
                state->exception_ = std::current_exception();
            }
            state->finished_ = true;
        }
    };  // state

  public:
    class coroutine
    {
      public:
        coroutine() = default;
        coroutine(coroutine&&) noexcept = default;
        coroutine& operator=(coroutine&&) noexcept = default;

        explicit operator bool() const noexcept
        {
            return state_ && !state_->finished_;
        }

        co_gen_type resume(co_arg_type&& a = {})
        {
            if (!state_ || !state_->stack_) {
                throw std::invalid_argument("coroutine: invalid state");
            }
            if (!state_->env_ || ::memcmp(state_->env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("coroutine: env expired");
            }

            if (state_->finished_) {
                assert(!state_->finished_);
                return std::nullopt;
            }

            state_->value_ = std::forward<co_arg_type>(a);
#ifdef COROUTINE_USE_SETJMP
            if (::setjmp(*state_->env_->uctx_) == 0) {
                ::longjmp(state_->uctx_, 1);
            }
#else
            if (::swapcontext(state_->env_->uctx_, &state_->uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(), "coroutine: swapcontext");
            }
#endif

            if (state_->exception_) {
                auto ep = std::move(state_->exception_);
                state_->exception_ = nullptr;
                std::rethrow_exception(ep);
            }

            if (state_->env_->last_value_) {
                // on yield w/ value
                auto val = std::move(*state_->env_->last_value_);
                state_->env_->last_value_ = std::nullopt;
                return val;
            } else {
                // on yield w/o value, or on return
                return std::nullopt;
            }
        }

      private:
        std::unique_ptr<state> state_ = nullptr;

        coroutine(coro_fn&& fn, size_t ss, coroutine_env<G, A>* env)
            : state_(std::make_unique<state>(std::forward<coro_fn>(fn), ss, env))
        {
        }

        friend class coroutine_env<G, A>;
    };  // coroutine

    /************************************************************************
     * coroutine_env
     */
  private:
    char magic_[4];
#ifdef COROUTINE_USE_SETJMP
    jmp_buf* uctx_ = nullptr;  // move safety
#else
    ucontext_t* uctx_ = nullptr;  // move safety
#endif
    co_gen_type last_value_;
#ifdef COROUTINE_USE_SETJMP
    inline static std::mutex mtx_;
#endif

  public:
    coroutine_env()
#ifdef COROUTINE_USE_SETJMP
        : uctx_((jmp_buf*)malloc(sizeof(*uctx_)))
#else
        : uctx_((ucontext_t*)malloc(sizeof(ucontext_t)))
#endif
    {
        if (!uctx_) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: malloc");
        }
        ::memcpy(magic_, MAGIC, sizeof(magic_));
    }

    coroutine_env(const coroutine_env&) = delete;
    coroutine_env& operator=(const coroutine_env&) = delete;
    coroutine_env(coroutine_env&& rhs) noexcept
        : uctx_(std::exchange(rhs.uctx_, nullptr))
        , last_value_(std::move(rhs.last_value_))
    {
        ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
        ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
    }
    coroutine_env& operator=(coroutine_env&& rhs) noexcept
    {
        if (this != &rhs) {
            if (uctx_) {
                ::free(uctx_);
            }
            ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
            ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
            uctx_ = std::exchange(rhs.uctx_, nullptr);
            last_value_ = std::move(rhs.last_value_);
        }
        return *this;
    }

    ~coroutine_env() noexcept
    {
        if (uctx_) {
            ::free(uctx_);
            uctx_ = nullptr;
        }
        ::memset(magic_, 0, sizeof(magic_));
    }

    template <typename F>
    coroutine spawn(F&& fn, size_t ss = COROUTINE_STACK_SIZE) &
    {
        coroutine co;
        if constexpr (std::is_invocable_v<F, const context&>) {
            co = coroutine(coro_without_init(std::forward<F>(fn)), ss, this);
        } else if constexpr (std::is_invocable_v<F, const context&, co_arg_type&&>) {
            co = coroutine(coro_with_init(std::forward<F>(fn)), ss, this);
        } else {
            static_assert(detail::always_false_v<F>, "invalid coroutine signature");
        }

#ifdef COROUTINE_USE_SETJMP
        std::lock_guard lk(mtx_);

        if (::sigaltstack(&co.state_->ss_, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaltstack");
        }

        struct sigaction act, oldact;
        ::sigemptyset(&act.sa_mask);
        act.sa_sigaction = spawn_handler;
        act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND | SA_RESTART;
        if (::sigaction(SIGURG, &act, &oldact) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaction");
        }
        union sigval sv;
        sv.sival_ptr = co.state_.get();
        ::pthread_sigqueue(::pthread_self(), SIGURG, sv);

        stack_t oss = {};
        oss.ss_flags = SS_DISABLE;
        if (::sigaltstack(&oss, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaltstack");
        }
        if (::sigaction(SIGURG, &oldact, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaction");
        }
#endif

        return co;
    }

    template <typename F>
    coroutine spawn(F&& fn, size_t ss = COROUTINE_STACK_SIZE) && = delete;

  private:
#ifdef COROUTINE_USE_SETJMP
    static void spawn_handler(int signum, siginfo_t* si, void*)
    {
        assert(signum == SIGURG);

        auto* state = (coroutine_env<G, A>::state*)si->si_value.sival_ptr;
        if (::setjmp(state->uctx_) == 0) {
            return;
        }

        auto ptr = (uintptr_t)state;
        state::entry((unsigned)(ptr >> 32), (unsigned)(ptr & 0xffffffffU));
        if (!state->env_ || ::memcmp(state->env_, MAGIC, sizeof(MAGIC)) != 0) {
            throw std::invalid_argument("coroutine_env: env expired");
        }

        state->finished_ = true;
        ::longjmp(*state->env_->uctx_, 1);
    }
#endif
};

using coro_env = coroutine_env<detail::co_null_type, detail::co_null_type>;
using coroutine = coro_env::coroutine;

}  // namespace tbd

#endif
