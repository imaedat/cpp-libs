#ifndef COROUTINE_HPP_
#define COROUTINE_HPP_

#include <sys/mman.h>
#ifdef COROUTINE_USE_SETJMP
#include <setjmp.h>
#include <signal.h>
#else
#include <ucontext.h>
#endif
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <type_traits>
#include <variant>

#ifndef COROUTINE_STACK_SIZE
#define COROUTINE_STACK_SIZE (8 * 1024)
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

  public:
    class coroutine;
    class yielder
    {
      public:
        co_arg_type operator()(co_gen_type&& g = {}) const
        {
            assert_env();
            return env_->yield(co_, std::forward<co_gen_type>(g));
        }

        void exit(co_gen_type&& g = {}) const
        {
            assert_env();
            env_->exit(co_, std::forward<co_gen_type>(g));
        }

      private:
        coroutine_env<G, A>* env_ = nullptr;
        coroutine* co_ = nullptr;

        yielder(coroutine_env<G, A>* env, coroutine* co) noexcept
            : env_(env)
            , co_(co)
        {
        }

        void assert_env() const
        {
            if (!env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("yielder: env expired");
            }
        }

        friend class coroutine;
    };

  private:
    using coro_without_init = std::function<void(const yielder&)>;
    using coro_with_init = std::function<void(const yielder&, co_arg_type&&)>;
    using coro_fn = std::variant<coro_without_init, coro_with_init>;

  public:
    class coroutine
    {
        friend class coroutine_env<G, A>;

      public:
        coroutine() = default;
        coroutine(const coroutine&) = delete;
        coroutine& operator=(const coroutine&) = delete;
        coroutine(coroutine&& rhs) noexcept
            : fn_(std::move(rhs.fn_))
            , stack_size_(std::exchange(rhs.stack_size_, 0))
            , stack_(std::exchange(rhs.stack_, nullptr))
            , finished_(std::exchange(rhs.finished_, true))
            , env_(std::exchange(rhs.env_, nullptr))
#ifdef COROUTINE_USE_SETJMP
            , ss_(std::exchange(rhs.ss_, {}))
#else
            , uctx_(std::exchange(rhs.uctx_, {}))
#endif
            , value_(std::move(rhs.value_))
            , exception_(std::move(rhs.exception_))
        {
#ifdef COROUTINE_USE_SETJMP
            ::memcpy(&uctx_, &rhs.uctx_, sizeof(jmp_buf));
#else
            ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
#endif
        }
        coroutine& operator=(coroutine&& rhs) noexcept
        {
            if (this != &rhs) {
                release_stack();
                fn_ = std::move(rhs.fn_);
                stack_size_ = std::exchange(rhs.stack_size_, 0);
                stack_ = std::exchange(rhs.stack_, nullptr);
                finished_ = std::exchange(rhs.finished_, true);
                env_ = std::exchange(rhs.env_, nullptr);
#ifdef COROUTINE_USE_SETJMP
                ss_ = std::exchange(rhs.ss_, {});
                ::memcpy(&uctx_, &rhs.uctx_, sizeof(jmp_buf));
#else
                uctx_ = std::exchange(rhs.uctx_, {});
#endif
                value_ = std::move(rhs.value_);
                exception_ = std::move(rhs.exception_);
#ifndef COROUTINE_USE_SETJMP
                ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
                // 1st argument of `entry`
                // uctx_.uc_mcontext.gregs[REG_RDI] = (greg_t)this;
#endif
            }
            return *this;
        }

        ~coroutine() noexcept
        {
            release_stack();
        }

        explicit operator bool() const noexcept
        {
            return !finished_;
        }

        co_gen_type resume(co_arg_type&& a = {})
        {
            if (!stack_ || !env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("coroutine: env expired");
            }
            return env_->resume(this, std::forward<co_arg_type>(a));
        }

      private:
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

        coroutine(coro_fn&& fn, size_t ss, coroutine_env<G, A>* env)
            : fn_(std::forward<coro_fn>(fn))
            , stack_size_(ss)
            , stack_(nullptr)
            , finished_(false)
            , env_(env)
        {
#ifndef COROUTINE_USE_SETJMP
            if (::getcontext(&uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(), "coroutine: getcontext");
            }
#endif

            size_t pagesz = ::sysconf(_SC_PAGE_SIZE);
            stack_size_ = (stack_size_ + pagesz - 1) & ~(pagesz - 1);  // align
            if (auto err = ::posix_memalign((void**)&stack_, pagesz, pagesz + stack_size_)) {
                throw std::system_error(err, std::generic_category(), "coroutine: posix_memalign");
            }
            ::mprotect(stack_, pagesz, PROT_NONE);  // guard page

#ifdef COROUTINE_USE_SETJMP
            ss_.ss_flags = 0;
            ss_.ss_size = stack_size_;
            ss_.ss_sp = stack_ + pagesz;
#else
            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = env_->uctx_.get();
            ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
#endif
        }

        static void entry(uintptr_t ptr) noexcept
        {
            auto* co = (coroutine*)ptr;
            try {
                if (auto fn = std::get_if<coro_without_init>(&co->fn_)) {
                    (*fn)(yielder(co->env_, co));
                } else if (auto fn = std::get_if<coro_with_init>(&co->fn_)) {
                    (*fn)(yielder(co->env_, co), std::move(co->value_));
                }
            } catch (...) {
                co->exception_ = std::current_exception();
            }

            co->finished_ = true;
        }

        void release_stack() noexcept
        {
            if (stack_) {
                ::mprotect(stack_, ::sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                ::free(stack_);
                stack_ = nullptr;
            }
        }
    };  // class coroutine

    /************************************************************************
     * coroutine_env
     */
  private:
    char magic_[4];
#ifdef COROUTINE_USE_SETJMP
    jmp_buf* uctx_ = nullptr;  // move safety
    inline static const int SIGSPAWN = SIGRTMAX - 1;
#else
    std::unique_ptr<ucontext_t> uctx_ = nullptr;  // move safety
#endif
    coroutine* current_ = nullptr;
    co_gen_type last_value_;

    friend class yielder;
    friend class coroutine;

  public:
    coroutine_env()
#ifndef COROUTINE_USE_SETJMP
        noexcept
        : uctx_(std::make_unique<ucontext_t>())
#endif
    {
        ::memcpy(magic_, MAGIC, sizeof(magic_));
#ifdef COROUTINE_USE_SETJMP
        uctx_ = (jmp_buf*)malloc(sizeof(jmp_buf));
        if (!uctx_) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: malloc");
        }
#endif
    }

    coroutine_env(const coroutine_env&) = delete;
    coroutine_env& operator=(const coroutine_env&) = delete;
    coroutine_env(coroutine_env&& rhs) noexcept
        : uctx_(std::move(rhs.uctx_))
        , current_(std::exchange(rhs.current_, nullptr))
        , last_value_(std::move(rhs.last_value_))
    {
        ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
        ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
    }
    coroutine_env& operator=(coroutine_env&& rhs) noexcept
    {
        if (this != &rhs) {
            ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
            ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
            uctx_ = std::move(rhs.uctx_);
            current_ = std::exchange(rhs.current_, nullptr);
            last_value_ = std::move(rhs.last_value_);
        }
        return *this;
    }

    ~coroutine_env() noexcept
    {
#ifdef COROUTINE_USE_SETJMP
        if (!uctx_) {
            ::free(uctx_);
        }
#endif
        ::memset(magic_, 0, sizeof(magic_));
    }

    template <typename F>
    coroutine spawn(F&& fn, size_t ss = COROUTINE_STACK_SIZE)
    {
        coroutine co;
        if constexpr (std::is_invocable_v<F, const yielder&>) {
            co = coroutine(coro_without_init(std::forward<F>(fn)), ss, this);
        } else if constexpr (std::is_invocable_v<F, const yielder&, co_arg_type&&>) {
            co = coroutine(coro_with_init(std::forward<F>(fn)), ss, this);
        } else {
            static_assert(detail::always_false_v<F>, "invalid coroutine signature");
        }

#ifdef COROUTINE_USE_SETJMP
        if (::sigaltstack(&co.ss_, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::spawn: sigaltstack");
        }

        struct sigaction act;
        act.sa_sigaction = spawn_handler;
        act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND | SA_RESTART;
        if (::sigaction(SIGSPAWN, &act, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::spawn: sigaction");
        }
        union sigval sv;
        sv.sival_ptr = &co;
        ::sigqueue(::getpid(), SIGSPAWN, sv);

        stack_t oss;
        oss.ss_flags = SS_DISABLE;
        if (::sigaltstack(&oss, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::spawn: sigaltstack");
        }
#endif

        return co;
    }

  private:
#ifdef COROUTINE_USE_SETJMP
    static void spawn_handler(int signum, siginfo_t* si, void*)
    {
        assert(signum == SIGSPAWN);

        auto* co = (coroutine*)si->si_value.sival_ptr;
        if (::setjmp(co->uctx_) == 0) {
            return;
        }

        coroutine::entry((uintptr_t)co);
        co->env_->exit(co);
    }
#endif

    co_gen_type resume(coroutine* co, co_arg_type&& r = {})
    {
        assert(!current_);
        if (co->finished_) {
            assert(!co->finished_);
            return std::nullopt;
        }

        co->value_ = std::move(r);
        current_ = co;
#ifdef COROUTINE_USE_SETJMP
        if (::setjmp(*uctx_) == 0) {
            ::longjmp(co->uctx_, 1);
        }
#else
        if (::swapcontext(uctx_.get(), &current_->uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: swapcontext");
        }
#endif

        current_ = nullptr;
        if (co->exception_) {
            auto ep = std::move(co->exception_);
            co->exception_ = nullptr;
            std::rethrow_exception(ep);
        }

        if (last_value_) {
            // on yield w/ value
            auto val = std::move(*last_value_);
            last_value_ = std::nullopt;
            return val;
        } else {
            // on return, or on yield w/o value
            return std::nullopt;
        }
    }

    co_arg_type yield(coroutine* co, co_gen_type&& g = {})
    {
        assert(current_);
#ifdef COROUTINE_USE_SETJMP
        assert(current_->env_->uctx_ == uctx_);
#else
        assert(current_->env_->uctx_.get() == uctx_.get());
#endif

        last_value_ = std::forward<co_gen_type>(g);
#ifdef COROUTINE_USE_SETJMP
        if (::setjmp(co->uctx_) == 0) {
            ::longjmp(*uctx_, 1);
        }
#else
        if (::swapcontext(&current_->uctx_, uctx_.get()) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: swapcontext");
        }
#endif

        return std::move(co->value_);
    }

    void exit(coroutine* co, co_gen_type&& g = {})
    {
        assert(current_);
        current_->finished_ = true;
        (void)yield(co, std::forward<co_gen_type>(g));
    }
};

using coro_env = coroutine_env<detail::co_null_type, detail::co_null_type>;
using coroutine = coro_env::coroutine;

}  // namespace tbd

#endif
