#ifndef COROUTINE_HPP_
#define COROUTINE_HPP_

#include <pthread.h>
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

    struct context;
    class yielder
    {
      public:
        co_arg_type operator()(co_gen_type&& g = {}) const
        {
            assert_context();
            return ctx_->env_->yield(ctx_, std::forward<co_gen_type>(g));
        }

        void exit(co_gen_type&& g = {}) const
        {
            assert_context();
            ctx_->env_->exit(ctx_, std::forward<co_gen_type>(g));
        }

      private:
        context* ctx_ = nullptr;

        yielder(context* ctx) noexcept
            : ctx_(ctx)
        {
        }

        void assert_context() const
        {
            if (!ctx_) {
                throw std::invalid_argument("yielder: invalid context");
            }
            if (!ctx_->env_ || ::memcmp(ctx_->env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("yielder: env expired");
            }
        }

        friend class context;
    };

    using coro_without_init = std::function<void(const yielder&)>;
    using coro_with_init = std::function<void(const yielder&, co_arg_type&&)>;
    using coro_fn = std::variant<coro_without_init, coro_with_init>;

    struct context
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

        context(coro_fn&& fn, size_t ss, coroutine_env<G, A>* env)
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
            ss_.ss_sp = stack_ + pagesz;
            ss_.ss_size = stack_size_;
            ss_.ss_flags = 0;
            ::memset(&uctx_, 0, sizeof(jmp_buf));
#else
            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = env_->uctx_;
            ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
#endif
        }

        context(const context&) = delete;
        context& operator=(const context&) = delete;
        context(context&&) = delete;
        context& operator=(context&&) = delete;
        ~context() noexcept
        {
            if (stack_) {
                ::mprotect(stack_, ::sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                ::free(stack_);
                stack_ = nullptr;
            }
        }

        static void entry(uintptr_t ptr) noexcept
        {
            auto* ctx = (context*)ptr;
            try {
                if (auto fn = std::get_if<coro_without_init>(&ctx->fn_)) {
                    (*fn)(yielder(ctx));
                } else if (auto fn = std::get_if<coro_with_init>(&ctx->fn_)) {
                    (*fn)(yielder(ctx), std::move(ctx->value_));
                }
            } catch (...) {
                ctx->exception_ = std::current_exception();
            }

            ctx->finished_ = true;
        }
    };  // context

  public:
    class coroutine
    {
      public:
        coroutine() = default;
        coroutine(coroutine&&) noexcept = default;
        coroutine& operator=(coroutine&&) noexcept = default;

        explicit operator bool() const noexcept
        {
            return ctx_ && !ctx_->finished_;
        }

        co_gen_type resume(co_arg_type&& a = {})
        {
            if (!ctx_ || !ctx_->stack_) {
                throw std::invalid_argument("coroutine: invalid context");
            }
            if (!ctx_->env_ || ::memcmp(ctx_->env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("coroutine: env expired");
            }
            return ctx_->env_->resume(ctx_.get(), std::forward<co_arg_type>(a));
        }

      private:
        std::unique_ptr<context> ctx_ = nullptr;

        coroutine(coro_fn&& fn, size_t ss, coroutine_env<G, A>* env)
            : ctx_(std::make_unique<context>(std::forward<coro_fn>(fn), ss, env))
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
    context* current_ = nullptr;
    co_gen_type last_value_;

  public:
    coroutine_env()
#ifdef COROUTINE_USE_SETJMP
        : uctx_((jmp_buf*)malloc(sizeof(jmp_buf)))
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
            uctx_ = std::exchange(rhs.uctx_, nullptr);
            current_ = std::exchange(rhs.current_, nullptr);
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
        if (::sigaltstack(&co.ctx_->ss_, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaltstack");
        }

        struct sigaction act;
        ::sigemptyset(&act.sa_mask);
        act.sa_sigaction = spawn_handler;
        act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND | SA_RESTART;
        if (::sigaction(SIGURG, &act, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaction");
        }
        union sigval sv;
        sv.sival_ptr = co.ctx_.get();
        ::pthread_sigqueue(::pthread_self(), SIGURG, sv);

        stack_t oss = {};
        oss.ss_flags = SS_DISABLE;
        if (::sigaltstack(&oss, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: sigaltstack");
        }
#endif

        return co;
    }

  private:
#ifdef COROUTINE_USE_SETJMP
    static void spawn_handler(int signum, siginfo_t* si, void*)
    {
        assert(signum == SIGURG);

        auto* ctx = (context*)si->si_value.sival_ptr;
        if (::setjmp(ctx->uctx_) == 0) {
            return;
        }

        context::entry((uintptr_t)ctx);
        if (!ctx->env_ || ::memcmp(ctx->env_, MAGIC, sizeof(MAGIC)) != 0) {
            throw std::invalid_argument("coroutine: env expired");
        }
        ctx->env_->exit(ctx);
    }
#endif

    co_gen_type resume(context* ctx, co_arg_type&& r = {})
    {
        assert(!current_);
        if (ctx->finished_) {
            assert(!ctx->finished_);
            return std::nullopt;
        }

        ctx->value_ = std::move(r);
        current_ = ctx;
#ifdef COROUTINE_USE_SETJMP
        if (::setjmp(*uctx_) == 0) {
            ::longjmp(ctx->uctx_, 1);
        }
#else
        if (::swapcontext(uctx_, &current_->uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: swapcontext");
        }
#endif

        current_ = nullptr;
        if (ctx->exception_) {
            auto ep = std::move(ctx->exception_);
            ctx->exception_ = nullptr;
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

    co_arg_type yield(context* ctx, co_gen_type&& g = {})
    {
        assert(current_);
        assert(current_->env_->uctx_ == uctx_);

        last_value_ = std::forward<co_gen_type>(g);
#ifdef COROUTINE_USE_SETJMP
        if (::setjmp(ctx->uctx_) == 0) {
            ::longjmp(*uctx_, 1);
        }
#else
        if (::swapcontext(&current_->uctx_, uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(), "coroutine_env: swapcontext");
        }
#endif

        return std::move(ctx->value_);
    }

    void exit(context* ctx, co_gen_type&& g = {})
    {
        assert(current_);
        current_->finished_ = true;
        (void)yield(ctx, std::forward<co_gen_type>(g));
    }
};

using coro_env = coroutine_env<detail::co_null_type, detail::co_null_type>;
using coroutine = coro_env::coroutine;

}  // namespace tbd

#endif
