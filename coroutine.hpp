#ifndef COROUTINE_HPP_
#define COROUTINE_HPP_

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include <functional>
#include <optional>
#include <system_error>

#ifndef COROUTINE_STACK_SIZE
#    define COROUTINE_STACK_SIZE (8 * 1024)
#endif

namespace tbd {

namespace detail {
struct co_null_type
{};
}  // namespace detail

template <typename T = detail::co_null_type, typename U = detail::co_null_type>
class coroutine_env_tmpl
{
    using gen_type = std::optional<T>;
    using ret_type = std::optional<U>;
    inline static constexpr char MAGIC[] = {0x7f, 'C', 'O', 'E'};

  public:
    class coroutine;
    class yielder
    {
      public:
        ret_type operator()(gen_type&& v = {}) const
        {
            if (!env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("yielder::operator(): not initialized");
            }
            return env_->yield(co_, std::forward<gen_type>(v));
        }

      private:
        coroutine_env_tmpl<T, U>* env_ = nullptr;
        coroutine* co_ = nullptr;

        explicit yielder(coroutine_env_tmpl<T, U>* env, coroutine* co) noexcept
            : env_(env)
            , co_(co)
        {
        }

        friend class coroutine;
    };

  private:
    using coro_fn = std::function<void(const yielder&)>;

  public:
    class coroutine
    {
        friend class coroutine_env_tmpl<T, U>;

      public:
        coroutine() = default;
        coroutine(const coroutine&) = delete;
        coroutine& operator=(const coroutine&) = delete;
        coroutine(coroutine&& rhs) noexcept
            : fn_(std::move(rhs.fn_))
            , stack_size_(std::exchange(rhs.stack_size_, 0))
            , stack_(std::exchange(rhs.stack_, nullptr))
            , finished_(std::exchange(rhs.finished_, false))
            , env_(std::exchange(rhs.env_, nullptr))
            , uctx_(std::exchange(rhs.uctx_, {}))
            , value_(std::move(rhs.value_))
        {
        }
        coroutine& operator=(coroutine&& rhs) noexcept
        {
            if (this != &rhs) {
                fn_ = std::move(rhs.fn_);
                stack_size_ = std::exchange(rhs.stack_size_, 0);
                stack_ = std::exchange(rhs.stack_, nullptr);
                finished_ = std::exchange(rhs.finished_, false);
                env_ = std::exchange(rhs.env_, nullptr);
                uctx_ = std::exchange(rhs.uctx_, {});
                value_ = std::move(rhs.value_);
                ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
                // 1st argument of `entry`
                // uctx_.uc_mcontext.gregs[REG_RDI] = (greg_t)this;
            }
            return *this;
        }

        ~coroutine() noexcept
        {
            if (stack_) {
                ::mprotect(stack_, ::sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                ::free(stack_);
                stack_ = nullptr;
            }
        }

        gen_type resume(ret_type&& r = {})
        {
            if (!stack_ || !env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("coroutine::resume: not initialized");
            }
            return env_->resume(this, std::forward<ret_type>(r));
        }

      private:
        coro_fn fn_;
        size_t stack_size_;
        char* stack_ = nullptr;
        bool finished_ = false;
        coroutine_env_tmpl<T, U>* env_ = nullptr;
        ucontext_t uctx_;
        ret_type value_;
        std::exception_ptr exception_;

        coroutine(coro_fn&& fn, size_t ss, coroutine_env_tmpl<T, U>* env)
            : fn_(std::forward<coro_fn>(fn))
            , stack_size_(ss)
            , stack_(nullptr)
            , finished_(false)
            , env_(env)
        {
            if (::getcontext(&uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(), "coroutine: getcontext");
            }

            size_t pagesz = ::sysconf(_SC_PAGE_SIZE);
            // align stack_size_
            stack_size_ = (stack_size_ + pagesz - 1) & ~(pagesz - 1);
            stack_ = (char*)::aligned_alloc(pagesz, pagesz + stack_size_);
            if (!stack_) {
                throw std::bad_alloc();
            }
            ::mprotect(stack_, pagesz, PROT_NONE);  // guard page

            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = &env_->uctx_;

            ::makecontext(&uctx_, (void (*)()) & entry, 1, (uintptr_t)this);
        }

        static void entry(uintptr_t ptr)
        {
            auto* co = (coroutine*)ptr;
            try {
                co->fn_(yielder(co->env_, co));
            } catch (...) {
                co->exception_ = std::current_exception();
            }

            co->finished_ = true;
        }
    };  // class coroutine

    friend class yielder;
    friend class coroutine;

  public:
    coroutine_env_tmpl() noexcept
        : current_(nullptr)
    {
        ::memcpy(magic_, MAGIC, sizeof(magic_));
    }

    coroutine_env_tmpl(const coroutine_env_tmpl&) = delete;
    coroutine_env_tmpl& operator=(const coroutine_env_tmpl&) = delete;
    coroutine_env_tmpl(coroutine_env_tmpl&& rhs) noexcept
        : uctx_(std::exchange(rhs.uctx_, {}))
        , current_(std::exchange(rhs.current_, nullptr))
        , last_value_(std::move(rhs.last_value_))
    {
        ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
        ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
    }
    coroutine_env_tmpl& operator=(coroutine_env_tmpl&& rhs) noexcept
    {
        if (this != &rhs) {
            ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
            ::memset(&rhs.magic_, 0, sizeof(rhs.magic_));
            uctx_ = std::exchange(rhs.uctx_, {});
            current_ = std::exchange(rhs.current_, nullptr);
            last_value_ = std::move(rhs.last_value_);
        }
        return *this;
    }

    ~coroutine_env_tmpl() noexcept
    {
        ::memset(magic_, 0, sizeof(magic_));
    }

    coroutine spawn(coro_fn&& fn, size_t ss = COROUTINE_STACK_SIZE)
    {
        return coroutine(std::forward<coro_fn>(fn), ss, this);
    }

#if 0
    void exit(gen_type&& v = {})
    {
        assert(current_);
        current_->finished_ = true;
        yield(std::forward<gen_type>(v));
    }
#endif

  private:
    char magic_[4];
    ucontext_t uctx_;
    coroutine* current_;
    gen_type last_value_;

    gen_type resume(coroutine* co, ret_type&& r = {})
    {
        assert(!current_);

        if (co->finished_) {
#ifdef COROUTINE_EXCEPTION_AGAINST_FINISHED
            throw std::invalid_argument("coroutine_env::resume: coroutine already finished");
#else
            return std::nullopt;
#endif
        }

        co->value_ = std::move(r);
        current_ = co;
        if (::swapcontext(&uctx_, &current_->uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::resume: swapcontext");
        }

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

    ret_type yield(coroutine* co, gen_type&& v = {})
    {
        assert(current_);
        assert(&current_->env_->uctx_ == &uctx_);

        last_value_ = std::forward<gen_type>(v);
        if (::swapcontext(&current_->uctx_, &uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::yield: swapcontext");
        }

        return co->value_;
    }
};

using co_env = coroutine_env_tmpl<detail::co_null_type, detail::co_null_type>;
using co_yielder = coroutine_env_tmpl<detail::co_null_type, detail::co_null_type>::yielder;
using coroutine = coroutine_env_tmpl<detail::co_null_type, detail::co_null_type>::coroutine;

}  // namespace tbd

#endif
