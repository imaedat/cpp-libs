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
#define COROUTINE_STACK_SIZE (8 * 1024)
#endif

namespace tbd {

struct nulltype
{};

template <typename T = nulltype>
class coroutine_env
{
    using value_type = std::optional<T>;
    inline static constexpr char MAGIC[] = {0x7f, 'C', 'O', 'E'};

  public:
    class yielder
    {
      public:
        yielder() = default;
        void operator()(value_type&& v = {}) const
        {
            if (!env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("yielder::operator(): not initialized");
            }
            env_->yield(std::forward<value_type>(v));
        }

      private:
        coroutine_env<T>* env_ = nullptr;

        friend class coroutine_env<T>;
        explicit yielder(coroutine_env<T>* env) noexcept
            : env_(env)
        {}
    };

  private:
    using coro_fn = std::function<void(yielder&)>;

  public:
    class coroutine
    {
        friend class coroutine_env<T>;

      public:
        coroutine() = default;
        coroutine(const coroutine&) = delete;
        coroutine& operator=(const coroutine&) = delete;
        coroutine(coroutine&& rhs) noexcept
        {
            *this = std::move(rhs);
        }
        coroutine& operator=(coroutine&& rhs) noexcept
        {
            using std::swap;
            if (this != &rhs) {
                fn_.swap(rhs.fn_);
                stack_size_ = rhs.stack_size_;
                swap(stack_, rhs.stack_);
                swap(finished_, rhs.finished_);
                swap(env_, rhs.env_);
                uctx_ = rhs.uctx_;
            }
            return *this;
        }

        ~coroutine()
        {
            if (stack_) {
                ::mprotect(stack_, ::sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                ::free(stack_);
                stack_ = nullptr;
            }
        }

        value_type resume()
        {
            if (!stack_ || !env_ || ::memcmp(env_, MAGIC, sizeof(MAGIC)) != 0) {
                throw std::invalid_argument("coroutine::resume: not initialized");
            }
            return env_->resume(this);
        }

      private:
        coro_fn fn_;
        size_t stack_size_;
        char* stack_ = nullptr;
        bool finished_ = false;
        coroutine_env<T>* env_ = nullptr;
        ucontext_t uctx_;

        coroutine(coro_fn&& fn, size_t ss, coroutine_env<T>* env)
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
            stack_ = (char*)::aligned_alloc(pagesz, pagesz + stack_size_);
            if (!stack_) {
                throw std::bad_alloc();
            }
            ::mprotect(stack_, pagesz, PROT_NONE);  // guard page

            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = &env_->uctx_;

            ::makecontext(&uctx_, (void (*)()) & execute, 1, this);
        }

        static void execute(coroutine* co)
        {
            std::exception_ptr ep;

            try {
                co->fn_(co->env_->yielder_);
            } catch (...) {
                ep = std::current_exception();
            }

            co->finished_ = true;

            if (ep) {
                std::rethrow_exception(ep);
            }
        }
    };  // class coroutine

    friend class yielder;
    friend class coroutine;

  public:
    coroutine_env() noexcept
        : current_(nullptr)
        , yielder_(this)
    {
        ::memcpy(magic_, MAGIC, sizeof(magic_));
    }

    coroutine_env(const coroutine_env&) = delete;
    coroutine_env& operator=(const coroutine_env&) = delete;
    coroutine_env(coroutine_env&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    coroutine_env& operator=(coroutine_env&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            ::memcpy(&magic_, &rhs.magic_, sizeof(magic_));
            uctx_ = rhs.uctx_;
            swap(current_, rhs.current_);
            swap(last_value_, rhs.last_value_);
            swap(yielder_, rhs.yielder_);
        }
        return *this;
    }

    ~coroutine_env()
    {
        ::memset(magic_, 0, sizeof(magic_));
    }

    coroutine spawn(coro_fn&& fn, size_t ss = COROUTINE_STACK_SIZE)
    {
        return coroutine(std::forward<coro_fn>(fn), ss, this);
    }

#if 0
    void exit(value_type&& v = {})
    {
        assert(current_);
        current_->finished_ = true;
        yield(std::forward<value_type>(v));
    }
#endif

  private:
    char magic_[4];
    ucontext_t uctx_;
    coroutine* current_;
    value_type last_value_;
    yielder yielder_;

    value_type resume(coroutine* co)
    {
        assert(!current_);

        if (co->finished_) {
#ifdef COROUTINE_EXCEPTION_AGAINST_FINISHED
            throw std::invalid_argument("coroutine_env::resume: coroutine already finished");
#else
            return std::nullopt;
#endif
        }

        current_ = co;
        if (::swapcontext(&uctx_, &current_->uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::resume: swapcontext");
        }

        if (last_value_) {
            // on yield w/ value
            auto val = std::move(*last_value_);
            last_value_ = std::nullopt;
            return val;
        } else {
            // on return, or on yield w/o value
            current_ = nullptr;
            return std::nullopt;
        }
    }

    void yield(value_type&& v = std::nullopt)
    {
        assert(current_);
        assert(&current_->env_->uctx_ == &uctx_);

        last_value_ = std::forward<value_type>(v);
        auto* cur_ctx = &current_->uctx_;
        current_ = nullptr;
        if (::swapcontext(cur_ctx, &uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "coroutine_env::yield: swapcontext");
        }
    }
};

}  // namespace tbd

#endif
