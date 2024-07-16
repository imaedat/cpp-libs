#ifndef COROUTINE_HPP_
#define COROUTINE_HPP_

#include <stdlib.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include <cassert>
#include <functional>
#include <optional>
#include <system_error>

#ifndef COROUTINE_STACK_SIZE
#define COROUTINE_STACK_SIZE (8 * 1024)
#endif

namespace tbd {

template <typename T = int>
class coroutine_env
{
    using Func = std::function<void(coroutine_env<T>&)>;

    class coroutine
    {
        friend class coroutine_env<T>;

      public:
        coroutine(const coroutine&) = delete;
        coroutine& operator=(const coroutine&) = delete;
        coroutine(coroutine&&) noexcept = default;
        coroutine& operator=(coroutine&&) noexcept = default;

        ~coroutine()
        {
            if (stack_) {
                mprotect(stack_, sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                free(stack_);
                stack_ = nullptr;
            }
        }

        std::optional<T> resume()
        {
            return env_.resume(this);
        }

      private:
        Func fn_;
        size_t stack_size_;
        char *stack_;
        bool finished_;
        coroutine_env<T> &env_;
        ucontext_t uctx_;

        coroutine(Func&& fn, size_t ss, coroutine_env<T> &env)
            : fn_(std::forward<Func>(fn))
            , stack_size_(ss)
            , stack_(nullptr)
            , finished_(false)
            , env_(env)
        {
            if (getcontext(&uctx_) < 0) {
                throw std::system_error(errno, std::generic_category(),
                        "coroutine: getcontext");
            }

            size_t pagesz = sysconf(_SC_PAGE_SIZE);
            stack_ = (char *)aligned_alloc(pagesz, pagesz + stack_size_);
            if (!stack_) {
                throw std::bad_alloc();
            }
            mprotect(stack_, pagesz, PROT_NONE);  // guard page

            uctx_.uc_stack.ss_sp = stack_ + pagesz;
            uctx_.uc_stack.ss_size = stack_size_;
            uctx_.uc_link = &env_.uctx_;

            makecontext(&uctx_, (void (*)())&execute, 1, this);
        }

        static void execute(coroutine *co)
        {
            std::exception_ptr ep;

            try {
                co->fn_(co->env_);
            } catch (...) {
                ep = std::current_exception();
            }

            co->finished_ = true;

            if (ep) {
                std::rethrow_exception(ep);
            }
        }
    };  // class coroutine

    friend class coroutine;

  public:
    coroutine_env() noexcept : current_(nullptr)
    {
        //
    }

    coroutine_env(const coroutine_env&) = delete;
    coroutine_env& operator=(const coroutine_env&) = delete;
    coroutine_env(coroutine_env&&) noexcept = default;
    coroutine_env& operator=(coroutine_env&&) noexcept = default;

    ~coroutine_env() = default;

    coroutine spawn(Func&& fn, size_t ss = COROUTINE_STACK_SIZE)
    {
        return coroutine(std::forward<Func>(fn), ss, *this);
    }

    void yield(std::optional<T>&& v = {})
    {
        assert(current_);
        assert(&current_->env_.uctx_ == &uctx_);

        last_value_ = std::forward<std::optional<T>>(v);
        auto *cur_ctx = &current_->uctx_;
        current_ = nullptr;
        if (swapcontext(cur_ctx, &uctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "coroutine_env::yield: swapcontext");
        }
    }

    void exit(std::optional<T>&& v = {})
    {
        assert(current_);
        current_->finished_ = true;
        yield(std::forward<std::optional<T>>(v));
    }

  private:
    ucontext_t uctx_;
    coroutine *current_;
    std::optional<T> last_value_;

    std::optional<T> resume(coroutine *co)
    {
        assert(!current_);

        if (co->finished_) {
#ifdef COROUTINE_EXCEPTION_AGAINST_FINISHED
            throw std::invalid_argument(
                    "coroutine_env::resume: coroutine already finished");
#else
            return std::nullopt;
#endif
        }

        current_ = co;
        if (swapcontext(&uctx_, &current_->uctx_) < 0) {
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
};

}  // namespace tbd

#endif
