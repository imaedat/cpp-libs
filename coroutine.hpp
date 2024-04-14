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
#define COROUTINE_STACK_SIZE (4 * 1024)
#endif

namespace tbd {

template <typename T>
class coroutine
{
    using Func = std::function<void()>;

    class routine
    {
        friend class coroutine<T>;

      public:
        routine(const routine&) = delete;
        routine& operator=(const routine&) = delete;

        ~routine()
        {
            if (stack_) {
                mprotect(stack_, sysconf(_SC_PAGE_SIZE), PROT_WRITE);
                free(stack_);
                stack_ = nullptr;
            }
        }

      private:
        Func fn_;
        size_t stack_size_;
        char *stack_;
        bool finished_;
        ucontext_t *parent_;
        ucontext_t ctx_;

        explicit routine(Func&& fn, size_t ss, ucontext_t *parent)
            : fn_(std::forward<Func>(fn))
            , stack_size_(ss)
            , stack_(nullptr)
            , finished_(false)
            , parent_(parent)
        {
            if (getcontext(&ctx_) < 0) {
                throw std::system_error(errno, std::generic_category(),
                        "routine: getcontext");
            }

            size_t pagesz = sysconf(_SC_PAGE_SIZE);
            stack_ = (char *)aligned_alloc(pagesz, pagesz + stack_size_);
            if (!stack_) {
                throw std::bad_alloc();
            }
            mprotect(stack_, pagesz, PROT_NONE);  // guard page

            ctx_.uc_stack.ss_sp = stack_ + pagesz;
            ctx_.uc_stack.ss_size = stack_size_;
            ctx_.uc_link = parent_;

            makecontext(&ctx_, (void (*)())&execute, 1, this);
        }

        static void execute(routine *r)
        {
            r->fn_();
            r->finished_ = true;
        }
    };  // class routine

  public:
    coroutine(size_t ss = COROUTINE_STACK_SIZE)
        : stack_size_(ss)
        , current_(nullptr)
    {
        //
    }

    coroutine(const coroutine&) = delete;
    coroutine& operator=(const coroutine&) = delete;

    ~coroutine() = default;

    routine spawn(Func&& fn)
    {
        return routine(std::forward<Func>(fn), stack_size_, &own_ctx_);
    }

    T resume(routine& r)
    {
        assert(!current_);
        assert(r.parent_ == &own_ctx_);

        if (r.finished_) {
#ifdef COROUTINE_FINISHED_ROUTEINE_RESUMABLE
            return T{};
#else
            throw std::invalid_argument("coroutine::resume: routine already finished");
#endif
        }

        current_ = &r;
        if (swapcontext(&own_ctx_, &current_->ctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "coroutine::resume: swapcontext");
        }

        if (last_value_) {
            // on yield w/ value
            auto val = std::move(*last_value_);
            last_value_ = std::nullopt;
            return val;

        } else {
            // on return, or on yield w/o value
            current_ = nullptr;
            return T{};  // `T` must be default constructible
        }
    }

    void yield(std::optional<T>&& v = {})
    {
        assert(current_);

        last_value_ = std::forward<std::optional<T>>(v);
        auto *cur_ctx = &current_->ctx_;
        current_ = nullptr;
        if (swapcontext(cur_ctx, &own_ctx_) < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "coroutine::yield: swapcontext");
        }
    }

    void exit(std::optional<T>&& v = {})
    {
        assert(current_);
        current_->finished_ = true;
        yield(std::forward<std::optional<T>>(v));
    }

  private:
    size_t stack_size_;
    routine *current_;
    ucontext_t own_ctx_;
    std::optional<T> last_value_;
};

}  // namespace tbd

#endif
