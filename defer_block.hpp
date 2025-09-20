#ifndef DEFER_BLOCK_HPP_
#define DEFER_BLOCK_HPP_

#include <functional>
#include <type_traits>

namespace tbd {

class defer_block
{
  public:
    template <typename F, typename = std::enable_if_t<std::is_invocable_v<F>>>
    explicit defer_block(F&& fn) noexcept
        : fn_(std::forward<F>(fn))
    {
    }

    defer_block(const defer_block&) = delete;
    defer_block& operator=(const defer_block&) = delete;
    defer_block(defer_block&& rhs) noexcept
        : fn_(std::move(rhs.fn_))
    {
    }
    defer_block& operator=(defer_block&& rhs) noexcept
    {
        if (this != &rhs) {
            fn_ = std::move(rhs.fn_);
        }
        return *this;
    }

    ~defer_block() noexcept
    {
        try {
            fn_();
        } catch (...) {
            // ignore
        }
    }

  private:
    std::function<void()> fn_;
};

}  // namespace tbd

#endif
