#ifndef DEFER_BLOCK_HPP_
#define DEFER_BLOCK_HPP_

#include <functional>

namespace tbd {

class defer_block
{
  public:
    explicit defer_block(std::function<void()>&& fn) noexcept
        : fn_(std::forward<std::function<void()>>(fn))
    {}

    defer_block(const defer_block&) = delete;
    defer_block& operator=(const defer_block&) = delete;
    defer_block(defer_block&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    defer_block& operator=(defer_block&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fn_, rhs.fn_);
        }
        return *this;
    }

    ~defer_block()
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
