#ifndef DEFER_BLOCK_HPP_
#define DEFER_BLOCK_HPP_

#include <functional>
#include <tuple>
#include <type_traits>

namespace tbd {

template <typename F, typename... Args>
class [[nodiscard]] defer_block
{
  public:
    explicit defer_block(F&& fn, Args&&... args)
        : fn_(std::forward<F>(fn))
        , args_(std::forward<Args>(args)...)
    {
    }

    defer_block(const defer_block&) = delete;
    defer_block& operator=(const defer_block&) = delete;
    defer_block(defer_block&&) = delete;
    defer_block& operator=(defer_block&&) = delete;

    ~defer_block() noexcept
    {
        try {
            std::apply(
                [this](auto&&... args) { std::invoke(fn_, std::forward<decltype(args)>(args)...); },
                args_);
        } catch (...) {
            // ignore
        }
    }

  private:
    F fn_;
    std::tuple<Args...> args_;
};

template <typename F, typename... Args>
defer_block(F&&, Args&&...) -> defer_block<std::decay_t<F>, std::decay_t<Args>...>;

}  // namespace tbd

#endif
