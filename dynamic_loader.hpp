#ifndef DYNAMIC_LOADER_HPP_
#define DYNAMIC_LOADER_HPP_

#include <dlfcn.h>

#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace tbd {

class dynamic_loader
{
    class function
    {
      public:
        explicit function(void* fn) noexcept
            : fn_(fn)
        {
        }

        template <typename R, typename... Args>
        R call(Args... args) const
        {
            return reinterpret_cast<R (*)(Args...)>(fn_)(args...);
        }

      private:
        void* fn_ = nullptr;
    };

  public:
    explicit dynamic_loader(std::string_view filename)
        : handle_(::dlopen(filename.data(), RTLD_LAZY))
    {
        if (!handle_) {
            throw std::system_error(ELIBACC, std::generic_category());
        }
    }

    dynamic_loader(const dynamic_loader&) = delete;
    dynamic_loader& operator=(const dynamic_loader&) = delete;
    dynamic_loader(dynamic_loader&& rhs) noexcept
        : handle_(std::exchange(rhs.handle_, nullptr))
        , cache_(std::move(rhs.cache_))
    {
    }
    dynamic_loader& operator=(dynamic_loader&& rhs) noexcept
    {
        if (this != &rhs) {
            close_();
            handle_ = std::exchange(rhs.handle_, nullptr);
            cache_ = std::move(rhs.cache_);
        }
        return *this;
    }

    ~dynamic_loader() noexcept
    {
        close_();
    }

    const function& operator[](std::string_view symbol)
    {
        auto it = cache_.find(symbol.data());
        if (it == cache_.end()) {
            ::dlerror();
            auto ptr = ::dlsym(handle_, symbol.data());
            if (char* err = ::dlerror()) {
                throw std::system_error(ELIBEXEC, std::generic_category(), err);
            }
            std::tie(it, std::ignore) = cache_.emplace(symbol, function(ptr));
        }
        return it->second;
    }

  private:
    void* handle_ = nullptr;
    std::unordered_map<std::string, function> cache_;

    void close_() noexcept
    {
        if (handle_) {
            ::dlclose(handle_);
            handle_ = nullptr;
        }
    }
};

}  // namespace tbd

#endif
