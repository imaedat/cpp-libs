#ifndef DYNLOADER_HPP_
#define DYNLOADER_HPP_

#include <dlfcn.h>

#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace tbd {

class dynloader
{
    struct string_like_hash
    {
        using is_transparent = void;
        size_t operator()(const std::string& s) const noexcept
        {
            return std::hash<std::string>{}(s);
        }
        size_t operator()(std::string_view sv) const noexcept
        {
            return std::hash<std::string_view>{}(sv);
        }
        size_t operator()(const char* s) const noexcept
        {
            return std::hash<std::string_view>{}(s);
        }
    };

    struct string_like_equal
    {
        using is_transparent = void;
        bool operator()(const std::string& s1, const std::string& s2) const noexcept
        {
            return s1 == s2;
        }
        bool operator()(const std::string& s1, std::string_view s2) const noexcept
        {
            return s1 == s2;
        }
        bool operator()(std::string_view s1, const std::string& s2) const noexcept
        {
            return s1 == s2;
        }
        bool operator()(const std::string& s1, const char* s2) const noexcept
        {
            return s1 == s2;
        }
        bool operator()(const char* s1, const std::string& s2) const noexcept
        {
            return s1 == s2;
        }
    };

    class libfunc
    {
      public:
        explicit libfunc(void* fnptr) noexcept
            : fnptr_(fnptr)
        {
        }

        template <typename R, typename... Args>
        R call(Args... args) const
        {
            return ((R(*)(Args...))fnptr_)(args...);
        }

      private:
        void* fnptr_ = nullptr;
    };

  public:
    explicit dynloader(std::string_view libname)
        : handle_(::dlopen(libname.data(), RTLD_LAZY))
    {
        if (!handle_) {
            throw std::system_error(ELIBACC, std::generic_category());
        }
    }

    dynloader(const dynloader&) = delete;
    dynloader& operator=(const dynloader&) = delete;
    dynloader(dynloader&& rhs) noexcept
        : handle_(std::exchange(rhs.handle_, nullptr))
        , cache_(std::exchange(rhs.cache_, {}))
    {
    }
    dynloader& operator=(dynloader&& rhs) noexcept
    {
        if (this != &rhs) {
            release();
            handle_ = std::exchange(rhs.handle_, nullptr);
            cache_ = std::exchange(rhs.cache_, {});
        }
        return *this;
    }

    ~dynloader()
    {
        release();
    }

    const libfunc& operator[](std::string_view fname)
    {
        auto it = cache_.find(fname.data());
        if (it == cache_.end()) {
            ::dlerror();
            auto fnptr = ::dlsym(handle_, fname.data());
            if (char* err = ::dlerror()) {
                throw std::system_error(ELIBEXEC, std::generic_category(), err);
            }
            std::tie(it, std::ignore) = cache_.emplace(fname, libfunc(fnptr));
        }
        return it->second;
    }

  private:
    void* handle_ = nullptr;
    std::unordered_map<std::string, libfunc, string_like_hash, string_like_equal> cache_;

    void release() noexcept
    {
        if (handle_) {
            ::dlclose(handle_);
            handle_ = nullptr;
        }
    }
};

}  // namespace tbd

#endif
