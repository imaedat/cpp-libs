#ifndef POPEN_HPP_
#define POPEN_HPP_

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>

namespace tbd {

class popen
{
  public:
    template <typename... Args>
    popen(const Args&... args)
    {
        std::string cmd;
        cmd.reserve(128);
        (cmd += ... += to_string(args));

        fp_ = ::popen(cmd.c_str(), "r");
        if (!fp_) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    popen(const popen&) = delete;
    popen& operator=(const popen&) = delete;
    popen(popen&& rhs) noexcept
        : fp_(rhs.fp_)
    {
        rhs.fp_ = nullptr;
    }
    popen& operator=(popen&& rhs) noexcept
    {
        if (this != &rhs) {
            if (fp_) {
                ::pclose(fp_);
            }
            fp_ = rhs.fp_;
            rhs.fp_ = nullptr;
        }
        return *this;
    }

    ~popen()
    {
        if (fp_) {
            ::pclose(fp_);
            fp_ = nullptr;
        }
    }

    std::optional<std::string> getline()
    {
        char buf[BUFSIZ] = {0};
        if (!::fgets(buf, BUFSIZ, fp_)) {
            return std::nullopt;
        }

        auto len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
        return buf;
    }

  private:
    FILE* fp_ = nullptr;

    template <typename T>
    std::string to_string(const T& value)
    {
        if constexpr (std::is_convertible_v<T, std::string_view>) {
            return std::string(std::string_view(value));
        } else if constexpr (std::is_arithmetic_v<T>) {
            return std::to_string(value);
        }

        static_assert(std::is_convertible_v<T, std::string_view> || std::is_arithmetic_v<T>,
                      "Unsupported type for string concatenation");
        return "";
    }
};

}  // namespace tbd

#endif
