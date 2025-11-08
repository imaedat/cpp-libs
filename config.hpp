#ifndef CONFIG_HPP_
#define CONFIG_HPP_

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>

namespace tbd {

class config
{
  public:
    config() noexcept = default;
    explicit config(std::string_view file)
    {
        parse(file);
    }

    template <typename T>
    T get(std::string_view key, T defval = {}) const
    {
        auto it = config_.find(key.data());
        if (it == config_.end()) {
            return defval;
        }

        const auto& sval = it->second;

        if constexpr (std::is_same_v<T, std::string>) {
            return sval;

        } else if constexpr (std::is_same_v<T, bool>) {
            std::string bval(sval);
            std::transform(bval.begin(), bval.end(), bval.begin(), ::tolower);
            if (bval == "true") {
                return true;
            }
            if (bval == "false") {
                return false;
            }

        } else if constexpr (std::is_integral_v<T>) {
            errno = 0;
            char* endptr = nullptr;
            auto result = ::strtoll(sval.c_str(), &endptr, 0);
            if (errno == 0 && endptr && endptr != sval.c_str() && *endptr == '\0') {
                return (T)result;
            }

        } else if constexpr (std::is_floating_point_v<T>) {
            errno = 0;
            char* endptr = nullptr;
            auto result = ::strtod(sval.c_str(), &endptr);
            if (errno == 0 && endptr && endptr != sval.c_str() && *endptr == '\0') {
                return (T)result;
            }
        }

        return defval;
        // throw std::bad_cast();
    }

  private:
    std::unordered_map<std::string, std::string> config_;

    void parse(std::string_view file)
    {
        std::ifstream ifs(file.data());
        if (!ifs) {
            throw std::system_error(errno, std::generic_category());
        }

        std::string line;
        while (std::getline(ifs, line)) {
            const auto& trimmed = trim(line);

            if (trimmed.empty() || trimmed[0] == '#') {
                continue;
            }

            auto eq_pos = trimmed.find('=');
            if (eq_pos == std::string_view::npos) {
                continue;
            }

            const auto& val = trim(trimmed.substr(eq_pos + 1));
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
                // quoted
                config_.emplace(trim(trimmed.substr(0, eq_pos)), val.substr(1, val.size() - 2));
            } else {
                config_.emplace(trim(trimmed.substr(0, eq_pos)), val);
            }
        }
    }

    template <typename S>
    std::string_view trim(const S& s) const noexcept
    {
        auto begin = s.find_first_not_of(" \t\r\n");
        if (begin == S::npos) {
            return "";
        }
        auto end = s.find_last_not_of(" \t\r\n");
        return std::string_view(&s[begin], end - begin + 1);
    }
};

}  // namespace tbd

#endif
