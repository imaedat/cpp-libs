#ifndef CONFIG_HPP_
#define CONFIG_HPP_

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>
#include <variant>

namespace tbd {

class config
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

  public:
    config() noexcept = default;
    explicit config(const std::string& file)
    {
        parse(file);
    }

    template <typename T>
    T get(std::string_view key, T defval = {}) const
    {
        auto it = config_.find(key.data());
        if (it != config_.end()) {
            if (auto val = std::get_if<T>(&it->second)) {
                return *val;
            }
        }
        return defval;
    }

  private:
    using value_type = std::variant<std::string, int, bool>;
    std::unordered_map<std::string, value_type, string_like_hash, string_like_equal> config_;

    void parse(const std::string& file)
    {
        std::ifstream ifs(file);
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

            config_.emplace(trim(trimmed.substr(0, eq_pos)),
                            parse_value(trim(trimmed.substr(eq_pos + 1))));
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

    value_type parse_value(const std::string_view& sval) const
    {
        // quoted
        if (sval.size() >= 2 && sval.front() == '"' && sval.back() == '"') {
            return std::string(&sval[1], sval.size() - 2);
        }

        // bool
        if (sval.size() == 4 || sval.size() == 5) {
            std::string bval(sval);
            std::transform(bval.begin(), bval.end(), bval.begin(), ::tolower);
            if (bval == "true") {
                return true;
            }
            if (bval == "false") {
                return false;
            }
        }

        // int
        char* endptr = nullptr;
        auto ival = ::strtol(sval.data(), &endptr, 0);
        if (*endptr == '\0') {
            return static_cast<int>(ival);
        }

        // string
        return std::string(sval);
    }
};

}  // namespace tbd

#endif
