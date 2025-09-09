#ifndef CONFIG_HPP_
#define CONFIG_HPP_

#include <algorithm>
#include <fstream>
#include <string>
#include <unordered_map>
#include <variant>

namespace tbd {

class config
{
    using value_type = std::variant<std::string, int, bool>;

    std::unordered_map<std::string, value_type> config_;

  public:
    config() = default;
    explicit config(const std::string& file)
    {
        parse(file);
    }

    template <typename T>
    T get(const std::string& key)
    {
        auto it = config_.find(key);
        if (it != config_.end()) {
            if (auto val = std::get_if<T>(&it->second)) {
                return *val;
            }
        }
        return T{};
    }

  private:
    void parse(const std::string& file)
    {
        std::ifstream ifs(file);
        if (!ifs) {
            throw std::system_error(errno, std::generic_category());
        }

        std::string line;
        while (std::getline(ifs, line)) {
            line = trim(line);

            if (line.empty() || line[0] == '#') {
                continue;
            }

            auto eq_pos = line.find('=');
            if (eq_pos == std::string::npos) {
                continue;
            }

            config_.emplace(trim(line.substr(0, eq_pos)),
                            parse_value(trim(line.substr(eq_pos + 1))));
        }
    }

    std::string trim(const std::string& s)
    {
        auto begin = s.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            return "";
        }
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(begin, end - begin + 1);
    }

    value_type parse_value(const std::string& sval)
    {
        // quoted
        if (sval.size() >= 2 && sval.front() == '"' && sval.back() == '"') {
            return sval.substr(1, sval.size() - 2);
        }

        // bool
        auto bval = sval;
        std::transform(bval.begin(), bval.end(), bval.begin(), ::tolower);
        if (bval == "true") {
            return true;
        }
        if (bval == "false") {
            return false;
        }

        // int
        char* endptr = nullptr;
        auto ival = ::strtol(sval.c_str(), &endptr, 10);
        if (*endptr == '\0') {
            return static_cast<int>(ival);
        }

        // string
        return sval;
    }
};

}  // namespace tbd

#endif
