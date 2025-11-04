#ifndef CMDOPT_HPP_
#define CMDOPT_HPP_

#include <cstring>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace tbd {

namespace detail {
bool is_nul(const char* c) noexcept
{
    return *c == '\0';
}

bool is_hyphen(const char* c) noexcept
{
    return *c == '-';
}
}  // namespace detail

class cmdopt
{
    using string_view = std::string_view;

    struct option
    {
        // definition
        char short_ = '\0';
        std::string long_;
        bool has_value = false;
        bool mandatory = false;
        std::string descr;
        std::string defval;

        // appears
        bool exists = false;
        bool want_value = false;
        std::string value;

        option(char s, string_view l, string_view d)
            : short_(s)
            , long_(l)
            , descr(d)
        {
        }

        std::string surrogate() const
        {
            return !detail::is_nul(&short_) ? std::string("-") + short_ : std::string("--") + long_;
        }

        std::string to_string() const
        {
            std::ostringstream ss;
            ss << " ";
            if (short_) {
                ss << "-" << short_;
            } else {
                ss << "  ";
            }
            if (long_.empty()) {
                ss << "\t";
            } else if (short_) {
                ss << ", --" << long_;
            } else {
                ss << "  --" << long_;
            }
            if (has_value) {
                ss << " <VALUE>";
            } else {
                ss << "\t";
            }
            ss << "\t\t" << descr;
            if (has_value && !mandatory) {
                ss << " (default=" << defval << ")";
            }

            return ss.str();
        }

        static option make_flag(char s, string_view l, string_view d)
        {
            return option(s, l, d);
        }

        static option make_mandatory(char s, string_view l, string_view d)
        {
            option o(s, l, d);
            o.has_value = true;
            o.mandatory = true;
            return o;
        }

        template <typename T>
        static option make_optional(char s, string_view l, T&& defval, string_view d)
        {
            option o(s, l, d);
            o.has_value = true;
            o.mandatory = false;
            if constexpr (std::is_convertible_v<std::decay_t<T>, std::string_view>) {
                o.defval = defval;
            } else {
                o.defval = std::to_string(defval);
            }
            return o;
        }
    };

    std::vector<option> options_;
    std::unordered_map<char, size_t> short_indices_;
    std::unordered_map<std::string, size_t> long_indices_;

    std::vector<char*> plain_args_;

  public:
    cmdopt() noexcept = default;
    ~cmdopt() noexcept = default;

    class parse_error : public std::runtime_error
    {
      public:
        parse_error(string_view what)
            : std::runtime_error(what.data())
        {
        }
    };

    /************************************************************************
     * define options
     */
    // bool flag
    void flag(char s, string_view l, string_view descr)
    {
        options_.emplace_back(option::make_flag(s, l, descr));
        update_indices(s, l);
    }

    // mandatory valued flag
    void mandatory(char s, string_view l, string_view descr)
    {
        options_.emplace_back(option::make_mandatory(s, l, descr));
        update_indices(s, l);
    }

    // optional valued flag
    template <typename T>
    void optional(char s, string_view l, T&& defval, string_view descr)
    {
        options_.emplace_back(option::make_optional(s, l, std::forward<T>(defval), descr));
        update_indices(s, l);
    }

    std::string usage() const
    {
        std::ostringstream ss;
        for (const auto& o : options_) {
            ss << o.to_string() << "\n";
        }
        return ss.str();
    }

    /************************************************************************
     * parse
     */
    void parse(int argc, char* argv[])
    {
        option* cur = nullptr;
        bool rest_are_plains = false;
        for (auto i = 1; i < argc; ++i) {
            char* c = argv[i];
            if (cur && cur->want_value) {
                cur->want_value = false;
                cur->value = c;
                cur = nullptr;
                continue;
            }

            cur = nullptr;
            if (rest_are_plains) {
                plain_args_.push_back(c);
            } else if (!detail::is_hyphen(c)) {
                // "x..."
                plain_args_.push_back(c);
            } else if (detail::is_nul(c + 1)) {
                // "-"
                plain_args_.push_back(c);
            } else if (!detail::is_hyphen(++c)) {
                // "-x..."
                cur = parse_short(c);
            } else if (detail::is_nul(++c)) {
                // "--", stop parsing
                rest_are_plains = true;
            } else {
                // "--x..."
                cur = parse_long(c);
            }
        }

        if (cur && cur->want_value) {
            throw parse_error(std::string("option ") + cur->surrogate() + " must specify value");
        }

        ensure_all_mandatories();
    }

    /************************************************************************
     * getter
     */
    bool exists(char s)
    {
        return find_short(s).exists;
    }

    bool exists(string_view l)
    {
        return find_long(l).exists;
    }

    template <typename T>
    T get(char s)
    {
        return get_<T>(find_short(s));
    }

    template <typename T>
    T get(string_view l)
    {
        return get_<T>(find_long(l));
    }

    const std::vector<char*>& left_args() const
    {
        return plain_args_;
    }

    /************************************************************************
     * privates
     */
  private:
    void update_indices(char s, string_view l)
    {
        if (s != '\0') {
            short_indices_.emplace(s, options_.size() - 1);
        }
        if (!l.empty()) {
            long_indices_.emplace(l.data(), options_.size() - 1);
        }
    }

    // "-x"
    //   ^ start with
    option* parse_short(char* c)
    {
        bool cont = false;
        do {
            cont = false;
            auto& o = find_short(*c++);
            o.exists = true;
            if (!o.has_value) {
                if (!detail::is_nul(c)) {
                    cont = true;
                }
            } else if (!detail::is_nul(c)) {
                o.value = c;
            } else {
                o.want_value = true;
                return &o;
            }
        } while (cont);

        return nullptr;
    }

    // "--x"
    //    ^ start with
    option* parse_long(char* c)
    {
        std::string dup(c);
        c = (char*)dup.data();
        auto* val = ::strchr(c, '=');
        if (val) {
            *val = '\0';
            ++val;
        }

        auto& o = find_long(c);
        o.exists = true;
        if (o.has_value) {
            if (val) {
                o.value = val;
            } else {
                o.want_value = true;
                return &o;
            }
        }

        return nullptr;
    }

    void ensure_all_mandatories() const
    {
        for (const auto& o : options_) {
            if (o.mandatory && !o.exists) {
                throw parse_error(std::string("no mandatory option: ") + o.surrogate());
            }
        }
    }

    option& find_short(char s)
    {
        auto it = short_indices_.find(s);
        if (it == short_indices_.cend()) {
            throw parse_error(std::string("unknown short option `") + std::string(1, s) + "'");
        }
        return options_.at(it->second);
    }

    option& find_long(string_view l)
    {
        auto it = long_indices_.find(l.data());
        if (it == long_indices_.cend()) {
            throw parse_error(std::string("unknown long option `") + l.data() + "'");
        }
        return options_.at(it->second);
    }

    template <typename T>
    T get_(const option& o)
    {
        if (!o.has_value) {
            throw parse_error(std::string("option ") + o.surrogate() +
                              " is flag option, has no value");
        }
        const auto& value = (o.mandatory || o.exists) ? o.value : o.defval;

        if constexpr (std::is_integral_v<T>) {
            try {
                return std::stoll(value);
            } catch (...) {
                throw parse_error("option " + o.surrogate() + " has no integer value: " + value);
            }
        } else if constexpr (std::is_floating_point_v<T>) {
            try {
                return std::stod(value);
            } catch (...) {
                throw parse_error("option " + o.surrogate() + " has no floating value: " + value);
            }
        } else {
            return value;
        }
    }
};

}  // namespace tbd

#endif
