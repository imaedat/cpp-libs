#ifndef CMDOPT_HPP_
#define CMDOPT_HPP_

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace tbd {

namespace detail {
inline constexpr bool is_nul(const char* c) noexcept
{
    return *c == '\0';
}

inline constexpr bool is_hyphen(const char* c) noexcept
{
    return *c == '-';
}

template <typename T>
inline constexpr bool always_false_v = false;
}  // namespace detail

class cmdopt
{
    struct option
    {
        // definition
        char short_ = '\0';
        std::string long_;
        bool has_value = false;
        bool mandatory = false;
        std::string descr;
        std::string defval;

        // appearance
        bool exists = false;
        bool want_value = false;
        std::vector<std::string> values;

        option(char s, std::string_view l, std::string_view d)
            : short_(s)
            , long_(l)
            , descr(d)
        {
        }

        std::string repr() const
        {
            return short_ ? std::string{'-', short_} : "--" + long_;
        }

        std::string short_desc() const
        {
            std::ostringstream ss;
            ss << (mandatory ? " " : " [") << repr() << (has_value ? " <VALUE>" : "")
               << (mandatory ? "" : "]");
            return ss.str();
        }

        std::string long_desc() const
        {
            std::ostringstream ss;

            ss << "  ";
            if (short_) {
                ss << "-" << short_;
            } else {
                ss << "  ";
            }

            if (!long_.empty()) {
                ss << (short_ ? "," : " ") << " --" << long_;
            }

            if (has_value) {
                ss << (long_.empty() ? " " : "=") << "<VALUE>" << (long_.empty() ? "\t" : "");
            } else {
                ss << "\t";
            }

            ss << "\t\t" << descr;
            if (has_value && !mandatory) {
                ss << " [default=" << defval << "]";
            }

            return ss.str();
        }

        static option make_flag(char s, std::string_view l, std::string_view d)
        {
            return option(s, l, d);
        }

        static option make_mandatory(char s, std::string_view l, std::string_view d)
        {
            option o(s, l, d);
            o.has_value = true;
            o.mandatory = true;
            return o;
        }

        template <typename T>
        static option make_optional(char s, std::string_view l, T&& defval, std::string_view d)
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

    std::string progname_;
    std::vector<option> options_;
    std::unordered_map<char, size_t> short_indices_;
    std::unordered_map<std::string, size_t> long_indices_;

    std::vector<char*> plain_args_;

  public:
    cmdopt() noexcept = default;
    explicit cmdopt(std::string_view path)
        : progname_(std::filesystem::path(path).filename().c_str())
    {
    }
    ~cmdopt() noexcept = default;

    class cmdopt_error : public std::runtime_error
    {
      public:
        cmdopt_error(std::string_view what)
            : std::runtime_error(what.data())
        {
        }
    };

    /************************************************************************
     * define options
     */
    // bool flag option
    cmdopt& flag(char s, std::string_view l, std::string_view d)
    {
        assert_undefined(s, l);
        options_.emplace_back(option::make_flag(s, l, d));
        update_indices(s, l);
        return *this;
    }

    // mandatory valued option
    cmdopt& mandatory(char s, std::string_view l, std::string_view d)
    {
        assert_undefined(s, l);
        options_.emplace_back(option::make_mandatory(s, l, d));
        update_indices(s, l);
        return *this;
    }

    // optional valued option
    template <typename T>
    cmdopt& optional(char s, std::string_view l, T&& defval, std::string_view d)
    {
        assert_undefined(s, l);
        options_.emplace_back(option::make_optional(s, l, std::forward<T>(defval), d));
        update_indices(s, l);
        return *this;
    }

    std::string usage() const
    {
        std::ostringstream ss;
        ss << "usage: " << progname_;
        for (const auto& o : options_) {
            ss << o.short_desc();
        }
        ss << "\n\noptions:\n";
        for (const auto& o : options_) {
            ss << o.long_desc() << "\n";
        }
        return ss.str();
    }

    /************************************************************************
     * parse
     */
    std::optional<std::string> try_parse(int argc, char* argv[])
    {
        try {
            parse(argc, argv);
        } catch (const std::exception& e) {
            return e.what();
        }
        return std::nullopt;
    }

    void parse(int argc, char* argv[])
    {
        if (argc >= 1) {
            progname_.assign(std::filesystem::path(argv[0]).filename().c_str());
        }

        option* cur = nullptr;
        bool rest_are_plains = false;
        for (auto i = 1; i < argc; ++i) {
            char* c = argv[i];
            if (cur && cur->want_value) {
                cur->want_value = false;
                cur->values.emplace_back(c);
                cur = nullptr;
                continue;
            }

            cur = nullptr;
            if (!detail::is_hyphen(c) || detail::is_nul(c + 1) || rest_are_plains) {
                // "x..."             or "-" only              or after "--"
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
            throw cmdopt_error("option " + cur->repr() + " must specify value");
        }

        ensure_all_mandatories();
    }

    /************************************************************************
     * getter
     */
    template <typename S>
    bool exists(S name) const
    {
        return find_option(name).exists;
    }

    template <typename T, typename S>
    T get(S name) const
    {
        return get_<T>(find_option<S>(name));
    }

    template <typename T, typename S>
    std::vector<T> get_multi(S name) const
    {
        return get_multi_<T>(find_option<S>(name));
    }

    const std::vector<char*>& rest_args() const
    {
        return plain_args_;
    }

    /************************************************************************
     * privates
     */
  private:
    void assert_undefined(char s, std::string_view l) const
    {
        if (!s && l.empty()) {
            throw cmdopt_error("either short/long name must specified");
        }

        if (s && short_indices_.find(s) != short_indices_.cend()) {
            throw cmdopt_error("redefinition of option `" + std::string(1, s) + "'");
        }
        if (!l.empty() && long_indices_.find(l.data()) != long_indices_.cend()) {
            throw cmdopt_error(std::string("redefinition of option `") + l.data() + "'");
        }
    }

    void update_indices(char s, std::string_view l)
    {
        if (s != '\0') {
            short_indices_.emplace(s, options_.size() - 1);
        }
        if (!l.empty()) {
            long_indices_.emplace(l.data(), options_.size() - 1);
        }
    }

    // "-x"
    //   ^ start from
    option* parse_short(const char* c)
    {
        bool cont = false;
        do {
            cont = false;
            auto& o = find_option(*c++);
            o.exists = true;
            if (!o.has_value) {
                if (!detail::is_nul(c)) {
                    cont = true;
                }
            } else if (!detail::is_nul(c)) {
                o.values.emplace_back(c);
            } else {
                o.want_value = true;
                return &o;
            }
        } while (cont);

        return nullptr;
    }

    // "--x"
    //    ^ start from
    option* parse_long(const char* c)
    {
        std::string_view sv(c);
        auto eq = sv.find('=');
        auto key = eq != sv.npos ? sv.substr(0, eq) : sv;
        auto val = eq != sv.npos ? sv.substr(eq + 1) : "";

        auto& o = find_option(key);
        o.exists = true;
        if (!o.has_value) {
            if (!val.empty()) {
                throw cmdopt_error("option " + o.repr() + " does not take value");
            }
        } else if (!val.empty()) {
            o.values.emplace_back(val);
        } else {
            o.want_value = true;
            return &o;
        }

        return nullptr;
    }

    void ensure_all_mandatories() const
    {
        for (const auto& o : options_) {
            if (o.mandatory && !o.exists) {
                throw cmdopt_error("no mandatory option: " + o.repr());
            }
        }
    }

    template <typename S>
    const option& find_option(S name) const
    {
        if constexpr (std::is_same_v<std::decay_t<S>, char>) {
            auto it = short_indices_.find(name);
            if (it == short_indices_.cend()) {
                throw cmdopt_error("unknown short option `" + std::string(1, name) + "'");
            }
            return options_.at(it->second);

        } else if constexpr (std::is_convertible_v<std::decay_t<S>, std::string_view>) {
            std::string s(name);
            auto it = long_indices_.find(s);
            if (it == long_indices_.cend()) {
                throw cmdopt_error("unknown long option `" + s + "'");
            }
            return options_.at(it->second);

        } else {
            static_assert(detail::always_false_v<S>, "invalid type for option name");
        }
    }

    template <typename S>
    option& find_option(S name)
    {
        return const_cast<option&>(static_cast<const cmdopt*>(this)->find_option(name));
    }

    template <typename T>
    T get_(const option& o) const
    {
        if (!o.has_value) {
            throw cmdopt_error("option " + o.repr() + " is flag option, has no value");
        }
        return convert<T>(o, (o.mandatory || o.exists) ? o.values.back() : o.defval);
    }

    template <typename T>
    std::vector<T> get_multi_(const option& o) const
    {
        if (!o.has_value) {
            throw cmdopt_error("option " + o.repr() + " is flag option, has no value");
        }

        const auto& values = (o.mandatory || o.exists) ? o.values : std::vector{o.defval};
        std::vector<T> results;
        results.reserve(values.size());
        std::transform(values.cbegin(), values.cend(), std::back_inserter(results),
                       [this, &o](const auto& s) { return convert<T>(o, s); });
        return results;
    }

    template <typename T>
    T convert(const option& o, const std::string& value) const
    {
        char* endptr = nullptr;
        errno = 0;

        if constexpr (std::is_integral_v<T>) {
            auto result = ::strtoll(value.c_str(), &endptr, 0);
            if (errno == 0 && endptr && endptr != value.c_str() && *endptr == '\0') {
                return (T)result;
            }
            throw cmdopt_error("option " + o.repr() + " has no integer value: " + value);

        } else if constexpr (std::is_floating_point_v<T>) {
            auto result = ::strtod(value.c_str(), &endptr);
            if (errno == 0 && endptr && endptr != value.c_str() && *endptr == '\0') {
                return (T)result;
            }
            throw cmdopt_error("option " + o.repr() + " has no floating value: " + value);

        } else {
            static_assert(std::is_same_v<T, std::string>,
                          "only string support for non-numeric option values");
            return value;
        }
    }
};

}  // namespace tbd

#endif
