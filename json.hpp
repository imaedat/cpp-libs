#ifndef JSON_HPP_
#define JSON_HPP_

#include <any>
#include <cassert>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace tbd {

class json
{
    [[noreturn]] static void throw_invalid(const std::string& f, std::string_view m, int c = -1)
    {
        std::string what = f + ": " + m.data();
        if (c > 0) {
            what.append(" (`");
            what.push_back((char)c);
            what.append("')");
        } else if (c == 0) {
            what.append(" (<nul>)");
        }
        throw std::invalid_argument(what);
    }

    using object_type = std::unordered_map<std::string, std::any>;
    using array_type = std::vector<std::any>;
    using result_type = std::pair<std::any, const char*>;
    using value_type = std::variant<bool, int64_t, double, std::string, json>;

    std::any value_;

  public:
    /************************************************************************
     * ctor & factory
     */
    json() noexcept = default;
    json(const json&) = default;
    json& operator=(const json&) = default;
    json(json&&) noexcept = default;
    json& operator=(json&&) noexcept = default;

    explicit json(const value_type& v)
    {
        std::visit([this](const auto& val) { this->operator=(val); }, v);
    }

    explicit json(const std::initializer_list<std::pair<std::string, value_type>>& list)
    {
        object_type obj;
        for (auto&& [k, v] : list) {
            bool holds_json = std::holds_alternative<json>(v);
            obj.emplace(k, holds_json ? std::move(std::get<json>(v)) : json(v));
        }
        value_ = std::move(obj);
    }

    static json parse(const std::string& s)
    {
        auto [j, p] = parse_value(ltrim(s.data()));
        p = ltrim(p);
        if (*p != '\0') {
            throw_invalid(__func__, "unexpected char", *p);
        }
        return *to_json_(j);
    }

    static json load(std::string_view file)
    {
        std::ifstream ifs(file.data());
        using iterator = std::istreambuf_iterator<char>;
        return parse(std::string(iterator(ifs), iterator()));
    }

    /************************************************************************
     * const attributes
     */
    bool is_null() const
    {
        return !value_.has_value();
    }

    bool is_object() const
    {
        return to_object_(value_) != nullptr;
    }

    bool is_array() const
    {
        return to_array_(value_) != nullptr;
    }

    bool empty() const
    {
        if (auto* obj = to_object_(value_)) {
            return obj->empty();
        }
        if (auto* arr = to_array_(value_)) {
            return arr->empty();
        }
        if (auto* str = to_string_(value_)) {
            if (quoted_(str)) {
                return *str == "\"\"";
            }
        }
        throw_invalid(__func__, "not container");
    }

    size_t size() const
    {
        if (auto* obj = to_object_(value_)) {
            return obj->size();
        }
        if (auto* arr = to_array_(value_)) {
            return arr->size();
        }
        if (auto* str = to_string_(value_)) {
            if (quoted_(str)) {
                return str->size() - 2;
            }
        }
        throw_invalid(__func__, "not container");
    }

    bool contains(std::string_view key) const
    {
        if (auto* obj = to_object_(value_)) {
            return obj->find(key.data()) != obj->end();
        }
        throw_invalid(__func__, "not object");
    }

    /************************************************************************
     * common operation
     */
    template <typename T, std::enable_if_t<!std::is_same_v<std::decay_t<T>, json>, bool> = true>
    json& operator=(T&& v)
    {
        using namespace std::string_literals;

        if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
            value_ = v ? "true"s : "false"s;
        } else if constexpr (std::is_convertible_v<std::decay_t<T>, std::string_view>) {
            value_ = "\""s + std::forward<T>(v) + "\"";
        } else {
            value_ = std::to_string(std::forward<T>(v));
        }
        return *this;
    }

    void clear()
    {
        if (auto* obj = to_object_(value_)) {
            obj->clear();
            return;

        } else if (auto* arr = to_array_(value_)) {
            arr->clear();
            return;

        } else if (auto* str = to_string_(value_)) {
            if (quoted_(str)) {
                str->assign("\"\"");
                return;
            }
        }

        throw_invalid(__func__, "not container");
    }

    void reset()
    {
        value_.reset();
    }

    /************************************************************************
     * object operator
     */
    const json& at(std::string_view key) const
    {
        if (auto* obj = to_object_(value_)) {
            if (auto it = obj->find(key.data()); it != obj->end()) {
                return *to_json_(it->second);
            }
            throw_invalid(__func__, "key not found");
        }
        throw_invalid(__func__, "not object");
    }

    json& operator[](std::string_view key)
    {
        if (is_null()) {
            value_ = object_type{};
        }
        if (auto* obj = to_object_(value_)) {
            auto it = obj->find(key.data());
            if (it == obj->end()) {
                std::tie(it, std::ignore) = obj->emplace(key, json{});
            }
            return *to_json_(it->second);
        }
        throw_invalid(__func__, "not object");
    }

    void erase(std::string_view key)
    {
        if (auto* obj = to_object_(value_)) {
            obj->erase(key.data());
            return;
        }
        throw_invalid(__func__, "not object");
    }

#if 1
    struct item_ref
    {
        const std::string& key;
        json& value;
    };

    struct object_iterator
    {
        object_type::iterator it;
        explicit object_iterator(object_type::iterator i)
            : it(i)
        {
        }
        item_ref operator*() const
        {
            return {it->first, *to_json_(it->second)};
        }
        object_iterator& operator++()
        {
            ++it;
            return *this;
        }
        bool operator==(const object_iterator& rhs) const
        {
            return it == rhs.it;
        }
        bool operator!=(const object_iterator& rhs) const
        {
            return !(*this == rhs);
        }
    };

    struct object_view
    {
        object_type* obj;
        object_iterator begin() const
        {
            return object_iterator(obj->begin());
        }
        object_iterator end() const
        {
            return object_iterator(obj->end());
        }
    };

    object_view items()
    {
        if (auto* obj = to_object_(value_)) {
            return object_view{obj};
        }
        throw_invalid(__func__, "not object");
    }
#endif

    /************************************************************************
     * array operator
     */
    const json& at(size_t i) const
    {
        if (auto* arr = to_array_(value_)) {
            if (i < arr->size()) {
                return *to_json_(arr->at(i));
            }
            throw_invalid(__func__, "out of range");
        }
        throw_invalid(__func__, "not array");
    }

    json& operator[](size_t i)
    {
        if (auto* arr = to_array_(value_)) {
            return *to_json_(arr->at(i));
        }
        throw_invalid(__func__, "not array");
    }

    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void push_back(J&& j)
    {
        if (is_null()) {
            array_type arr;
            arr.push_back(std::forward<J>(j));
            value_ = std::move(arr);

        } else if (auto* arr = to_array_(value_)) {
            arr->push_back(std::forward<J>(j));

        } else {
            throw_invalid(__func__, "not array");
        }
    }

    template <typename T, std::enable_if_t<!std::is_same_v<std::decay_t<T>, json>, bool> = true>
    void push_back(T&& v)
    {
        json j;
        j.operator=(std::forward<T>(v));
        push_back(std::move(j));
    }

#if 1
    struct array_iterator
    {
        array_type::iterator it;
        explicit array_iterator(array_type::iterator i)
            : it(i)
        {
        }
        json& operator*() const
        {
            return *to_json_(*it);
        }
        array_iterator& operator++()
        {
            ++it;
            return *this;
        }
        bool operator==(const array_iterator& rhs) const
        {
            return it == rhs.it;
        }
        bool operator!=(const array_iterator& rhs) const
        {
            return !(*this == rhs);
        }
    };

    array_iterator begin() const
    {
        if (auto* arr = to_array_(value_)) {
            return array_iterator(const_cast<array_type*>(arr)->begin());
        }
        throw_invalid(__func__, "not array");
    }

    array_iterator end() const
    {
        if (auto* arr = to_array_(value_)) {
            return array_iterator(const_cast<array_type*>(arr)->end());
        }
        throw_invalid(__func__, "not array");
    }
#endif

    /************************************************************************
     * value accessor
     */
    template <typename T>
    T get() const
    {
        if (auto* str = to_string_(value_)) {
            bool quoted = quoted_(str);
            std::string_view sv(str->data() + (quoted ? 1 : 0), str->size() - (quoted ? 2 : 0));
            char* endptr = nullptr;
            errno = 0;

            if constexpr (std::is_same_v<T, std::string>) {
                if (quoted) {
                    return unescape_(sv);
                }

            } else if constexpr (std::is_same_v<T, bool>) {
                if (!quoted) {
                    if (sv == "true") {
                        return true;
                    }
                    if (sv == "false") {
                        return false;
                    }
                }

            } else if constexpr (std::is_integral_v<T>) {
                if (!quoted) {
                    auto ival = std::strtoll(sv.data(), &endptr, 0);
                    if (errno == 0 && endptr && endptr != sv.data() && *endptr == '\0') {
                        return (T)ival;
                    }
                }

            } else if constexpr (std::is_floating_point_v<T>) {
                if (!quoted) {
                    auto fval = std::strtod(sv.data(), &endptr);
                    if (errno == 0 && endptr && endptr != sv.data() && *endptr == '\0') {
                        return (T)fval;
                    }
                }
            }

            throw_invalid(__func__, "type error");
        }
        throw_invalid(__func__, "not primitive");
    }

    /************************************************************************
     * stringify
     */
    std::string to_string() const
    {
        std::ostringstream ss;
        stringify_(ss, this);
        return ss.str();
    }

  private:
    /************************************************************************
     * parse
     */
    static result_type parse_value(const char* p)
    {
        switch (*p) {
        case '{':
            return parse_object(p);

        case '[':
            return parse_array(p);

        case '"':
            return parse_string(p);

        // clang-format off
        case '0': case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9': case '-': case '.':
            // clang-format on
            return parse_number(p);

        // clang-format off
        case 't': case 'f': case 'n':
            // clang-format on
            return parse_bool(p);

        case '\0':
            return {json{}, p};

        default:
            throw_invalid(__func__, "unexpected char", *p);
        }
    }

    template <typename V>
    static json json_value(V&& v)
    {
        json j;
        j.value_ = std::forward<V>(v);
        return j;
    }

    static result_type parse_object(const char* p)
    {
        assert(*p == '{');
        auto q = ltrim(p + 1);
        object_type obj;
        bool comma = false;
        while (*q != '}') {
            if (*q != '"') {
                throw_invalid(__func__, "key not start with quote", *q);
            }

            auto [k, r] = parse_string(q, true);
            q = r;
            if (*q++ != ':') {
                throw_invalid(__func__, "key-value not separated with colon", *(q - 1));
            }
            auto [v, s] = parse_value(ltrim(q));
            q = s;
            auto* key = to_string_(to_json_(k)->value_);
            obj.emplace(std::move(*key), std::move(v));

            q = ltrim((comma = *q == ',') ? q + 1 : q);
            if (!comma) {
                break;
            }
        }
        if (comma) {
            throw_invalid(__func__, "next key-value expected", *q);
        }
        if (*q != '}') {
            throw_invalid(__func__, "object not end with right-brace", *q);
        }
        return {json_value(std::move(obj)), ltrim(q + 1)};
    }

    static result_type parse_array(const char* p)
    {
        assert(*p == '[');
        auto q = ltrim(p + 1);
        array_type arr;
        bool comma = false;
        while (*q != ']') {
            auto [v, r] = parse_value(q);
            q = r;
            arr.emplace_back(std::move(v));
            q = ltrim((comma = *q == ',') ? q + 1 : q);
            if (!comma) {
                break;
            }
        }
        if (comma) {
            throw_invalid(__func__, "next value expected", *q);
        }
        if (*q != ']') {
            throw_invalid(__func__, "array not end with right-bracket", *q);
        }
        return {json_value(std::move(arr)), ltrim(q + 1)};
    }

    static result_type parse_string(const char* p, bool trim_quote = false)
    {
        assert(*p == '"');
        bool escape = false;
        auto q = p + 1;
        while (true) {
            char c = *q++;
            if (c == '\0') {
                throw_invalid(__func__, "unexpected eof");
            }
            if (c == '\\') {
                escape = !escape;
            } else if (c == '"' && !escape) {
                break;
            } else {
                escape = false;
            }
        }
        auto loff = trim_quote ? 1 : 0;
        auto roff = trim_quote ? 2 : 0;
        return {json_value(std::string(p + loff, q - p - roff)), ltrim(q)};
    }

    static result_type parse_number(const char* p)
    {
        auto q = p;
        if (*q == '-') {
            ++q;
        }

        ssize_t len1 = -1, len2 = -1, len3 = -1;
        q += (len1 = std::strspn(q, "0123456789"));  // int
        if (*q == '.') {
            q += (len2 = std::strspn(++q, "0123456789"));  // frac
        }
        if (*q == 'e' || *q == 'E') {  // exp
            ++q;
            if (*q == '+' || *q == '-') {
                ++q;
            }
            q += (len3 = std::strspn(q, "0123456789"));
        }
        std::string n(p, q - p);
        if ((len1 <= 0 && len2 <= 0) || len3 == 0) {
            throw_invalid(__func__, "invalid numeric: " + n);
        }
        return {json_value(std::move(n)), q};
    }

    static result_type parse_bool(const char* p)
    {
        if (std::strncmp(p, "true", 4) == 0) {
            return {json_value(std::string("true")), ltrim(p + 4)};
        }
        if (std::strncmp(p, "false", 5) == 0) {
            return {json_value(std::string("false")), ltrim(p + 5)};
        }
        if (std::strncmp(p, "null", 4) == 0) {
            return {json{}, ltrim(p + 4)};
        }
        throw_invalid(__func__, "unexpected literal", *p);
    }

    static const char* ltrim(const char* p) noexcept
    {
        return p + std::strspn(p, " \t\r\n");
    }

    /************************************************************************
     * any cast
     */
    static const object_type* to_object_(const std::any& v)
    {
        return std::any_cast<object_type>(&v);
    }

    static object_type* to_object_(std::any& v)
    {
        return std::any_cast<object_type>(&v);
    }

    static const array_type* to_array_(const std::any& v)
    {
        return std::any_cast<array_type>(&v);
    }

    static array_type* to_array_(std::any& v)
    {
        return std::any_cast<array_type>(&v);
    }

    static const std::string* to_string_(const std::any& v)
    {
        return std::any_cast<std::string>(&v);
    }

    static std::string* to_string_(std::any& v)
    {
        return std::any_cast<std::string>(&v);
    }

    static const json* to_json_(const std::any& v)
    {
        return std::any_cast<json>(&v);
    }

    static json* to_json_(std::any& v)
    {
        return std::any_cast<json>(&v);
    }

    /************************************************************************
     * stringify
     */
    static void stringify_(std::ostringstream& ss, const json* j)
    {
        if (auto* obj = to_object_(j->value_)) {
            stringify_(ss, *obj);

        } else if (auto* arr = to_array_(j->value_)) {
            stringify_(ss, *arr);

        } else if (auto* str = to_string_(j->value_)) {
            stringify_(ss, *str);

        } else {
            ss << "null";
        }
    }

    static void stringify_(std::ostringstream& ss, const object_type& obj)
    {
        ss << "{";
        auto remains = obj.size();
        for (const auto& [k, v] : obj) {
            ss << "\"" << k << "\":";
            stringify_(ss, to_json_(v));
            if (--remains > 0) {
                ss << ",";
            }
        }
        ss << "}";
    }

    static void stringify_(std::ostringstream& ss, const array_type& arr)
    {
        ss << "[";
        auto remains = arr.size();
        for (const auto& v : arr) {
            stringify_(ss, to_json_(v));
            if (--remains > 0) {
                ss << ",";
            }
        }
        ss << "]";
    }

    static void stringify_(std::ostringstream& ss, const std::string& str)
    {
        ss << str;
    }

    /************************************************************************
     * helper
     */
    static bool quoted_(const std::string* s)
    {
        return s->front() == '"' && s->back() == '"';
    }

    static std::string unescape_(std::string_view sv)
    {
        std::string s;
        s.reserve(sv.size());
        bool escape = false;
        for (auto c : sv) {
            if (c == '\\' && !escape) {
                escape = true;
                continue;
            }
            if (escape) {
                if (c == 'b') {
                    c = '\b';
                } else if (c == 'f') {
                    c = '\f';
                } else if (c == 'n') {
                    c = '\n';
                } else if (c == 'r') {
                    c = '\r';
                } else if (c == 't') {
                    c = '\t';
                }
                escape = false;
            }
            s.push_back(c);
        }
        return s;
    }
};

}  // namespace tbd

#endif
