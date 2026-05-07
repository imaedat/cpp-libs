#ifndef JSON_HPP_
#define JSON_HPP_

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace tbd {

class json
{
  public:
    inline static constexpr size_t MAX_VALUE_SIZE = 64;
    using object_type = std::unordered_map<std::string, json>;
    using array_type = std::vector<json>;
    using value_type = std::variant<bool, int64_t, double, std::string, json>;

  private:
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

    using result_type = std::pair<json, const char*>;

    alignas(alignof(std::max_align_t)) uint8_t buffer_[MAX_VALUE_SIZE] = {0};
    size_t textsize_ = 0;
    enum class value_t : uint8_t
    {
        null,
        boolean,
        integral,
        floating,
        string,
        object,
        array,
    } type_{value_t::null};

    void alloc(value_t type)
    {
        switch (type) {
        case value_t::null:
            break;

        case value_t::boolean:
            new (buffer_) bool();
            break;

        case value_t::integral:
        case value_t::floating:
        case value_t::string:
            new (buffer_) std::string();
            break;

        case value_t::object:
            new (buffer_) object_type();
            break;

        case value_t::array:
            new (buffer_) array_type();
            break;

        default:
            assert(false);
        }

        type_ = type;
    }

    template <typename V>
    void initialize(value_t type, V&& v)
    {
        alloc(type);
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            *to_bool_() = v;
        } else if constexpr (std::is_convertible_v<std::decay_t<V>, std::string_view>) {
            *to_str_() = std::forward<V>(v);
        } else if constexpr (std::is_same_v<std::decay_t<V>, object_type>) {
            operator=(std::forward<V>(v));
        } else if constexpr (std::is_same_v<std::decay_t<V>, array_type>) {
            operator=(std::forward<V>(v));
        } else {
            static_assert([] { return false; }(), "invalid argument");
        }
    }

    explicit json(value_t type)
    {
        alloc(type);
    }

    template <typename V>
    json(value_t type, V&& v)
    {
        initialize(type, std::forward<V>(v));
    }

  public:
    json()
        : json(value_t::null)
    {
    }
    template <typename V,
              std::enable_if_t<(std::is_same_v<std::decay_t<V>, bool> ||
                                std::is_arithmetic_v<std::decay_t<V>> ||
                                std::is_convertible_v<std::decay_t<V>, std::string_view> ||
                                std::is_same_v<std::decay_t<V>, json>),
                               bool> = true>
    explicit json(V&& v)
    {
        using namespace std::string_literals;
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            initialize(value_t::boolean, v);
        } else if constexpr (std::is_integral_v<std::decay_t<V>>) {
            initialize(value_t::integral, std::to_string(v));
        } else if constexpr (std::is_floating_point_v<std::decay_t<V>>) {
            initialize(value_t::floating, std::to_string(v));
        } else if constexpr (std::is_convertible_v<std::decay_t<V>, std::string_view>) {
            initialize(value_t::string, "\""s + std::forward<V>(v) + "\"");
        } else if constexpr (std::is_same_v<std::decay_t<V>, json>) {
            operator=(std::forward<V>(v));
        } else {
            static_assert([] { return false; }(), "invalid argument");
        }
    }
    explicit json(const std::initializer_list<std::pair<std::string, value_type>>& list)
    {
        struct value_visitor
        {
            object_type* obj;
            const std::string& k;
            void operator()(bool v)
            {
                obj->emplace(k, json(value_t::boolean, v));
            }
            void operator()(int64_t v)
            {
                obj->emplace(k, json(value_t::integral, std::to_string(v)));
            }
            void operator()(double v)
            {
                obj->emplace(k, json(value_t::floating, std::to_string(v)));
            }
            void operator()(const std::string& v)
            {
                using namespace std::string_literals;
                obj->emplace(k, json(value_t::string, "\""s + v + "\""));
            }
            void operator()(const json& v)
            {
                obj->emplace(k, v);
            }
        };

        alloc(value_t::object);
        auto* obj = to_obj_();
        for (auto&& [k, v] : list) {
            value_visitor vv{obj, k};
            std::visit(vv, v);
        }
    }
    json(const json& rhs)
    {
        *this = rhs;
    }
    json& operator=(const json& rhs)
    {
        if (this != &rhs) {
            reset();
            type_ = rhs.type_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
            case value_t::string:
                new (buffer_) std::string(*rhs.to_str_());
                break;

            case value_t::object:
                new (buffer_) object_type(*rhs.to_obj_());
                break;

            case value_t::array:
                new (buffer_) array_type(*rhs.to_arr_());
                break;

            default:
                assert(false);
            }
        }
        return *this;
    }
    json(json&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    json& operator=(json&& rhs) noexcept
    {
        if (this != &rhs) {
            reset();
            type_ = rhs.type_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
            case value_t::string:
                new (buffer_) std::string(std::move(*rhs.to_str_()));
                break;

            case value_t::object:
                new (buffer_) object_type(std::move(*rhs.to_obj_()));
                break;

            case value_t::array:
                new (buffer_) array_type(std::move(*rhs.to_arr_()));
                break;

            default:
                assert(false);
            }

            rhs.reset();
        }
        return *this;
    }
    ~json()
    {
        reset();
    }

    static json parse(const std::string& s)
    {
        auto [j, p] = parse_value(ltrim(s.data()));
        p = ltrim(p);
        if (*p != '\0') {
            throw_invalid(__func__, "unexpected char", *p);
        }
        j.textsize_ = p - s.data();
        return std::move(j);
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
        return type_ == value_t::null;
    }
    bool is_bool() const
    {
        return type_ == value_t::boolean;
    }
    bool is_integral() const
    {
        return type_ == value_t::integral;
    }
    bool is_floating() const
    {
        return type_ == value_t::floating;
    }
    bool is_string() const
    {
        return type_ == value_t::string;
    }
    bool is_object() const
    {
        return type_ == value_t::object;
    }
    bool is_array() const
    {
        return type_ == value_t::array;
    }

    bool empty() const
    {
        switch (type_) {
        case value_t::string:
            return *to_str_() == "\"\"";

        case value_t::object:
            return to_obj_()->empty();

        case value_t::array:
            return to_arr_()->empty();

        default:
            throw_invalid(__func__, "not container");
        }
    }

    size_t size() const
    {
        switch (type_) {
        case value_t::string:
            return to_str_()->size() - 2;

        case value_t::object:
            return to_obj_()->size();

        case value_t::array:
            return to_arr_()->size();

        default:
            throw_invalid(__func__, "not container");
        }
    }

    bool contains(std::string_view key) const
    {
        if (auto* obj = to_obj_()) {
            return obj->find(key.data()) != obj->end();
        }
        throw_invalid(__func__, "not object");
    }

    /************************************************************************
     * common operation
     */
    template <typename V, std::enable_if_t<!std::is_same_v<std::decay_t<V>, json>, bool> = true>
    json& operator=(V&& v)
    {
        reset();
        *this = json(std::forward<V>(v));
        return *this;
    }

    void clear()
    {
        switch (type_) {
        case value_t::string:
            to_str_()->assign("\"\"");
            return;

        case value_t::object:
            to_obj_()->clear();
            return;

        case value_t::array:
            to_arr_()->clear();
            return;

        default:
            throw_invalid(__func__, "not container");
        }
    }

    void reset() noexcept
    {
        switch (type_) {
        case value_t::null:
        case value_t::boolean:
            break;

        case value_t::integral:
        case value_t::floating:
        case value_t::string:
            to_str_()->~basic_string();
            break;

        case value_t::object:
            to_obj_()->~unordered_map();
            break;

        case value_t::array:
            to_arr_()->~vector();
            break;

        default:
            break;
        }

        type_ = value_t::null;
    }

    /************************************************************************
     * object operator
     */
    const json& at(std::string_view key) const
    {
        if (auto* obj = to_obj_()) {
            if (auto it = obj->find(key.data()); it != obj->end()) {
                return it->second;
            }
            throw_invalid(__func__, "key not found");
        }
        throw_invalid(__func__, "not object");
    }

    json& operator[](std::string_view key)
    {
        if (is_null()) {
            alloc(value_t::object);
        }
        if (auto* obj = to_obj_()) {
            auto it = obj->find(key.data());
            if (it == obj->end()) {
                std::tie(it, std::ignore) = obj->emplace(key, json{});
            }
            return it->second;
        }
        throw_invalid(__func__, "not object");
    }

    template <typename K, typename V>
    void emplace(K&& k, V&& v)
    {
        if (auto* obj = to_obj_()) {
            obj->emplace(std::forward<K>(k), std::forward<V>(v));
            return;
        }
        throw_invalid(__func__, "not object");
    }

    void erase(std::string_view key)
    {
        if (auto* obj = to_obj_()) {
            obj->erase(key.data());
            return;
        }
        throw_invalid(__func__, "not object");
    }

    // for object iterator
    struct item_ref;
    struct object_iterator;
    struct object_view
    {
        object_type* obj;
        object_iterator begin();  // const;
        object_iterator end();    // const;
    };

    object_view items()
    {
        if (auto* obj = to_obj_()) {
            return object_view{obj};
        }
        throw_invalid(__func__, "not object");
    }

    /************************************************************************
     * array operator
     */
    const json& at(size_t i) const
    {
        if (auto* arr = to_arr_()) {
            if (i < arr->size()) {
                return arr->at(i);
            }
            throw_invalid(__func__, "out of range");
        }
        throw_invalid(__func__, "not array");
    }

    json& operator[](size_t i)
    {
        if (auto* arr = to_arr_()) {
            return (*arr)[i];
        }
        throw_invalid(__func__, "not array");
    }

    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void push_back(J&& j)
    {
        if (is_null()) {
            alloc(value_t::array);
        }
        if (auto* arr = to_arr_()) {
            arr->push_back(std::forward<J>(j));
            return;
        }
        throw_invalid(__func__, "not array");
    }

    template <typename V, std::enable_if_t<!std::is_same_v<std::decay_t<V>, json>, bool> = true>
    void push_back(V&& v)
    {
        push_back(json(std::forward<V>(v)));
    }

    // for array iterator
    struct array_iterator
    {
        array_type::iterator it;
        explicit array_iterator(array_type::iterator i)
            : it(i)
        {
        }
        json& operator*() const
        {
            return *it;
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

    array_iterator begin()  // const
    {
        if (auto* arr = to_arr_()) {
            return array_iterator(arr->begin());
        }
        throw_invalid(__func__, "not array");
    }

    array_iterator end()  // const
    {
        if (auto* arr = to_arr_()) {
            return array_iterator(arr->end());
        }
        throw_invalid(__func__, "not array");
    }

    /************************************************************************
     * value accessor
     */
    template <typename T>
    T get() const
    {
        if constexpr (std::is_same_v<T, bool>) {
            if (auto* b = to_bool_()) {
                return *b;
            }

        } else if (auto* str = to_str_()) {
            bool quoted = quoted_(str);
            std::string_view sv(str->data() + (quoted ? 1 : 0), str->size() - (quoted ? 2 : 0));
            char* endptr = nullptr;
            errno = 0;

            if constexpr (std::is_same_v<T, std::string>) {
                if (quoted) {
                    return unescape_(sv);
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
        std::string ss;
        ss.reserve(std::max(textsize_, 4096UL));
        stringify_(ss);
        const_cast<json*>(this)->textsize_ = ss.size();
        return ss;
    }

  private:
    /************************************************************************
     * cast
     */
    template <typename T>
    T* cast_(bool ok)
    {
        return ok ? std::launder(reinterpret_cast<T*>(buffer_)) : nullptr;
    }
    template <typename T>
    const T* cast_(bool ok) const
    {
        return ok ? std::launder(reinterpret_cast<const T*>(buffer_)) : nullptr;
    }

    bool holds_as_string() const
    {
        return is_integral() || is_floating() || is_string();
    }

    object_type* to_obj_()
    {
        return cast_<object_type>(is_object());
    }
    const object_type* to_obj_() const
    {
        return cast_<object_type>(is_object());
    }
    array_type* to_arr_()
    {
        return cast_<array_type>(is_array());
    }
    const array_type* to_arr_() const
    {
        return cast_<array_type>(is_array());
    }
    std::string* to_str_()
    {
        return cast_<std::string>(holds_as_string());
    }
    const std::string* to_str_() const
    {
        return cast_<std::string>(holds_as_string());
    }
    bool* to_bool_()
    {
        return cast_<bool>(is_bool());
    }
    const bool* to_bool_() const
    {
        return cast_<bool>(is_bool());
    }

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

    static result_type parse_object(const char* p)
    {
        assert(*p == '{');
        auto q = ltrim(p + 1);
        json obj(value_t::object);
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
            obj.emplace(std::move(*k.to_str_()), std::move(v));

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
        return {std::move(obj), ltrim(q + 1)};
    }

    static result_type parse_array(const char* p)
    {
        assert(*p == '[');
        auto q = ltrim(p + 1);
        json arr(value_t::array);
        bool comma = false;
        while (*q != ']') {
            auto [v, r] = parse_value(q);
            q = r;
            arr.push_back(std::move(v));
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
        return {std::move(arr), ltrim(q + 1)};
    }

    static result_type parse_string(const char* p, bool trim_quote = false)
    {
        assert(*p == '"');
        auto q = p + 1;
        bool escape = false;
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
        std::string s(p + (trim_quote ? 1 : 0), q - p - (trim_quote ? 2 : 0));
        return {json(value_t::string, std::move(s)), ltrim(q)};
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
        auto type = (len2 >= 0 || len3 > 0) ? value_t::floating : value_t::integral;
        return {json(type, std::move(n)), q};
    }

    static result_type parse_bool(const char* p)
    {
        if (std::strncmp(p, "true", 4) == 0) {
            return {json(value_t::boolean, true), ltrim(p + 4)};
        }
        if (std::strncmp(p, "false", 5) == 0) {
            return {json(value_t::boolean, false), ltrim(p + 5)};
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
     * stringify
     */
    void stringify_(std::string& ss) const
    {
        switch (type_) {
        case value_t::null:
            ss += "null";
            break;

        case value_t::boolean:
            ss += (*to_bool_() ? "true" : "false");
            break;

        case value_t::integral:
        case value_t::floating:
        case value_t::string:
            ss += *to_str_();
            break;

        case value_t::object: {
            ss += "{";
            const auto* obj = to_obj_();
            auto remains = obj->size();
            for (const auto& [k, v] : *obj) {
                ss.append("\"").append(k).append("\":");
                v.stringify_(ss);
                if (--remains > 0) {
                    ss += ",";
                }
            }
            ss += "}";
            break;
        }

        case value_t::array: {
            ss += "[";
            const auto* arr = to_arr_();
            auto remains = arr->size();
            for (const auto& v : *arr) {
                v.stringify_(ss);
                if (--remains > 0) {
                    ss += ",";
                }
            }
            ss += "]";
            break;
        }

        default:
            break;
        }
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

/****************************************************************************
 * object iterator
 */
struct json::item_ref
{
    const std::string& key;
    json& value;
};

struct json::object_iterator
{
    json::object_type::iterator it;
    explicit object_iterator(json::object_type::iterator i)
        : it(i)
    {
    }
    json::item_ref operator*() const
    {
        return {it->first, it->second};
    }
    json::object_iterator& operator++()
    {
        ++it;
        return *this;
    }
    bool operator==(const json::object_iterator& rhs) const
    {
        return it == rhs.it;
    }
    bool operator!=(const json::object_iterator& rhs) const
    {
        return !(*this == rhs);
    }
};

json::object_iterator json::object_view::begin()  // const
{
    return json::object_iterator(obj->begin());
}

json::object_iterator json::object_view::end()  // const
{
    return json::object_iterator(obj->end());
}

static_assert(sizeof(std::string) <= json::MAX_VALUE_SIZE);
static_assert(sizeof(json::object_type) <= json::MAX_VALUE_SIZE);
static_assert(sizeof(json::array_type) <= json::MAX_VALUE_SIZE);

}  // namespace tbd

#endif
