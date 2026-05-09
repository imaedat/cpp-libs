#ifndef JSON_HPP_
#define JSON_HPP_

#include <algorithm>
#include <cassert>
#include <charconv>
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
        static constexpr const char hex[] = "0123456789ABCDEF";
        std::string what = f + ": " + m.data();
        if (c >= 0) {
            if (c <= 0x1f) {
                what.append(" <");
                what.push_back(hex[c >> 4]);
                what.push_back(hex[c & 0x0f]);
                what.append("h>");
            } else {
                what.append(" (`");
                what.push_back((char)c);
                what.append("')");
            }
        }
        throw std::invalid_argument(what);
    }

    using result_type = std::pair<json, const char*>;
    union number
    {
        int64_t i;
        double d;
    };

    alignas(alignof(std::max_align_t)) uint8_t buffer_[MAX_VALUE_SIZE] = {0};
    mutable size_t textsize_ = 0;
    enum class value_t : uint8_t
    {
        null,
        boolean,
        integral,
        floating,
        string,
        unescaped_string,
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
        case value_t::unescaped_string:
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
    void initialize(value_t type, V&& v, union number n = {})
    {
        alloc(type);
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            *to_bool_() = v;
        } else if constexpr (std::is_convertible_v<std::decay_t<V>, std::string_view>) {
            if (type_ == value_t::unescaped_string) {
                type_ = value_t::string;
                *to_str_() = escape_(v);
            } else {
                *to_str_() = std::forward<V>(v);
                assign_number(n);
            }
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
    json(value_t type, V&& v, union number n = {})
    {
        initialize(type, std::forward<V>(v), n);
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
        union number n;
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            initialize(value_t::boolean, v);
        } else if constexpr (std::is_integral_v<std::decay_t<V>>) {
            n.i = v;
            initialize(value_t::integral, std::to_string(v), n);
        } else if constexpr (std::is_floating_point_v<std::decay_t<V>>) {
            n.d = v;
            initialize(value_t::floating, std::to_string(v), n);
        } else if constexpr (std::is_convertible_v<std::decay_t<V>, std::string_view>) {
            initialize(value_t::unescaped_string, std::forward<V>(v));
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
            union number n;
            void operator()(bool v)
            {
                obj->emplace(k, json(value_t::boolean, v));
            }
            void operator()(int64_t v)
            {
                n.i = v;
                obj->emplace(k, json(value_t::integral, std::to_string(v), n));
            }
            void operator()(double v)
            {
                n.d = v;
                obj->emplace(k, json(value_t::floating, std::to_string(v), n));
            }
            void operator()(const std::string& v)
            {
                obj->emplace(k, json(value_t::unescaped_string, v));
            }
            void operator()(const json& v)
            {
                obj->emplace(k, v);
            }
        };

        alloc(value_t::object);
        auto* obj = to_obj_();
        for (auto&& [k, v] : list) {
            value_visitor vv{obj, k, {}};
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
            textsize_ = rhs.textsize_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
                assign_number(rhs);
                [[fallthrough]];

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
            textsize_ = rhs.textsize_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
                assign_number(rhs);
                [[fallthrough]];

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

    std::string to_string() const
    {
        std::string ss;
        ss.reserve(std::max(textsize_, 4096UL));
        stringify_(ss);
        textsize_ = ss.size();
        return ss;
    }

    /************************************************************************
     * const attributes
     */
    // clang-format off
    bool is_null() const { return type_ == value_t::null; }
    bool is_bool() const { return type_ == value_t::boolean; }
    bool is_integral() const { return type_ == value_t::integral; }
    bool is_floating() const { return type_ == value_t::floating; }
    bool is_number() const { return is_integral() || is_floating(); }
    bool is_string() const { return type_ == value_t::string; }
    bool is_object() const { return type_ == value_t::object; }
    bool is_array() const { return type_ == value_t::array; }
    // clang-format on

    bool empty() const
    {
        switch (type_) {
        case value_t::string:
            return to_str_()->empty();

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
            return to_str_()->size();

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
     * common operator
     */
    template <typename V, std::enable_if_t<!std::is_same_v<std::decay_t<V>, json>, bool> = true>
    json& operator=(V&& v)
    {
        using std::swap;
        json rhs(std::forward<V>(v));
        swap(*this, rhs);
        return *this;
    }

    bool operator==(const json& rhs) const
    {
        switch (type_) {
        case value_t::null:
            return rhs.is_null();

        case value_t::boolean:
            return rhs.is_bool() && *to_bool_() == *rhs.to_bool_();

        case value_t::integral:
            return (rhs.is_integral() && get<int64_t>() == rhs.get<int64_t>()) ||
                   (rhs.is_floating() && get<double>() == rhs.get<double>());

        case value_t::floating:
            return (rhs.is_floating() || rhs.is_integral()) && get<double>() == rhs.get<double>();

        case value_t::string:
            return rhs.is_string() && *to_str_() == *rhs.to_str_();

        case value_t::object:
            return rhs.is_object() && *to_obj_() == *rhs.to_obj_();

        case value_t::array:
            return rhs.is_array() && *to_arr_() == *rhs.to_arr_();

        default:
            assert(false);
        }
    }

    bool operator!=(const json& rhs) const
    {
        return !(*this == rhs);
    }

    template <typename T>
    T get() const
    {
        if constexpr (std::is_same_v<T, bool>) {
            if (auto* b = to_bool_()) {
                return *b;
            }

        } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
            if (auto* num = to_int_()) {
                return *num;
            }
            if (auto* num = to_float_()) {
                return *num;
            }

        } else if constexpr (std::is_same_v<T, std::string>) {
            if (auto* str = to_str_(); str && is_string()) {
                return unescape_(*str);
            }

        } else {
            static_assert([] { return false; }(), "invalid type");
        }

        throw_invalid(__func__, "not primitive");
    }

    void clear()
    {
        switch (type_) {
        case value_t::string:
            to_str_()->clear();
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
        textsize_ = 0;
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

#if 0
    template <typename K, typename V>
    void emplace(K&& k, V&& v)
    {
        if (auto* obj = to_obj_()) {
            obj->emplace(std::forward<K>(k), std::forward<V>(v));
            return;
        }
        throw_invalid(__func__, "not object");
    }
#endif

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
            return arr->at(i);
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

  private:
    /************************************************************************
     * cast
     */
    template <typename T>
    T* cast_(bool ok, bool num = false)
    {
        return ok ? std::launder(reinterpret_cast<T*>(num ? numbuffer_() : buffer_)) : nullptr;
    }
    template <typename T>
    const T* cast_(bool ok, bool num = false) const
    {
        return ok ? std::launder(reinterpret_cast<const T*>(num ? numbuffer_() : buffer_))
                  : nullptr;
    }

    // clang-format off
          void* numbuffer_()       { return buffer_ + sizeof(std::string); }
    const void* numbuffer_() const { return buffer_ + sizeof(std::string); }

    bool holds_as_string() const { return is_integral() || is_floating() || is_string(); }

          object_type* to_obj_()         { return cast_<object_type>(is_object()); }
    const object_type* to_obj_() const   { return cast_<object_type>(is_object()); }
          array_type*  to_arr_()         { return cast_<array_type>(is_array()); }
    const array_type*  to_arr_() const   { return cast_<array_type>(is_array()); }
          std::string* to_str_()         { return cast_<std::string>(holds_as_string()); }
    const std::string* to_str_() const   { return cast_<std::string>(holds_as_string()); }
          int64_t*     to_int_()         { return cast_<int64_t>(is_integral(), true); }
    const int64_t*     to_int_() const   { return cast_<int64_t>(is_integral(), true); }
          double*      to_float_()       { return cast_<double>(is_floating(), true); }
    const double*      to_float_() const { return cast_<double>(is_floating(), true); }
          bool*        to_bool_()        { return cast_<bool>(is_bool()); }
    const bool*        to_bool_() const  { return cast_<bool>(is_bool()); }
    // clang-format on

    void assign_number(union number n)
    {
        if (is_integral()) {
            *to_int_() = n.i;
        } else if (is_floating()) {
            *to_float_() = n.d;
        }
    }

    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void assign_number(J&& j)
    {
        if (is_integral()) {
            *to_int_() = *j.to_int_();
        } else if (is_floating()) {
            *to_float_() = *j.to_float_();
        } else {
            assert(false);
        }
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
            return parse_literal(p);

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
        json j(value_t::object);
        auto* obj = j.to_obj_();
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
            // obj.emplace(std::move(*k.to_str_()), std::move(v));
            obj->emplace(std::move(*k.to_str_()), std::move(v));

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
        return {std::move(j), ltrim(q + 1)};
    }

    static result_type parse_array(const char* p)
    {
        assert(*p == '[');
        auto q = ltrim(p + 1);
        json j(value_t::array);
        auto* arr = j.to_arr_();
        bool comma = false;
        while (*q != ']') {
            auto [v, r] = parse_value(q);
            q = r;
            // arr.push_back(std::move(v));
            arr->emplace_back(std::move(v));
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
        return {std::move(j), ltrim(q + 1)};
    }

    static result_type parse_string(const char* p, bool is_key = false)
    {
        assert(*p == '"');
        auto q = p + 1;
        bool escape = false;
        std::string s;
        while (true) {
            char c = *q++;
            if (0x00 <= c && c <= 0x1f) {
                throw_invalid(__func__, "invalid character", c);
            }
            if (c == '\\' && !escape) {
                escape = true;
                continue;
            } else if (c == '"' && !escape) {
                break;
            }
            if (is_key) {
                s.push_back(escape ? unescape_(c) : c);
            }
            escape = false;
        }
        if (!is_key) {
            s.assign(p + 1, q - p - 2);
        }
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
        std::string s(p, q - p);
        if (len1 == 0 || (len1 >= 2 && p[0] == '0') || len2 == 0 || len3 == 0) {
            throw_invalid(__func__, "invalid numeric: " + s);
        }
        auto type = (len2 >= 0 || len3 > 0) ? value_t::floating : value_t::integral;
        union number n;
        std::from_chars_result res;
        if (type == value_t::integral) {
            res = std::from_chars(p, q, n.i);
        } else {
            res = std::from_chars(p, q, n.d);
        }
        if (res.ec != std::errc{}) {
            throw_invalid(__func__, "invalid numeric: " + s);
        }
        return {json(type, std::move(s), n), ltrim(q)};
    }

    static result_type parse_literal(const char* p)
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
            ss += *to_str_();
            break;

        case value_t::string:
            ss.push_back('"');
            ss.append(*to_str_());
            ss.push_back('"');
            break;

        case value_t::object: {
            ss += "{";
            auto* obj = to_obj_();
            auto remains = obj->size();
            for (const auto& [k, v] : *obj) {
                ss.push_back('"');
                escape_(ss, k);
                ss.append("\":");
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
            auto* arr = to_arr_();
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
            assert(false);
        }
    }

    /************************************************************************
     * helper
     */
    static std::string escape_(const std::string& s)
    {
        std::string e;
        e.reserve(s.size());
        escape_(e, s);
        return e;
    }

    static void escape_(std::string& ss, const std::string& s)
    {
        for (auto c : s) {
            if (c == '"') {
                ss.append("\\\"");
            } else if (c == '\\') {
                ss.append("\\\\");
            } else if (c == '\b') {
                ss.append("\\b");
            } else if (c == '\f') {
                ss.append("\\f");
            } else if (c == '\n') {
                ss.append("\\n");
            } else if (c == '\r') {
                ss.append("\\r");
            } else if (c == '\t') {
                ss.append("\\t");
            } else {
                ss.push_back(c);
            }
        }
    }

    static std::string unescape_(const std::string& s)
    {
        std::string u;
        u.reserve(s.size());
        bool escape = false;
        for (auto c : s) {
            if (c == '\\' && !escape) {
                escape = true;
                continue;
            }
            u.push_back(escape ? unescape_(c) : c);
            escape = false;
        }
        assert(!escape);
        return u;
    }

    static char unescape_(char c) noexcept
    {
        // XXX invalid/unknown escape sequence?
        return (c == 'b')   ? '\b'
               : (c == 'f') ? '\f'
               : (c == 'n') ? '\n'
               : (c == 'r') ? '\r'
               : (c == 't') ? '\t'
                            : c;
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

static_assert(sizeof(std::string) + std::max(sizeof(int64_t), sizeof(double)) <=
              json::MAX_VALUE_SIZE);
static_assert(sizeof(json::object_type) <= json::MAX_VALUE_SIZE);
static_assert(sizeof(json::array_type) <= json::MAX_VALUE_SIZE);

}  // namespace tbd

#endif
