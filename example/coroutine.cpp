#include "coroutine.hpp"

#include <iostream>

using namespace std;
using namespace tbd;

void basic()
{
    puts("\n--- basic pattern ---");

    coro_env env;

    auto co1 = env.spawn([](const auto& yield) {
        printf("co1:hello");
        yield();
        printf("co1:HELLO");
    });

    auto co2 = env.spawn([](const auto& yield) {
        printf("co2:world\n");
        yield();
        printf("co2:WORLD\n");
    });

    co1.resume();
    printf(" -> ");
    co2.resume();

    co1.resume();
    printf(" -> ");
    co2.resume();
    assert(!co2);

    auto co3 = env.spawn([](const auto& yield) {
        puts("co3 start");
        throw 1;
        yield();
        puts("co3 end (NOT REACHED)");
    });

    try {
        co3.resume();
    } catch (int n) {
        printf("exception thrown in co3: %d\n", n);
    }
}

void generator()
{
    puts("\n--- generator pattern ---");

    coroutine_env<int> env;
    auto gen = env.spawn([](const auto& yield) {
        int i = 0;
        while (true) {
            yield(i++);
        }
    });

    for (size_t i = 0; i < 10; ++i) {
        auto x = gen.resume();
        cout << *x << endl;
    }
}

void copyable()
{
    puts("\n--- yields copyable object ---");

    coroutine_env<string, int> env;

    string s("hello");
    auto co1 = env.spawn([s](const auto& yield, auto&& i) {
        printf("co1: initial_value from env: %d\n", *i);
        auto n = yield(s);
        printf("co1: passed from env: %d\n", *n);
        [[maybe_unused]] auto m = yield("world");
        puts("--- NOT REACHED HERE!!! ---");
    });

    auto x = co1.resume(10);  // pass by arg w/ 1st resume
    cout << "env: yields by co1: " << *x << endl;
    auto y = co1.resume(20);  // pass to coroutine
    cout << "env: yields by co1: " << *y << endl;
}

void noncopyable()
{
    puts("\n--- yields non_copyable object ---");

    struct non_copyable
    {
        string val;
        explicit non_copyable(const string& s)
            : val(s)
        {
        }
        non_copyable(const non_copyable&) = delete;
        non_copyable& operator=(const non_copyable&) = delete;
        non_copyable(non_copyable&&) noexcept = default;
        non_copyable& operator=(non_copyable&&) noexcept = default;
    };

    coroutine_env<non_copyable, non_copyable> env;

    auto co1 = env.spawn([](const auto& yield, auto&& init) {
        cout << "co1: initial_value: " << init->val << endl;

        non_copyable nc("co1-1");
        auto x = yield(move(nc));
        cout << "co1: passed by end: " << x->val << endl;

        yield.exit(non_copyable("co1-2"));
    });

    auto x = co1.resume(non_copyable("hello"));
    cout << "env: yields by co1: " << x->val << endl;
    auto y = co1.resume(non_copyable("world"));
    cout << "env: yields by co1: " << y->val << endl;
}

int main()
{
    basic();
    generator();
    copyable();
    noncopyable();

    return 0;
}
