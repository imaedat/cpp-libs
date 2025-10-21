#undef COROUTINE_EXCEPTION_AGAINST_FINISHED
#include "coroutine.hpp"

#include <iostream>

using namespace std;
using namespace tbd;

void basic()
{
    puts("\n--- basic pattern ---");

    co_env co_env;

    auto co1 = co_env.spawn([](const auto& yield) {
        printf("co1:hello");
        yield();
        printf("co1:HELLO");
    });

    auto co2 = co_env.spawn([](const auto& yield) {
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

    auto co3 = co_env.spawn([](const auto& yield) {
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

    coroutine_env_tmpl<int> co_env;
    auto gen = co_env.spawn([](const auto& yield) {
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

    coroutine_env_tmpl<string, int> co_env;

    string s("hello");
    auto co1 = co_env.spawn([s](const auto& yield) {
        auto n = yield(s);
        printf("passed from env: %d\n", *n);
        [[maybe_unused]] auto m = yield("world");
        puts("--- NOT REACHED HERE!!! ---");
    });

    auto x = co1.resume(10);  // not passed w/ 1st resume
    cout << "yields by co1: " << *x << endl;
    auto y = co1.resume(20);  // pass to coroutine
    cout << "yields by co1: " << *y << endl;
}

void noncopyable()
{
    puts("\n--- yields non_copyable object ---");

    struct non_copyable
    {
        int val;
        non_copyable()
            : val(0)
        {
        }  // must be default constructible
        explicit non_copyable(int n)
            : val(n)
        {
        }
        non_copyable(const non_copyable&) = delete;
        non_copyable& operator=(const non_copyable&) = delete;
        non_copyable(non_copyable&&) noexcept = default;
        non_copyable& operator=(non_copyable&&) noexcept = default;
    };

    coroutine_env_tmpl<non_copyable> co_env;

    auto co1 = co_env.spawn([](const auto& yield) {
        non_copyable nc(1);
        yield(move(nc));

        yield(non_copyable(2));
    });

    auto x = co1.resume();
    cout << "yields by co1: " << x->val << endl;
    auto y = co1.resume();
    cout << "yields by co1: " << y->val << endl;
}

int main()
{
    basic();
    generator();
    copyable();
    noncopyable();

    return 0;
}
