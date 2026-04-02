#define COROUTINE_USE_SETJMP
#include "coroutine.hpp"

#include <iostream>

using namespace std;
using namespace tbd;

void basic()
{
    puts("\n--- basic pattern ---");

    struct S
    {
        string s_;
        S()
            : s_(1024, 's')
        {
            cout << "S ctor (s_: " << s_.substr(0, 4) << "...)\n";
        }
        ~S() noexcept
        {
            cout << "S dtor\n";
        }
    };

    coro_env env;

    cout << "# normal\n";
    auto co1 = env.spawn([](const auto& yield) {
        cout << "co1:hello";
        yield();
        cout << "co1:HELLO";
    });

    auto co2 = env.spawn([](const auto& yield) {
        cout << "co2:world\n";
        yield();
        cout << "co2:WORLD\n";
    });

    co1.resume();
    cout << " -> ";
    co2.resume();

    co1.resume();
    cout << " -> ";
    auto co22 = move(co2);
    co22.resume();
    assert(!co22);
    assert(!co2);

    cout << "# move, raii, exception\n";
    auto co3 = env.spawn([](const auto& yield) {
        cout << "co3 start\n";
        [[maybe_unused]] S s;
        throw 42;
        yield();
        assert(false);
    });

    auto env2 = move(env);
    try {
        co3.resume();
    } catch (const invalid_argument&) {
        cout << "co3's env has been moved\n";
    }
    env = move(env2);
    try {
        co3.resume();
    } catch (int n) {
        cout << "exception thrown from co3: " << n << "\n";
    }
    assert(!co3);

    cout << "# nested\n";
    auto co4 = env.spawn([](const auto& yield) {
        cout << "co4:hello -> ";
        coro_env inner;
        auto cin = inner.spawn([](const auto& ctx) {
            cout << "cin:world\n";
            ctx.yield();
            cout << "cin:HELLO -> ";
        });
        cin.resume();
        yield();
        cin.resume();
        cout << "co4:WORLD\n";
    });

    co4.resume();
    co4.resume();
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
        cout << *x << ", ";
    }
    cout << "..." << endl;
}

void copyable()
{
    puts("\n--- yields copyable object ---");

    string s("hello");
    coroutine_env<string, int> env;
    auto co1 = env.spawn([s](const auto& yield, auto&& init) {
        cout << "co1: initial value: " << *init << endl;

        auto x = yield(s);
        cout << "co1: passed by env: " << *x << endl;

        [[maybe_unused]] auto m = yield("world");
        assert(false);
    });

    auto x = co1.resume(10);  // pass by arg w/ 1st resume
    cout << "env: yields by co1: " << *x << endl;
    auto y = co1.resume(20);  // pass to coroutine
    cout << "env: yields by co1: " << *y << endl;
}

void noncopyable()
{
    puts("\n--- yields non-copyable object ---");

    coroutine_env<unique_ptr<int>, unique_ptr<string>> env;
    auto co1 = env.spawn([](const auto& ctx, auto&& init) {
        cout << "co1: initial value: " << **init << endl;

        auto up = make_unique<int>(10);
        auto x = ctx.yield(move(up));
        cout << "co1: passed by env: " << **x << endl;

        ctx.exit(make_unique<int>(20));
    });

    auto x = co1.resume(make_unique<string>("hello"));
    cout << "env: yields by co1: " << **x << endl;
    auto y = co1.resume(make_unique<string>("world"));
    cout << "env: yields by co1: " << **y << endl;
}

int main()
{
    basic();
    generator();
    copyable();
    noncopyable();

    return 0;
}
