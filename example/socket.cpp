#include "socket.hpp"

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>

#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

inline char* now()
{
    thread_local char buf[32] = {0};

    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    auto sec = count / (1000 * 1000);
    auto usec = count % (1000 * 1000);
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, 21, "%F %T.", &tm);
    sprintf(buf + 20, "%06ld", usec);
    return buf;
}

#define LOG(fmt, ...) printf("%s [%04ld] " fmt, now(), syscall(SYS_gettid), ##__VA_ARGS__)

void tcp()
{
    thread_pool pool(1);

    pool.submit([] {
        tcp_server svr(8080);
        LOG("server : start w/ port %d\n", 8080);
        auto sess = svr.accept();
        auto [peer, port] = sess.remote_endpoint();
        LOG("server : new connection accepted from %s:%u\n", peer.c_str(), port);

        while (true) {
            char buf[128] = {0};
            auto ec = sess.recv_some(buf, 1);
            if (ec) {
                LOG("session: receive error: %s\n", ec.message().c_str());
                break;
            }
            LOG("session: recv [%s]\n", buf);
        }
        LOG("server : done\n");
    });

    usleep(100 * 1000);

    tcp_client cli("127.0.0.1", 8080);
    cli.connect();
    auto [host, lport] = cli.local_endpoint();
    auto [peer, rport] = cli.remote_endpoint();
    LOG("client : connection from %s:%u to %s:%u\n", host.c_str(), lport, peer.c_str(), rport);
    usleep(50 * 1000);
    for (int i = 0; i < 10; ++i) {
        auto ec = cli.send(to_string(i));
        if (ec) {
            LOG("client : send error: %s\n", ec.message().c_str());
            break;
        }
    }
    LOG("client : done\n");
    cli.close();
}

void tls()
{
#if 1
    thread_pool pool(1);

    pool.submit([] {
        ssl_ctx ctx(true);
        ctx.load_certificate("hostcert.pem", "hostkey.pem");
        tls_server svr(ctx, 8433);
        LOG("server : start w/ port %d\n", 8433);
        auto sess = svr.accept();
        auto [peer, port] = sess.remote_endpoint();
        LOG("server : new connection accepted from %s:%u\n", peer.c_str(), port);

        while (true) {
            char buf[128] = {0};
            auto ec = sess.recv_some(buf, 1);
            if (ec) {
                LOG("session: receive error: %s\n", ec.message().c_str());
                break;
            }
            LOG("session: recv [%s]\n", buf);
        }
        LOG("server : done\n");
    });

    usleep(500 * 1000);

    ssl_ctx ctx;
    ctx.load_ca_file("cacert.pem");
    tls_client cli(ctx, "127.0.0.1", 8433);
    cli.connect();
    auto [host, lport] = cli.local_endpoint();
    auto [peer, rport] = cli.remote_endpoint();
    LOG("client : connection from %s:%u to %s:%u\n", host.c_str(), lport, peer.c_str(), rport);
    usleep(50 * 1000);
    for (int i = 0; i < 10; ++i) {
        auto ec = cli.send(to_string(i));
        if (ec) {
            LOG("client : send error: %s\n", ec.message().c_str());
            break;
        }
    }
    LOG("client : done\n");
    cli.close();
#endif
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    tcp();
    puts("---");
    tls();

    return 0;
}
