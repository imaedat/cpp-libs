#include "socket.hpp"

#include <signal.h>

#include <cstdio>

#include "thread_pool.hpp"
#include "util.h"

using namespace std;
using namespace tbd;

void tcp()
{
    thread_pool pool(2);

    pool.submit([] {
        tcp_server svr(8080);
        auto sess = svr.accept();
        auto [peer, port] = sess.remote_endpoint();
        LOG("server : new connection accepted from %s:%u\n", peer.c_str(), port);

        while (true) {
            char buf[1024] = {0};
            auto ec = sess.recv_some(buf, 1);
            if (ec) {
                LOG("session: receive error: %s\n", ec.message().c_str());
                break;
            }
            LOG("session: recv [%s]\n", buf);
        }
        LOG("server : done\n");
    });

    usleep(10 * 1000);

    tcp_client cli("127.0.0.1", 8080);
    cli.connect();
    auto [peer, port] = cli.remote_endpoint();
    LOG("client : connection established to %s:%u\n", peer.c_str(), port);
    for (int i = 0; i < 10; ++i) {
        auto ec = cli.send(to_string(i));
        if (ec) {
            LOG("client : send error: %s\n", ec.message().c_str());
            break;
        }
    }
    cli.close();
    LOG("client : done\n");
}

void tls()
{
#if 1
    thread_pool pool(2);

    pool.submit([] {
        ssl_ctx ctx(true);
        ctx.load_certificate("hostcert.pem", "hostkey.pem");
        tls_server svr(ctx, 8433);
        //LOG("server : start w/ port %d\n", 8433);
        auto sess = svr.accept();
        auto [peer, port] = sess.remote_endpoint();
        //LOG("server : new connection accepted from %s:%u\n", peer.c_str(), port);

        while (true) {
            char buf[1024] = {0};
            auto ec = sess.recv_some(buf, 1);
            if (ec) {
                //LOG("session: receive error: %s\n", ec.message().c_str());
                break;
            }
            //LOG("session: recv [%s]\n", buf);
        }
    });

    usleep(10 * 1000);

    ssl_ctx ctx;
    ctx.load_ca_file("cacert.pem");
    tls_client cli(ctx, "127.0.0.1", 8433);
    //LOG("client : just begin to connect to %d\n", 8433);
    cli.connect();
    auto [peer, port] = cli.remote_endpoint();
    //LOG("client : connection established to %s:%u\n", peer.c_str(), port);
    usleep(100 * 1000);
    for (int i = 0; i < 10; ++i) {
        auto ec = cli.send(to_string(i));
        if (ec) {
            //LOG("client : send error: %s\n", ec.message().c_str());
            break;
        }
    }
    cli.close();
#endif
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    //tcp();
    //puts("---");
    tls();

    return 0;
}
