#pragma once

#include <netinet/in.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>


namespace Hypervision 
{

static auto string_2_uint128(const std::string input) -> __uint128_t {
    const char * str = input.c_str();
    __uint128_t res = 0;
    for (; *str; res = res * 10 + *str++ - '0');
    return res;
}

static auto uint128_2_string(const __uint128_t num) -> std::string {
    __uint128_t mask = -1;
    size_t a, b, c = 1, d;
    char *s = (char *) malloc(2);
    strcpy(s, "0");
    for (mask -= mask / 2; mask; mask >>= 1) {
        for (a = (num & mask) != 0, b = c; b;) {
            d = ((s[--b] - '0') << 1) + a;
            s[b] = "0123456789"[d % 10];
            a = d / 10;
        }
        for (; a; s = (char *) realloc(s, ++c + 1), memmove(s + 1, s, c), *s = "0123456789"[a % 10], a /= 10);
    }
    std::stringstream ss;
    ss << s;
    free(s);
    std::string ret = ss.str();
    return ret;
}

};