#pragma once

#include "../common.hpp"
#include "packet_info.hpp"
#include "pcpp_common.hpp"

namespace Hypervision 
{


struct basic_packet {
    pkt_ts_t ts;
    pkt_code_t tp;
    pkt_len_t len;
    basic_packet() = default;
    explicit basic_packet(const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
    ts(ts), tp(tp), len(len) {}
    virtual ~basic_packet() {}
};


struct basic_packet_bad : public basic_packet {
    basic_packet_bad() = default;
    explicit basic_packet_bad(const decltype(ts) ts):
    basic_packet(ts, 0, 0) {}
    virtual ~basic_packet_bad() {}
};


struct basic_packet4 final: public basic_packet {
    tuple4_conn4 flow_id;
    basic_packet4() = default;
    explicit basic_packet4(const pkt_addr4_t s_IP, 
                           const pkt_addr4_t d_IP,
                           const pkt_port_t s_port,
                           const pkt_port_t d_port,
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(s_IP, d_IP, s_port, d_port), basic_packet(ts, tp, len) {}
    explicit basic_packet4(const string s_IP, 
                           const string d_IP,
                           const pkt_port_t s_port,
                           const pkt_port_t d_port,
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(convert_str_addr4(s_IP), convert_str_addr4(d_IP), s_port, d_port), basic_packet(ts, tp, len) {}
    explicit basic_packet4(const decltype(flow_id) flow_id, 
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(flow_id), basic_packet(ts, tp, len) {}
    explicit basic_packet4(const string & str) {        
        stringstream ss(str);
        int t;
        ss >> t;
        assert(t == 4);
        pkt_addr4_t sIP, dIP;
        ss >> sIP >> dIP;
        pkt_port_t sp, dp;
        ss >> sp >> dp;
        flow_id = {sIP, dIP, sp, dp};
        double_t _str_time;
        ss >> _str_time;
        ts = get_time_spec(_str_time / 1e6);
        ss >> tp;
        ss >> len;
    }

    virtual ~basic_packet4() {}

    auto get_pkt_str(const int64_t align_time) -> string {
        stringstream ss;
        ss << 4 << ' ' << tuple_get_src_addr(flow_id) 
            << ' ' <<  tuple_get_dst_addr(flow_id)
            << ' ' << tuple_get_src_port(flow_id) 
            << ' ' << tuple_get_dst_port(flow_id) 
            << ' ' << ((int64_t) (GET_DOUBLE_TS(ts) * 1e6)) - align_time
            << ' ' << tp 
            << ' ' << len << '\n';
        return ss.str();
    }
};


struct basic_packet6 final: public basic_packet {
    tuple4_conn6 flow_id;
    basic_packet6() = default;
    explicit basic_packet6(const pkt_addr6_t s_IP, 
                           const pkt_addr6_t d_IP,
                           const pkt_port_t s_port,
                           const pkt_port_t d_port,
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(s_IP, d_IP, s_port, d_port), basic_packet(ts, tp, len) {}
    explicit basic_packet6(const string s_IP, 
                           const string d_IP,
                           const pkt_port_t s_port,
                           const pkt_port_t d_port,
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(convert_str_addr6(s_IP), convert_str_addr6(d_IP), s_port, d_port), basic_packet(ts, tp, len) {}
    explicit basic_packet6(const decltype(flow_id) flow_id, 
                           const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len):
                           flow_id(flow_id), basic_packet(ts, tp, len) {}
    explicit basic_packet6(const string & str) {
        
        stringstream ss(str);
        int t;
        ss >> t;
        assert(t == 6);
        string sIP, dIP;
        ss >> sIP >> dIP;
        pkt_port_t sp, dp;
        ss >> sp >> dp;
        flow_id = {string_2_uint128(sIP), string_2_uint128(dIP), sp, dp};
        double_t _str_time;
        ss >> _str_time;
        ts = get_time_spec(_str_time / 1e6);
        ss >> tp;
        ss >> len;
    }

    virtual ~basic_packet6() {}

    auto get_pkt_str(const int64_t align_time) -> string {
        stringstream ss;
        ss << 6 << ' ' << uint128_2_string(tuple_get_src_addr(flow_id)) 
            << ' ' <<  uint128_2_string(tuple_get_dst_addr(flow_id))
            << ' ' << tuple_get_src_port(flow_id) 
            << ' ' << tuple_get_dst_port(flow_id) 
            << ' ' << ((int64_t) (GET_DOUBLE_TS(ts) * 1e6)) - align_time
            << ' ' << tp
            << ' ' << len << '\n';
        return ss.str();
    }
};


}