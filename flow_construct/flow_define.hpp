#pragma once

#include "../common.hpp"
#include "../packet_parse/packet_basic.hpp"

namespace Hypervision 
{

using flow_time_t = double_t;


class basic_flow {
protected:
    flow_time_t str = numeric_limits<flow_time_t>::max();
    flow_time_t end = numeric_limits<flow_time_t>::min();
    pkt_code_t code = 0;
    shared_ptr<vector<shared_ptr<basic_packet> > > p_packet_p_seq;
    shared_ptr<vector<size_t> > p_reverse_index;

public:
    basic_flow() {
        p_packet_p_seq = make_shared<vector<shared_ptr<basic_packet> > >();
        p_reverse_index = make_shared<vector<size_t> >();
    }

    basic_flow(const decltype(str) str, const decltype(end) end, const decltype(code) code, 
        const decltype(p_packet_p_seq) p_packet_p_seq, const decltype(p_reverse_index) p_reverse_index):
        str(str), end(end), code(code), p_packet_p_seq(p_packet_p_seq), p_reverse_index(p_reverse_index) {}

    basic_flow(const decltype(p_packet_p_seq) p_packet_p_seq, const decltype(p_reverse_index) p_reverse_index):
        p_packet_p_seq(p_packet_p_seq), p_reverse_index(p_reverse_index) {
            for (const auto p: *p_packet_p_seq) {
                str = min(str, GET_DOUBLE_TS(p->ts));
                end = max(end, GET_DOUBLE_TS(p->ts));
                code |= p->tp;
            }
        }
    virtual ~basic_flow() {};

    basic_flow(const basic_flow&) = default;
    basic_flow & operator=(const basic_flow&) = default;

    bool emplace_packet(const shared_ptr<basic_packet> p, const size_t rid) {
        if (typeid(*p) == typeid(basic_packet_bad)) {
            return false;
        } else {
            auto ts = GET_DOUBLE_TS(p->ts);
            str = min(str, ts);
            end = max(end, ts);
            code |= p->tp;
            p_packet_p_seq->push_back(p);
            p_reverse_index->push_back(rid);
            return true;
        }
    }

    inline auto get_str_time(void) -> decltype(str) {return str;}
    inline auto get_end_time(void) -> decltype(end) {return end;}
    inline auto get_fct(void) -> decltype(end) {return end - str;}
    inline auto get_pkt_code(void) -> decltype(code) {return code;}
    inline auto get_p_reverse_id(void) -> decltype(p_reverse_index) {return p_reverse_index;}
    inline auto get_p_packet_p_seq(void) -> decltype(p_packet_p_seq) {return p_packet_p_seq;}
};


class tuple5_flow4 final: public basic_flow {
public:
    tuple5_conn4 flow_id;

    tuple5_flow4(const tuple5_conn4 & flow_id): flow_id(flow_id) {}

    tuple5_flow4(const tuple5_conn4 & flow_id, 
                const decltype(str) str, 
                const decltype(end) end,
                const decltype(code) code,
                const decltype(p_packet_p_seq) p_packet_p_seq,
                const decltype(p_reverse_index) p_reverse_index): 
                flow_id(flow_id), basic_flow(str, end, code, p_packet_p_seq, p_reverse_index) {}

    tuple5_flow4(const tuple5_conn4 & flow_id, const decltype(p_packet_p_seq) p_packet_p_seq, 
                 const decltype(p_reverse_index) p_reverse_index):
                    flow_id(flow_id), basic_flow(p_packet_p_seq, p_reverse_index) {}
    
    tuple5_flow4(const tuple5_flow4&) = default;
    tuple5_flow4 & operator=(const tuple5_flow4&) = default;
    virtual ~tuple5_flow4() {}
};


class tuple5_flow6 final : public basic_flow {
public:
    tuple5_conn6 flow_id;

    tuple5_flow6(const tuple5_conn6 & flow_id): flow_id(flow_id) {}

    tuple5_flow6(const tuple5_conn6 & flow_id, 
                const decltype(str) str, 
                const decltype(end) end,
                const decltype(code) code,
                const decltype(p_packet_p_seq) p_packet_p_seq,
                const decltype(p_reverse_index) p_reverse_index): 
                flow_id(flow_id), basic_flow(str, end, code, p_packet_p_seq, p_reverse_index) {}
    
    tuple5_flow6(const tuple5_conn6 & flow_id, const decltype(p_packet_p_seq) p_packet_p_seq, 
                 const decltype(p_reverse_index) p_reverse_index):
                    flow_id(flow_id), basic_flow(p_packet_p_seq, p_reverse_index) {}

    tuple5_flow6(const tuple5_flow6&) = default;
    tuple5_flow6 & operator=(const tuple5_flow6&) = default;
    virtual ~tuple5_flow6() {}

};


}