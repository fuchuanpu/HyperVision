#pragma once


#include "../common.hpp"
#include "edge_define.hpp"


#include<boost/functional/hash.hpp>


namespace Hypervision
{

using raw_flow_vec = vector<shared_ptr<basic_flow> >;

class edge_constructor {
private:
    shared_ptr<raw_flow_vec> p_parse_result;

    shared_ptr<vector<shared_ptr<long_edge> > > p_long_edges;
    shared_ptr<vector<shared_ptr<short_edge> > > p_short_edges;

    u_int16_t LENGTH_BIN_SIZE = 10;
    u_int16_t TIME_BIN_SIZE = 1e-3;
    u_int16_t EDGE_LONG_LINE = 15;
    u_int16_t EDGE_AGG_LINE = 20;

    size_t long_packet_sum = 0;
    size_t short_packet_sum = 0;

    void flow_classification(raw_flow_vec & short_flow_pvec, raw_flow_vec &  long_flow_pvec);
    void construct_short_flow(raw_flow_vec & short_flow_pvec);
    void construct_short_flow2(raw_flow_vec & short_flow_pvec);
    void construct_long_flow(raw_flow_vec & long_flow_pvec, size_t multiplex=64);

public:
    explicit edge_constructor(const decltype(p_parse_result) p_parse_result): p_parse_result(p_parse_result) {}

    virtual ~edge_constructor () {}
    edge_constructor(const edge_constructor &) = delete;
    edge_constructor & operator=(const edge_constructor &) = delete;

    void do_construct(void) {
        raw_flow_vec short_flow_pvec, long_flow_pvec;
        flow_classification(short_flow_pvec, long_flow_pvec);
        construct_long_flow(long_flow_pvec);
        construct_short_flow(short_flow_pvec);
        LOGF("After aggregation: %ld short edges [%ld pkts], %ld long edges [%ld pkts].", 
            p_short_edges->size(), short_packet_sum, p_long_edges->size(), long_packet_sum);
    }

    void dump_long_edge(void) const {
        for (const auto edge: * p_long_edges) {
            edge->show_edge();
        }
    }

    void dump_short_edge(void) const {
        for (const auto edge: * p_short_edges) {
            edge->show_edge();
        }
    }

    auto inline get_short_edge(void) const -> decltype(p_short_edges) {
        return p_short_edges;
    }
    auto inline get_long_edge(void) const -> decltype(p_long_edges) {
        return p_long_edges;
    }
    auto inline get_edge(void) const -> pair<decltype(p_short_edges), decltype(p_long_edges)> {
        return {p_short_edges, p_long_edges};
    }

    void config_via_json(const json & jin);
    void show_short_edge_statistic(void) const;
    
};

}
