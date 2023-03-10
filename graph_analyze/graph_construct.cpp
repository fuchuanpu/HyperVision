#include "graph_define.hpp"


using namespace Hypervision;


void traffic_graph::parse_short_edge(void) {
    __START_FTIMMER__
    LOG("Parsing short edge.");

    if (p_short_edge == nullptr) {
        FATAL_ERROR("The short edges not found.");
    }

    auto _f_add_vertex_set = [&] (const addr_t __s) -> bool {
            if (vertex_set_short.find(__s) == vertex_set_short.end()) {
                vertex_set_short.insert(__s);
                return true;
            } else {
                return false;
            }
        };

    const auto _f_add_vertex_set_reduce = [&] (const addr_t & __s) -> bool {
        if (vertex_set_short_reduce.find(__s) == vertex_set_short_reduce.end()) {
            vertex_set_short_reduce.insert(__s);
            return true;
        } else {
            return false;
        }
    };

    auto _f_add_vertex_edge = [&] (decltype(short_edge_in) & __mp, const addr_t __s, const size_t __id) -> void {
        if (__mp.find(__s) == __mp.end()) {
            __mp.insert({__s, {__id}});
        } else {
            __mp[__s].push_back(__id);
        }
    };

    for (size_t i = 0; i < p_short_edge->size(); ++i) {
        const auto _edge = p_short_edge->at(i);
        const addr_t _srcaddr = _edge->get_src_str();
        const addr_t _dstaddr = _edge->get_dst_str();
        const agg_code _agg = _edge->get_agg_code();

        if (is_no_agg(_agg) || (is_src_agg(_agg) && is_dst_agg(_agg))) {
            _f_add_vertex_set(_srcaddr);
            _f_add_vertex_set(_dstaddr);
            _f_add_vertex_set_reduce(_srcaddr);
            _f_add_vertex_set_reduce(_dstaddr);
            _f_add_vertex_edge(short_edge_out, _srcaddr, i);
            _f_add_vertex_edge(short_edge_in, _dstaddr, i);
        } else if (is_src_agg(_agg)) {
            _f_add_vertex_set(_srcaddr);
            _f_add_vertex_edge(short_edge_out_agg, _srcaddr, i);
        } else if (is_dst_agg(_agg)) {
            _f_add_vertex_set(_dstaddr);
            _f_add_vertex_edge(short_edge_in_agg, _dstaddr, i);
        } else {
            assert(false);
        }
    }
    
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void traffic_graph::parse_long_edge(void) {
    LOG("Parsing longlive edge.");
    __START_FTIMMER__

    for (size_t i = 0; i < p_long_edge->size(); ++i) {

        const auto _edge = p_long_edge->at(i);
        const addr_t & _srcaddr = _edge->get_src_str();
        const addr_t & _dstaddr = _edge->get_dst_str();

        if (vertex_set_long.find(_srcaddr) == vertex_set_long.end()) {
            vertex_set_long.insert(_srcaddr);
        }
        if (vertex_set_long.find(_dstaddr) == vertex_set_long.end()) {
            vertex_set_long.insert(_dstaddr);
        }
        
        if (long_edge_out.find(_srcaddr) == long_edge_out.end()) {
            long_edge_out.insert({_srcaddr, {i}});
        } else {
            long_edge_out[_srcaddr].push_back(i);
        }

        if (long_edge_in.find(_dstaddr) == long_edge_in.end()) {
            long_edge_in.insert({_dstaddr, {i}});
        } else {
            long_edge_in[_dstaddr].push_back(i);
        }
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void traffic_graph::dump_graph_statistic_long(void) const {
    LOGF("Number of vertex: %ld.", vertex_set_long.size());

    auto _f = [&] (const decltype(long_edge_in) & mp) -> size_t {
        size_t i = 0;
        for(auto & v : mp)
            i = max(i, v.second.size());
        return i;
    };

    LOGF("In/Out degree max: %ld / %ld", _f(long_edge_in), _f(long_edge_out));

#ifdef DUMP_DEGREE
    using size_collector = map<size_t, size_t>;
    size_collector size_mp_in, size_mp_out;
    auto __f = [&] (const decltype(long_edge_in) & mp,  size_collector & col) -> void {
        for(const auto & ref: mp) {
            const size_t ___t = ref.second.size();
            if (col.find(___t) == col.end()) {
                col.insert({___t, 1});
            } else {
                ++ col[___t];
            }
        }
    };

    __f(long_edge_in, size_mp_in);
    __f(long_edge_out, size_mp_out);

    printf("[Long edge in-degree.]\n");
    for (const auto & ref: size_mp_in) {
        printf("|- %5ld-%-5ld\n", ref.first, ref.second);
    }
    printf("[Long edge out-degree.]\n");
    for (const auto & ref: size_mp_out) {
        printf("|- %5ld-%-5ld\n", ref.first, ref.second);
    }
#endif

}


void traffic_graph::dump_graph_statistic_short(void) const {
    
    LOGF("Number of vertex: %ld.", vertex_set_short.size());

    size_t mx_degree_in = 0, mx_degree_out = 0;

    for (const auto & ref: vertex_set_short) {
        size_t __ctr_in = 0, __ctr_out = 0;
        __ctr_in += short_edge_in.find(ref) != short_edge_in.end() ? short_edge_in.at(ref).size() : 0;
        __ctr_in += short_edge_in_agg.find(ref) != short_edge_in_agg.end() ? short_edge_in_agg.at(ref).size() : 0;

        __ctr_out += short_edge_out.find(ref) != short_edge_out.end() ? short_edge_out.at(ref).size() : 0;
        __ctr_out += short_edge_out_agg.find(ref) != short_edge_out_agg.end() ? short_edge_out_agg.at(ref).size() : 0;

        mx_degree_in = max(mx_degree_in, __ctr_in);
        mx_degree_out = max(mx_degree_out, __ctr_out);
    }

    LOGF("In/Out degree max: %ld / %ld", mx_degree_in, mx_degree_out);

#ifdef DUMP_DEGREE
    using size_collector = map<size_t, size_t>;
    size_collector size_mp_in, size_mp_out;
    size_collector size_mp_in_agg, size_mp_out_agg;

    auto __f = [&] (const decltype(short_edge_in) & mp,  size_collector & col) -> void {
        for(const auto & ref: mp) {
            const size_t ___t = ref.second.size();
            if (col.find(___t) == col.end()) {
                col.insert({___t, 1});
            } else {
                ++ col[___t];
            }
        }
    };

    auto ___f = [&] (const size_collector & col) -> void {
        for (const auto & ref: col) {
            printf("|- %5ld-%-5ld\n", ref.first, ref.second);
        }
    };

    __f(short_edge_in, size_mp_in);
    __f(short_edge_in_agg, size_mp_in_agg);
    __f(short_edge_out, size_mp_out);
    __f(short_edge_out_agg, size_mp_out_agg);

    printf("short edge in-degree.\n");
    ___f(size_mp_in);
    printf("short edge in-degree (aggregate).\n");
    ___f(size_mp_in_agg);
    printf("short edge out-degree.\n");
    ___f(size_mp_out);
    printf("short edge out-degree (aggregate).\n");
    ___f(size_mp_out_agg);

#endif

}
