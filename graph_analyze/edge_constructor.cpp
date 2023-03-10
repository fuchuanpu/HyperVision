#include "edge_constructor.hpp"


using namespace Hypervision;


void edge_constructor::flow_classification(raw_flow_vec & short_flow_pvec, raw_flow_vec &  long_flow_pvec) {
    size_t sum_short = 0, sum_long = 0;
    for (const auto p_f: * p_parse_result) {
        if (p_f->get_p_reverse_id()->size() > EDGE_LONG_LINE) {
            long_flow_pvec.push_back(p_f);
            sum_long += p_f->get_p_packet_p_seq()->size();
        } else {
            short_flow_pvec.push_back(p_f);
            sum_short += p_f->get_p_packet_p_seq()->size();
        }
    }
    LOGF("Before aggregation: %ld short edges [%ld pkts], %ld long edges [%ld pkts].", 
            short_flow_pvec.size(), sum_short, long_flow_pvec.size(), sum_long);
}


void edge_constructor::construct_long_flow(raw_flow_vec & long_flow_pvec, size_t multiplex) {
    __START_FTIMMER__

    if (p_long_edges != nullptr) {
        WARN("Long flow constructing results are detected.");
    }

    p_long_edges = make_shared<decltype(p_long_edges)::element_type>();
    long_packet_sum = 0;

    const u_int32_t part_size = ceil(((double) long_flow_pvec.size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, long_flow_pvec.size())});
    }

    mutex result_m;

    auto __f = [&] (const size_t _from, const size_t _to) -> void {
        auto temp_result = make_shared<decltype(p_long_edges)::element_type>();
        for (size_t i = _from; i < _to; i ++) {
            const auto p_f = long_flow_pvec[i];
            const auto p_pkt_seq = p_f->get_p_packet_p_seq();
            
            shared_ptr<len_db> _len_db = make_shared<len_db>();
            shared_ptr<type_db> _type_db = make_shared<type_db>();
            shared_ptr<interval_db> _time_db = make_shared<interval_db>();
            double_t time_ctr = GET_DOUBLE_TS(p_pkt_seq->at(0)->ts);

            for (const auto p_p: *p_pkt_seq) {
                size_t __fuzzing_len = (p_p->len / LENGTH_BIN_SIZE) * LENGTH_BIN_SIZE;
                size_t __fuzzing_time = floor(max(GET_DOUBLE_TS(p_p->ts) - time_ctr, 0.0) / TIME_BIN_SIZE);
                time_ctr = max(time_ctr, GET_DOUBLE_TS(p_p->ts));
                pkt_code_t __type = p_p->tp;

                if (_len_db->find(__fuzzing_len) == _len_db->end()) {
                    _len_db->insert({__fuzzing_len, 1});
                } else {
                    _len_db->at(__fuzzing_len) ++;
                }
                if (_type_db->find(__type) == _type_db->end()) {
                    _type_db->insert({__type, 1});
                } else {
                    _type_db->at(__type) ++;
                }
                if (_time_db->find(__fuzzing_time) == _time_db->end()) {
                    _time_db->insert({__fuzzing_time, 1});
                } else {
                    _time_db->at(__fuzzing_time) ++;
                }
            }

            const auto _long_to_add = make_shared<long_edge>(p_f, _len_db, _type_db, _time_db);
            temp_result->push_back(_long_to_add);
        }
        result_m.lock();
        for (const auto p_f : * temp_result) {
            p_long_edges->push_back(p_f);
            long_packet_sum += p_f->get_raw_flow()->get_p_packet_p_seq()->size();
        }
        result_m.unlock();
    };

    vector<thread> vt;
    for (size_t core = 0; core < multiplex; ++core) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second);
    }

    for (auto & t : vt)
        t.join();

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void edge_constructor::construct_short_flow(raw_flow_vec & short_flow_pvec) {
    __START_FTIMMER__

    if (p_short_edges != nullptr) {
        WARN("Detect previous short edge.");
    }
    p_short_edges = make_shared<decltype(p_short_edges)::element_type>();
    short_packet_sum = 0;

    using unif_addr_t = __uint128_t;
    vector<unif_addr_t> f_src_vec, f_dst_vec;

    for (const auto p_f: short_flow_pvec) {
        if (typeid(*p_f) == typeid(tuple5_flow4)) {
            const auto p_f4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
            f_src_vec.push_back(tuple_get_src_addr(p_f4->flow_id));
            f_dst_vec.push_back(tuple_get_dst_addr(p_f4->flow_id));
        } else {
            const auto p_f6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
            f_src_vec.push_back(tuple_get_src_addr(p_f6->flow_id));
            f_dst_vec.push_back(tuple_get_dst_addr(p_f6->flow_id));
        }
    }
    vector<bool> is_fetched;
    fill_n(back_inserter(is_fetched), short_flow_pvec.size(), false);

    using id_vec_t = vector<size_t>;
    using src_agg_key_t = pair<unif_addr_t, pkt_code_t>;
    using dst_agg_key_t = src_agg_key_t;
    using src_dst_agg_key_t = tuple<unif_addr_t, unif_addr_t, pkt_code_t>;

    unordered_map<src_agg_key_t, id_vec_t, boost::hash<src_agg_key_t> > src_agg_select;
    unordered_map<dst_agg_key_t, id_vec_t, boost::hash<dst_agg_key_t> > dst_agg_select;
    unordered_map<src_dst_agg_key_t, id_vec_t, boost::hash<src_dst_agg_key_t> > src_dst_agg_select;

    vector<id_vec_t> src_dst_agg_res, src_agg_res, dst_agg_res;

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        const src_dst_agg_key_t tag = {f_src_vec[i], f_dst_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (src_dst_agg_select.find(tag) == src_dst_agg_select.end()) {
            src_dst_agg_select.insert({tag, {i}});
        } else {
            src_dst_agg_select[tag].push_back(i);
        }
    }

    for (const auto ref: src_dst_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const src_agg_key_t tag = {f_src_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (src_agg_select.find(tag) == src_agg_select.end()) {
            src_agg_select.insert({tag, {i}});
        } else {
            src_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: src_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }
    
    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const dst_agg_key_t tag = {f_dst_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (dst_agg_select.find(tag) == dst_agg_select.end()) {
            dst_agg_select.insert({tag, {i}});
        } else {
            dst_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: dst_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    const auto _f_get_port = [&short_flow_pvec](const size_t id) -> pair<pkt_port_t, pkt_port_t> {
        const auto p_f = short_flow_pvec[id];
        if (typeid(*p_f) == typeid(tuple5_flow4)) {
            const auto p_f4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
            return {tuple_get_src_port(p_f4->flow_id), tuple_get_dst_port(p_f4->flow_id)};
        } else {
            const auto p_f6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
            return {tuple_get_src_port(p_f6->flow_id), tuple_get_dst_port(p_f6->flow_id)};    
        }
    };

    const auto _f_set_port_agg_code = [&short_flow_pvec, &_f_get_port]
                            (const vector<size_t> & ve, agg_code & code_to_add) -> void {
        const auto port_pair0 = _f_get_port(ve[0]);
        bool src_p_agg_enable = true, dst_p_agg_enable = true;
        for (const auto id: ve) {
            const auto _port_pair = _f_get_port(id);
            if (_port_pair.first != port_pair0.first) {
                src_p_agg_enable = false;
            }
            if (_port_pair.second != port_pair0.second) {
                dst_p_agg_enable = false;
            }
            if (src_p_agg_enable == false && dst_p_agg_enable == false) {
                break;
            }
        }
        if (src_p_agg_enable) {
            set_srcp_agg(code_to_add);
        }
        if (dst_p_agg_enable) {
            set_dstp_agg(code_to_add);
        }
    };

    for (const auto & ve : src_dst_agg_res) {
        agg_code code_to_add = 0;
        set_src_agg(code_to_add);
        set_dst_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (const auto & ve : src_agg_res) {
        agg_code code_to_add = 0;
        set_src_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (const auto & ve : dst_agg_res) {
        agg_code code_to_add = 0;
        set_dst_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++i) {
        if (is_fetched[i] == false) {
            agg_code code_to_add = 0;
            set_no_agg(code_to_add);
            const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
            p_add->push_back(short_flow_pvec[i]);
            short_packet_sum += short_flow_pvec[i]->get_p_packet_p_seq()->size();
            p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
        }
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void edge_constructor::construct_short_flow2(raw_flow_vec & short_flow_pvec) {
        __START_FTIMMER__

    if (p_short_edges != nullptr) {
        WARN("Detect previous short edge.");
    }
    p_short_edges = make_shared<decltype(p_short_edges)::element_type>();
    short_packet_sum = 0;

    using unif_addr_t = __uint128_t;
    vector<unif_addr_t> f_src_vec, f_dst_vec;
    vector<pkt_port_t> f_sp_vec, f_dp_vec;

    for (const auto p_f: short_flow_pvec) {
        if (typeid(*p_f) == typeid(tuple5_flow4)) {
            const auto p_f4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
            f_src_vec.push_back(tuple_get_src_addr(p_f4->flow_id));
            f_dst_vec.push_back(tuple_get_dst_addr(p_f4->flow_id));
            f_sp_vec.push_back(tuple_get_src_port(p_f4->flow_id));
            f_dp_vec.push_back(tuple_get_dst_port(p_f4->flow_id));
        } else {
            const auto p_f6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
            f_src_vec.push_back(tuple_get_src_addr(p_f6->flow_id));
            f_dst_vec.push_back(tuple_get_dst_addr(p_f6->flow_id));
            f_sp_vec.push_back(tuple_get_src_port(p_f6->flow_id));
            f_dp_vec.push_back(tuple_get_dst_port(p_f6->flow_id));
        }
    }
    vector<bool> is_fetched;
    fill_n(back_inserter(is_fetched), short_flow_pvec.size(), false);

    using id_vec_t = vector<size_t>;
    using srcdst_sp_agg_key_t = tuple<unif_addr_t, unif_addr_t, pkt_port_t, pkt_code_t>;
    using srcdst_dp_agg_key_t = srcdst_sp_agg_key_t;
    using srcp_agg_key_t = tuple<unif_addr_t, pkt_port_t, pkt_code_t>;
    using dstp_agg_key_t = srcp_agg_key_t;
    using src_agg_key_t = pair<unif_addr_t, pkt_code_t>;
    using dst_agg_key_t = src_agg_key_t;
    using src_dst_agg_key_t = tuple<unif_addr_t, unif_addr_t, pkt_code_t>;

    unordered_map<src_agg_key_t, id_vec_t, boost::hash<src_agg_key_t> > src_agg_select;
    unordered_map<dst_agg_key_t, id_vec_t, boost::hash<dst_agg_key_t> > dst_agg_select;
    unordered_map<srcp_agg_key_t, id_vec_t, boost::hash<srcp_agg_key_t> > srcp_agg_select;
    unordered_map<dstp_agg_key_t, id_vec_t, boost::hash<dstp_agg_key_t> > dstp_agg_select;
    unordered_map<src_dst_agg_key_t, id_vec_t, boost::hash<src_dst_agg_key_t> > src_dst_agg_select;
    unordered_map<srcdst_sp_agg_key_t, id_vec_t, boost::hash<srcdst_sp_agg_key_t> > srcdst_sp_agg_select;
    unordered_map<srcdst_dp_agg_key_t, id_vec_t, boost::hash<srcdst_dp_agg_key_t> > srcdst_dp_agg_select;

    vector<id_vec_t> src_dst_agg_res, src_agg_res, dst_agg_res;

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const srcdst_dp_agg_key_t tag = {f_src_vec[i], f_dst_vec[i], f_sp_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (srcdst_sp_agg_select.find(tag) == srcdst_sp_agg_select.end()) {
            srcdst_sp_agg_select.insert({tag, {i}});
        } else {
            srcdst_sp_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: srcdst_sp_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const srcdst_dp_agg_key_t tag = {f_src_vec[i], f_dst_vec[i], f_dp_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (srcdst_dp_agg_select.find(tag) == srcdst_dp_agg_select.end()) {
            srcdst_dp_agg_select.insert({tag, {i}});
        } else {
            srcdst_dp_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: srcdst_dp_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const src_dst_agg_key_t tag = {f_src_vec[i], f_dst_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (src_dst_agg_select.find(tag) == src_dst_agg_select.end()) {
            src_dst_agg_select.insert({tag, {i}});
        } else {
            src_dst_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: src_dst_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const srcp_agg_key_t tag = {f_src_vec[i], f_sp_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (srcp_agg_select.find(tag) == srcp_agg_select.end()) {
            srcp_agg_select.insert({tag, {i}});
        } else {
            srcp_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: srcp_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const dstp_agg_key_t tag = {f_dst_vec[i], f_dp_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (dstp_agg_select.find(tag) == dstp_agg_select.end()) {
            dstp_agg_select.insert({tag, {i}});
        } else {
            dstp_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: dstp_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const src_agg_key_t tag = {f_src_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (src_agg_select.find(tag) == src_agg_select.end()) {
            src_agg_select.insert({tag, {i}});
        } else {
            src_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: src_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            src_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }
    
    for (size_t i = 0; i < short_flow_pvec.size(); ++ i) {
        if (is_fetched[i]) {
            continue;
        }
        const dst_agg_key_t tag = {f_dst_vec[i], short_flow_pvec[i]->get_pkt_code()};
        if (dst_agg_select.find(tag) == dst_agg_select.end()) {
            dst_agg_select.insert({tag, {i}});
        } else {
            dst_agg_select[tag].push_back(i);
        }
    }
    for (const auto ref: dst_agg_select) {
        if (ref.second.size() > EDGE_AGG_LINE) {
            dst_agg_res.push_back(ref.second);
            for (const auto id : ref.second) {
                assert(is_fetched[id] == false);
                is_fetched[id] = true;
            }
        }
    }

    const auto _f_get_port = [&short_flow_pvec](const size_t id) -> pair<pkt_port_t, pkt_port_t> {
        const auto p_f = short_flow_pvec[id];
        if (typeid(*p_f) == typeid(tuple5_flow4)) {
            const auto p_f4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
            return {tuple_get_src_port(p_f4->flow_id), tuple_get_dst_port(p_f4->flow_id)};
        } else {
            const auto p_f6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
            return {tuple_get_src_port(p_f6->flow_id), tuple_get_dst_port(p_f6->flow_id)};    
        }
    };

    const auto _f_set_port_agg_code = [&short_flow_pvec, &_f_get_port]
                            (const vector<size_t> & ve, agg_code & code_to_add) -> void {
        const auto port_pair0 = _f_get_port(ve[0]);
        bool src_p_agg_enable = true, dst_p_agg_enable = true;
        for (const auto id: ve) {
            const auto _port_pair = _f_get_port(id);
            if (_port_pair.first != port_pair0.first) {
                src_p_agg_enable = false;
            }
            if (_port_pair.second != port_pair0.second) {
                dst_p_agg_enable = false;
            }
            if (src_p_agg_enable == false && dst_p_agg_enable == false) {
                break;
            }
        }
        if (src_p_agg_enable) {
            set_srcp_agg(code_to_add);
        }
        if (dst_p_agg_enable) {
            set_dstp_agg(code_to_add);
        }
    };

    for (const auto & ve : src_dst_agg_res) {
        agg_code code_to_add = 0;
        set_src_agg(code_to_add);
        set_dst_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (const auto & ve : src_agg_res) {
        agg_code code_to_add = 0;
        set_src_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (const auto & ve : dst_agg_res) {
        agg_code code_to_add = 0;
        set_dst_agg(code_to_add);
        _f_set_port_agg_code(ve, code_to_add);
        const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
        for (const auto id: ve) {
            p_add->push_back(short_flow_pvec[id]);
            short_packet_sum += short_flow_pvec[id]->get_p_packet_p_seq()->size();
        }
        p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
    }

    for (size_t i = 0; i < short_flow_pvec.size(); ++i) {
        if (is_fetched[i] == false) {
            agg_code code_to_add = 0;
            set_no_agg(code_to_add);
            const auto p_add = make_shared<vector<shared_ptr<basic_flow> > >();
            p_add->push_back(short_flow_pvec[i]);
            short_packet_sum += short_flow_pvec[i]->get_p_packet_p_seq()->size();
            p_short_edges->push_back(make_shared<short_edge>(p_add, code_to_add));
        }
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void edge_constructor::show_short_edge_statistic(void) const {
    if (p_short_edges == nullptr) {
        FATAL_ERROR("Short edge not found.");
    }
    size_t num_no_agg = 0;
    size_t num_srcdst_agg = 0;
    size_t num_dst_agg = 0;
    size_t num_src_agg = 0;
    size_t num_srcp_agg = 0;
    size_t num_dstp_agg = 0;

    for (const auto p_e: * p_short_edges) {
        const auto _co = p_e->get_agg_code();
        if (is_no_agg(_co)) {
            ++ num_no_agg;
        } else {
            if (is_src_agg(_co) && is_dst_agg(_co)) {
                ++ num_srcdst_agg;
            } else {
                if (is_src_agg(_co)) {
                    ++ num_src_agg;
                } else {
                    ++ num_dst_agg;
                }
            }
            if (is_srcp_agg(_co)) {
                ++ num_srcp_agg;
            }
            if (is_dstp_agg(_co)) {
                ++ num_dstp_agg;
            }
        }
    }
    printf("[NO_AGG  ]: %6ld\n", num_no_agg);
    printf("[SRC_DST ]: %6ld\n", num_srcdst_agg);
    printf("[SRC_AGG ]: %6ld\n", num_src_agg);
    printf("[DST_AGG ]: %6ld\n", num_dst_agg);
    printf("[SRCP_AGG]: %6ld\n", num_srcp_agg);
    printf("[DSTP_AGG]: %6ld\n", num_dstp_agg);
    printf("[SUM     ]: %6ld\n", num_no_agg + num_srcdst_agg + num_dst_agg + num_src_agg);
}


void edge_constructor::config_via_json(const json & jin) {
    try {
        if (jin.count("length_bin_size")) {
            LENGTH_BIN_SIZE = static_cast<decltype(LENGTH_BIN_SIZE)>(jin["length_bin_size"]);
        }
        if (jin.count("edge_long_line")) {
            EDGE_LONG_LINE = static_cast<decltype(EDGE_LONG_LINE)>(jin["edge_long_line"]);
        }
        if (jin.count("edge_agg_line")) {
            EDGE_AGG_LINE = static_cast<decltype(EDGE_AGG_LINE)>(jin["edge_agg_line"]);
        }
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }
}