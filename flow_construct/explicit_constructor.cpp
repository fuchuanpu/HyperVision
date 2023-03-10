#include "explicit_constructor.hpp"

using namespace Hypervision;

#include<boost/functional/hash.hpp>

using flow_hash_4_t = tuple5_conn4;
using flow_H_table_entry_4_t = shared_ptr<tuple5_flow4>;
using flow_H_table_4_t = unordered_map<flow_hash_4_t, flow_H_table_entry_4_t, boost::hash<flow_hash_4_t>> ;

using flow_hash_6_t = tuple5_conn6;
using flow_H_table_entry_6_t = shared_ptr<tuple5_flow6>;
using flow_H_table_6_t = unordered_map<flow_hash_6_t, flow_H_table_entry_6_t, boost::hash<flow_hash_6_t>>;


void explicit_flow_constructor::construct_flow(size_t multiplex) {
    __START_FTIMMER__

    if (p_parse_result == nullptr) {
        FATAL_ERROR("The packet to construct not exists.");
    }

    if (p_construct_result4 != nullptr || p_construct_result6 != nullptr) {
        WARN("Previous flow construction result detected, do it again.");
    }

    p_construct_result4 = make_shared<decltype(p_construct_result4)::element_type>();
    p_construct_result6 = make_shared<decltype(p_construct_result6)::element_type>();

    mutex construct_mutex;
    const u_int32_t part_size = ceil(((double) p_parse_result->size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, p_parse_result->size())});
    }

    auto __f = [&] (size_t _from, size_t _to) -> void {
        
        if (_from == _to) {
            return;
        }
        
        flow_H_table_4_t flow_H_table_4;
        flow_H_table_6_t flow_H_table_6;

        vector<flow_H_table_entry_4_t> flow4_to_add;
        vector<flow_H_table_entry_6_t> flow6_to_add;

        double_t last_check_time = GET_DOUBLE_TS(p_parse_result->at(_from)->ts);

        for(size_t i = _from ; i < _to;  ++i) {
            auto p_rep = p_parse_result->at(i);
            if (typeid(*p_rep) == typeid(basic_packet_bad)) {
                continue;
            }

            const auto _timestp = GET_DOUBLE_TS(p_rep->ts);
            if (typeid(*p_rep) == typeid(basic_packet4)) {
                const auto _p_rep = dynamic_pointer_cast<basic_packet4>(p_rep);
                const auto _stack_code = convert_packet2stack_code(_p_rep->tp);
                const auto _flow_id = tuple4_extend(_p_rep->flow_id, _stack_code);
                if (flow_H_table_4.find(_flow_id) == flow_H_table_4.end()) {
                    const auto _to_add = make_shared<tuple5_flow4>(_flow_id);
                    _to_add->emplace_packet(p_rep, i);
                    flow_H_table_4.insert({_flow_id, _to_add});
                } else {
                    flow_H_table_4[_flow_id]->emplace_packet(p_rep, i);
                }
            } else if (typeid(*p_rep) == typeid(basic_packet6)) {
                const auto _p_rep = dynamic_pointer_cast<basic_packet6>(p_rep);
                const auto _stack_code = convert_packet2stack_code(_p_rep->tp);
                const auto _flow_id = tuple4_extend(_p_rep->flow_id, _stack_code);
                if (flow_H_table_6.find(_flow_id) == flow_H_table_6.end()) {
                    const auto _to_add = make_shared<tuple5_flow6>(_flow_id);
                    _to_add->emplace_packet(p_rep, i);
                    flow_H_table_6.insert({_flow_id, _to_add});
                } else {
                    flow_H_table_6[_flow_id]->emplace_packet(p_rep, i);
                }
            } else {
                assert(false);
            }

            if ((_timestp - last_check_time - EVICT_FLOW_TIME_OUT) > EPS) {
                last_check_time = _timestp;

                unordered_set<flow_hash_4_t, boost::hash<flow_hash_4_t> > evicted_flow4;
                for_each(begin(flow_H_table_4), end(flow_H_table_4), 
                                [&] (flow_H_table_4_t::const_reference & ref) -> void {
                    if ((_timestp - ref.second->get_end_time() - FLOW_TIME_OUT) > EPS) {
                        evicted_flow4.insert(ref.first);
                        flow4_to_add.push_back(ref.second);
                    }
                });
                for(const auto & _bc: evicted_flow4) {
                    flow_H_table_4.erase(_bc);
                }

                unordered_set<flow_hash_6_t, boost::hash<flow_hash_6_t> > evicted_flow6;
                for_each(begin(flow_H_table_6), end(flow_H_table_6), 
                                [&] (flow_H_table_6_t::const_reference & ref) -> void {
                    if ((_timestp - ref.second->get_end_time() - FLOW_TIME_OUT) > EPS) {
                        evicted_flow6.insert(ref.first);
                        flow6_to_add.push_back(ref.second);
                    }
                });
                for(const auto & _bc: evicted_flow6) {
                    flow_H_table_6.erase(_bc);
                }
            }
        }
        for_each(begin(flow_H_table_4), end(flow_H_table_4), 
                        [&] (flow_H_table_4_t::const_reference & ref) -> void {
            flow4_to_add.push_back(ref.second);
        });
        for_each(begin(flow_H_table_6), end(flow_H_table_6), 
                        [&] (flow_H_table_6_t::const_reference & ref) -> void {
            flow6_to_add.push_back(ref.second);
        });

        construct_mutex.lock();
        copy(flow4_to_add.cbegin(), flow4_to_add.cend(), back_inserter(*p_construct_result4));
        copy(flow6_to_add.cbegin(), flow6_to_add.cend(), back_inserter(*p_construct_result6));
        construct_mutex.unlock();
    };

    vector<thread> vt;
    for (size_t core = 0; core < multiplex; ++core) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second);
    }

    for (auto & t : vt)
        t.join();

    LOGF("Number of flows: %ld [%ld IPv4 | %ld IPv6].", p_construct_result4->size() + p_construct_result6->size(),
        p_construct_result4->size(), p_construct_result6->size());
    flow_double_check();

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void explicit_flow_constructor::_flow_double_check4(size_t multiplex) {
    const decltype(p_construct_result4) p_construct_result4_temp = p_construct_result4;
    using flow_check_table4 = unordered_map<flow_hash_4_t, vector<shared_ptr<tuple5_flow4> >, boost::hash<flow_hash_4_t> >;
    using flow_check_table_entry = vector<shared_ptr<tuple5_flow4> >;
    flow_check_table4 col4;
    for (const auto p: *p_construct_result4_temp) {
        if (col4.find(p->flow_id) == col4.end()) {
            col4.insert({p->flow_id, {p}});
        } else {
            col4[p->flow_id].push_back(p);
        }
    }

    vector<flow_check_table4::key_type> __vec_key;
    vector<flow_check_table_entry> __vec_value;
    for(auto & ref: col4) {
        __vec_key.push_back(ref.first);
        __vec_value.push_back(ref.second);
    }
    const u_int32_t part_size = ceil(((double) col4.size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, col4.size())});
    }
    p_construct_result4 = make_shared<decltype(p_construct_result4)::element_type>();
    mutex result_m;

    auto __f = [&] (const size_t _from, const size_t _to) -> void {
        auto temp_result4 = make_shared<decltype(p_construct_result4)::element_type>();
        for (size_t i = _from; i < _to; i ++) {
            auto pvec = __vec_value[i];
            auto flow_id = __vec_key[i];
            assert(pvec.size() != 0);
            if (pvec.size() == 1) {
                temp_result4->push_back(pvec[0]);
            } else {
                sort(pvec.begin(), pvec.end(), [](shared_ptr<tuple5_flow4> a, shared_ptr<tuple5_flow4> b) -> bool {
                    assert(a != nullptr && b != nullptr);
                    return a->get_str_time() < b->get_end_time();
                });

                auto _str = begin(pvec), _prev = begin(pvec);
                auto _f_merge = [&flow_id] (decltype(_str) _str, decltype(_str) _cur) -> shared_ptr<tuple5_flow4> {
                    auto ptr_to_add = make_shared<vector<shared_ptr<basic_packet> > >();
                    auto index_to_add = make_shared<vector<size_t> >();
                    for (auto ite = _str; ite < _cur; ite ++) {
                        const auto & seq_to_merge = *(*ite)->get_p_packet_p_seq();
                        const auto & index_to_merge = *(*ite)->get_p_reverse_id();
                        ptr_to_add->insert(end(*ptr_to_add), begin(seq_to_merge), end(seq_to_merge));
                        index_to_add->insert(end(*index_to_add), begin(index_to_merge), end(index_to_merge));
                    }
                    return make_shared<tuple5_flow4>(flow_id, ptr_to_add, index_to_add);
                };
                for (auto _cur = begin(pvec) + 1; _cur != end(pvec); _cur ++, _prev ++) {
                    assert((*_cur) != nullptr);
                    if ((*_cur)->get_str_time() - (*_prev)->get_end_time() >= FLOW_TIME_OUT) {
                        temp_result4->push_back(_f_merge(_str, _cur));
                        _str = _cur;
                    }
                }
                temp_result4->push_back(_f_merge(_str, end(pvec)));
            }
        }
        result_m.lock();
        p_construct_result4->insert(p_construct_result4->end(), temp_result4->begin(), temp_result4->end());
        result_m.unlock();
    };

    vector<thread> vt;
    for (size_t core = 0; core < multiplex; ++core) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second);
    }

    for (auto & t : vt)
        t.join();
}


void explicit_flow_constructor::_flow_double_check6(size_t multiplex) {
    const decltype(p_construct_result6) p_construct_result6_temp = p_construct_result6;
    using flow_check_table6 = unordered_map<flow_hash_6_t, vector<shared_ptr<tuple5_flow6> >, boost::hash<flow_hash_6_t> >;
    using flow_check_table_entry = vector<shared_ptr<tuple5_flow6> >;
    flow_check_table6 col6;
    for (const auto p: *p_construct_result6_temp) {
        if (col6.find(p->flow_id) == col6.end()) {
            col6.insert({p->flow_id, {p}});
        } else {
            col6[p->flow_id].push_back(p);
        }
    }

    vector<flow_check_table6::key_type> __vec_key;
    vector<flow_check_table_entry> __vec_value;
    for(auto & ref: col6) {
        __vec_key.push_back(ref.first);
        __vec_value.push_back(ref.second);
    }
    const u_int32_t part_size = ceil(((double) col6.size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, col6.size())});
    }
    p_construct_result6 = make_shared<decltype(p_construct_result6)::element_type>();
    mutex result_m;

    auto __f = [&] (const size_t _from, const size_t _to) -> void {
        auto temp_result6 = make_shared<decltype(p_construct_result6)::element_type>();
        for (size_t i = _from; i < _to; i ++) {
            auto pvec = __vec_value[i];
            auto flow_id = __vec_key[i];
            assert(pvec.size() != 0);
            if (pvec.size() == 1) {
                temp_result6->push_back(pvec[0]);
            } else {
                sort(pvec.begin(), pvec.end(), [](shared_ptr<tuple5_flow6> a, shared_ptr<tuple5_flow6> b) -> bool {
                    return a->get_str_time() < b->get_end_time();
                });

                auto _str = begin(pvec), _prev = begin(pvec);
                auto _f_merge = [&flow_id] (decltype(_str) _str, decltype(_str) _cur) -> shared_ptr<tuple5_flow6> {
                    auto ptr_to_add = make_shared<vector<shared_ptr<basic_packet> > >();
                    auto index_to_add = make_shared<vector<size_t> >();
                    for (auto ite = _str; ite < _cur; ite ++) {
                        const auto & seq_to_merge = *(*ite)->get_p_packet_p_seq();
                        const auto & index_to_merge = *(*ite)->get_p_reverse_id();
                        ptr_to_add->insert(end(*ptr_to_add), begin(seq_to_merge), end(seq_to_merge));
                        index_to_add->insert(end(*index_to_add), begin(index_to_merge), end(index_to_merge));
                    }
                    return make_shared<tuple5_flow6>(flow_id, ptr_to_add, index_to_add);
                };
                for (auto _cur = begin(pvec) + 1; _cur != end(pvec); _cur ++, _prev ++) {
                    assert((*_cur) != nullptr);
                    if ((*_cur)->get_str_time() - (*_prev)->get_end_time() >= FLOW_TIME_OUT) {
                        temp_result6->push_back(_f_merge(_str, _cur));
                        _str = _cur;
                    }
                }
                temp_result6->push_back(_f_merge(_str, end(pvec)));
            }
        }
        result_m.lock();
        p_construct_result6->insert(p_construct_result6->end(), temp_result6->begin(), temp_result6->end());
        result_m.unlock();
    };

    vector<thread> vt;
    for (size_t core = 0; core < multiplex; ++core) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second);
    }

    for (auto & t : vt)
        t.join();
}


void explicit_flow_constructor::flow_double_check(size_t multiplex) {
    __START_FTIMMER__

    thread th4(&explicit_flow_constructor::_flow_double_check4, this, multiplex);
    thread th6(&explicit_flow_constructor::_flow_double_check6, this, multiplex);

    th4.join();
    th6.join();

    LOGF("Number of flows: %ld [%ld IPv4 | %ld IPv6].", p_construct_result4->size() + p_construct_result6->size(),
            p_construct_result4->size(), p_construct_result6->size());
    
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void explicit_flow_constructor::dump_flow_statistic(void) const {
    __START_FTIMMER__

    if (p_parse_result == nullptr) {
        FATAL_ERROR("The packet toconstruct not exists.");
    }

    if (p_construct_result4 == nullptr || p_construct_result6 == nullptr) {
        WARN("Flow construction has not been done.");
        return;
    }

    LOGF("Constructed IPv4 flow: %8ld, IPv6 flow: %8ld", 
        p_construct_result4->size(), p_construct_result6->size());
    LOGF("Display parsed flow statistic:");

    vector<u_int32_t> __sat4(stack_type_t::F_UNKNOWN);
    for (auto p_flow: *p_construct_result4) {
        for (uint8_t i = 0; i < stack_type_t::F_UNKNOWN; i ++) {
            if (tuple_get_stack(p_flow->flow_id) == get_pkt_stack_code((stack_type_t) i)) {
                __sat4[i] ++;
            }
        }
    }

    vector<u_int32_t> __sat6(stack_type_t::F_UNKNOWN);
    for (auto p_flow: *p_construct_result6) {
        for (uint8_t i = 0; i < stack_type_t::F_UNKNOWN; i ++) {
            if (tuple_get_stack(p_flow->flow_id) == get_pkt_stack_code((stack_type_t) i)) {
                __sat6[i] ++;
            }
        }
    }

    printf("[Sum IPv4 Flow]: %ld\n", p_construct_result4->size());
    for (size_t i = 0; i < stack_type_t::F_UNKNOWN; i ++) {
        printf("[%-8s]: %d\n", stack2name[i], __sat4[i]);
    }
    printf("[Sum IPv6 Flow]: %ld\n", p_construct_result6->size());
    for (size_t i = 0; i < stack_type_t::F_UNKNOWN; i ++) {
        printf("[%-8s]: %d\n", stack2name[i], __sat6[i]);
    }

#ifdef FLOW_PACKET_SUM_CHECK
    size_t ipv4_packets = 0;
    for (const auto p_rep: *p_construct_result4) {
        ipv4_packets += p_rep->get_p_packet_p_seq()->size();
    }
    size_t ipv6_packets = 0;
    for (const auto p_rep: *p_construct_result6) {
        ipv6_packets += p_rep->get_p_packet_p_seq()->size();
    }
    printf("[%-8s]: %ld\n", "IPv4", ipv4_packets);
    printf("[%-8s]: %ld\n", "IPv6", ipv6_packets);
#endif

#ifdef FLOW_TIME_CHECK
    LOG("Flow time length statistic.");
    vector<double_t> time_vec;
    for (const auto p_rep: *p_construct_result4) {
        time_vec.push_back(p_rep->get_fct());
    }
    for (const auto p_rep: *p_construct_result6) {
        time_vec.push_back(p_rep->get_fct());
    }

    const size_t time_bin_num = 10;
    map<size_t, size_t> time_stat;
    for(const auto v : time_vec) {
        const auto index = ceil(v);
        if (time_stat.find(index) == time_stat.end()) {
            time_stat.insert({index, 1});
        } else {
            ++ time_stat[index];
        }
    }
    for (const auto & ref: time_stat) {
        printf("[%2lds -%2lds]: %6ld\n", ref.first, ref.first + 1, ref.second);
    }
#endif

#ifdef FLOW_LENGTH_CHECK
    LOG("Flow sequence length statistic.");
    vector<size_t> length_vec;
    for (const auto p_rep: *p_construct_result4) {
        length_vec.push_back(p_rep->get_p_packet_p_seq()->size());
    }
    for (const auto p_rep: *p_construct_result6) {
        length_vec.push_back(p_rep->get_p_packet_p_seq()->size());
    }
    map<size_t, size_t> len_stat;
    for(const auto v : length_vec) {
        const auto index = ceil(log2(v));
        if (len_stat.find(index) == len_stat.end()) {
            len_stat.insert({index, 1});
        } else {
            ++ len_stat[index];
        }
    }
    for (const auto & ref: len_stat) {
        printf("[%8ld - %8ld]: %6ld\n", (size_t)(1 << ref.first), (size_t)(1 << (ref.first + 1)), ref.second);
    }
#endif

#ifdef FLOW_BYTE_CHECK
    LOG("Flow sequence byte statistic.");
    vector<size_t> byte_vec;
    for (const auto p_rep: *p_construct_result4) {
        const auto p_seq = p_rep->get_p_packet_p_seq();
        byte_vec.push_back(
            accumulate(p_seq->begin(), p_seq->end(), 0, [] (size_t a, const decltype(p_seq->at(0)) & b) {
                return a + static_cast<size_t>(b->len);})
        );
    }
    for (const auto p_rep: *p_construct_result6) {
        const auto p_seq = p_rep->get_p_packet_p_seq();
        byte_vec.push_back(
            accumulate(p_seq->begin(), p_seq->end(), 0, [] (size_t a, const decltype(p_seq->at(0)) & b) {
                return a + static_cast<size_t>(b->len);})
        );
    }
    map<size_t, size_t> byte_stat;
    for(const auto v : byte_vec) {
        const auto index = ceil(log2(v));
        if (byte_stat.find(index) == byte_stat.end()) {
            byte_stat.insert({index, 1});
        } else {
            ++ byte_stat[index];
        }
    }
    for (const auto & ref: byte_stat) {
        printf("[%10ld - %10ld]: %10ld\n", ((u_int64_t) 0x1) << ref.first, ((u_int64_t) 0x1) << (ref.first + 1), ref.second);
    }
#endif

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}


void explicit_flow_constructor::configure_via_json(const json & jin) {
    try {
        if (jin.count("flow_time_out")) {
            FLOW_TIME_OUT = static_cast<decltype(FLOW_TIME_OUT)>(jin["flow_time_out"]);
            if (FLOW_TIME_OUT < EPS) {
                FATAL_ERROR("Invalid configuration for flow time out.");
            }
        }
        if (jin.count("evict_flow_time_out")) {
            EVICT_FLOW_TIME_OUT = static_cast<decltype(EVICT_FLOW_TIME_OUT)>(jin["evict_flow_time_out"]);
            if (EVICT_FLOW_TIME_OUT < EPS) {
                FATAL_ERROR("Invalid configuration for evicting timeout flow.");
            }
        }
    } catch (const exception & e) {
        WARN(e.what());
    }
}


void explicit_flow_constructor::config_via_json(const json & jin) {
    try {
        if (jin.count("flow_time_out")) {
            FLOW_TIME_OUT = static_cast<decltype(FLOW_TIME_OUT)>(jin["flow_time_out"]);
            if (fabs(FLOW_TIME_OUT) < EPS) {
                FATAL_ERROR("Invalid configuration for flow time out.");
            }
        }
        if (jin.count("evict_flow_time_out")) {
            EVICT_FLOW_TIME_OUT = static_cast<decltype(EVICT_FLOW_TIME_OUT)>(jin["evict_flow_time_out"]);
            if (fabs(EVICT_FLOW_TIME_OUT) < EPS) {
                FATAL_ERROR("Invalid configuration for flow eviviting interval.");
            }
        }
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }
}
