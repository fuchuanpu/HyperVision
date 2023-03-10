#include "edge_define.hpp"


using namespace Hypervision;


const auto __get4_tuple = [] (shared_ptr<basic_flow> pf, 
    string & saddr, string & daddr, pkt_port_t & sp, pkt_port_t & dp) -> void {
    if (typeid(*pf) == typeid(tuple5_flow4)) {
        const auto p4 = dynamic_pointer_cast<tuple5_flow4>(pf);
        saddr = get_str_addr(tuple_get_src_addr(p4->flow_id));
        daddr = get_str_addr(tuple_get_dst_addr(p4->flow_id));
        sp = tuple_get_src_port(p4->flow_id);
        dp = tuple_get_dst_port(p4->flow_id);
    } else {
        const auto p6 = dynamic_pointer_cast<tuple5_flow6>(pf);
        saddr = get_str_addr(tuple_get_src_addr(p6->flow_id));
        daddr = get_str_addr(tuple_get_dst_addr(p6->flow_id));
        sp = tuple_get_src_port(p6->flow_id);
        dp = tuple_get_dst_port(p6->flow_id);
#ifdef REDUCE_IPv6_ADDR_LEN
        if (saddr.size() > REDUCE_IPv6_ADDR_LEN) {
            saddr = saddr.substr(saddr.size() - 1 - REDUCE_IPv6_ADDR_LEN, REDUCE_IPv6_ADDR_LEN);
        }
        if (daddr.size() > REDUCE_IPv6_ADDR_LEN) {
            daddr = daddr.substr(daddr.size() - 1 - REDUCE_IPv6_ADDR_LEN, REDUCE_IPv6_ADDR_LEN);
        }
#endif
    }
};


void long_edge::show_edge(void) const {
    
    double_t start_tm = p_flow->get_str_time(), end_tm = p_flow->get_end_time();
    string saddr, daddr;
    pkt_port_t sp, dp;
    size_t flow_len = p_flow->get_p_packet_p_seq()->size();

    pkt_code_t flow_content = 0;
    for (const auto & ref: * p_type_distribution) {
        flow_content |= ref.first;
    }
    ostringstream oss;
    for (u_int8_t i = pkt_type_t::ICMP; i < pkt_type_t::UNKNOWN; ++i) {
        if (test_pkt_type_code(flow_content, (pkt_type_t) i)) {
            oss << type2name[i] << ' ';
        }
    }
    string type_str = oss.str();
    
    __get4_tuple(p_flow, saddr, daddr, sp, dp);

    printf("[%15s:%-6d -> %15s:%-6d] => [%7ld Packets] [%6.3lfs FCT] [%s].\n",
        saddr.c_str(), sp, daddr.c_str(), dp, flow_len, end_tm - start_tm, type_str.c_str());
}


auto long_edge::get_src_str() const -> string {
    if (typeid(*p_flow) == typeid(tuple5_flow4)) {
        const auto pf4 = dynamic_pointer_cast<tuple5_flow4>(p_flow);
        return get_str_addr(tuple_get_src_addr(pf4->flow_id));
    } else {
        const auto pf6 = dynamic_pointer_cast<tuple5_flow6>(p_flow);
        return get_str_addr(tuple_get_src_addr(pf6->flow_id));
    }
}


auto long_edge::get_dst_str() const -> string {
    if (typeid(*p_flow) == typeid(tuple5_flow4)) {
        const auto pf4 = dynamic_pointer_cast<tuple5_flow4>(p_flow);
        return get_str_addr(tuple_get_dst_addr(pf4->flow_id));
    } else {
        const auto pf6 = dynamic_pointer_cast<tuple5_flow6>(p_flow);
        return get_str_addr(tuple_get_dst_addr(pf6->flow_id));
    }
}


auto long_edge::is_huge_flow() const -> bool {
    size_t ctr = 0, byte_ctr = 0;
    for(const auto & ref: * p_length_distribution) {
        ctr += ref.second;
        byte_ctr += ref.second * ref.first;
    }
    if (ctr > huge_flow_count_line || byte_ctr > huge_flow_byte_line)
        return true;
    else
        return false;
}


auto long_edge::get_avg_packet_rate() const -> bool {
    double_t sum_time = 0;
    for (const auto ref: *p_time_distribution) {
        sum_time += 1e-3 * ref.first * ref.second;
    }
    size_t sum_pkt = 0;
    for (const auto ref: *p_length_distribution) {
        sum_pkt += ref.second;
    }
    return sum_time / sum_pkt;
}


auto long_edge::is_pulse_flow() const -> bool {
    if (get_avg_packet_rate() > pulse_flow_time_line || 
        p_length_distribution->size() < pulse_flow_ctr_line) {
        return true;
    } else {
        return false;
    }
}


auto long_edge::is_invalid_flow() const -> bool {
    auto _get = [&] (pkt_type_t t) -> size_t {
        size_t sum = 0;
        for (const auto ref: * p_type_distribution) {
            if (test_pkt_type_code(ref.first, t)) {
                sum += ref.second;
            }
        }
        return sum;
    };

    if (_get(TCP_SYN) > invalid_packet_line || 
        _get(TCP_FIN) > invalid_packet_line || 
        _get(TCP_RST) > invalid_packet_line) {
            return true;
    }
    return false;
}



void short_edge::show_edge(size_t max_show) const {
    
    auto __get_agg_str = [] (const agg_code _ac) -> const string {
        ostringstream oss;
        for (size_t i = 0; i < 5; i ++)
            if ((_ac >> i) & 0x1) {
                oss << agg2name[i] << ' ';
            }
        return oss.str();
    };


    auto __get_type_str = [&] (const shared_ptr<basic_flow> p_f) -> const string {
        u_int16_t type_code = 0;
        const auto p_pkt_seq = p_f->get_p_packet_p_seq();
        ostringstream oss;
        for (const auto p: * p_pkt_seq) {
            for (u_int8_t i = pkt_type_t::ICMP; i < pkt_type_t::UNKNOWN; ++i) {
                if (test_pkt_type_code(p->tp, (pkt_type_t) i)) {
                    oss << type2name[i] << ' ';
                    break;
                }
            }
        }
        return oss.str();
    };
    
    string saddr, daddr;
    pkt_port_t sp, dp;
    __get4_tuple(p_flow->at(0), saddr, daddr, sp, dp);

    const agg_code agg_idx = get_agg_code();
    const string agg_str = __get_agg_str(agg_idx);
    const string pkt_seq_str = __get_type_str(p_flow->at(0));
    const size_t seq_len = p_flow->at(0)->get_p_packet_p_seq()->size();

    u_int32_t num_len = 0;

    string str_saddr = "---", str_daddr = "---", str_sp = "-", str_dp = "-";
    string str_agg = __get_agg_str(agg_idx), str_type = __get_type_str(p_flow->at(0));
    shared_ptr<vector<string> > p_ls_saddr, p_ls_daddr;
    shared_ptr<vector<pkt_port_t> > p_ls_sp, p_ls_dp;
    vector<string> ls_sp, ls_dp;
    p_ls_saddr = make_shared<vector<string> >();
    p_ls_daddr = make_shared<vector<string> >();

    if (is_no_agg(agg_idx)) {
        str_saddr = saddr;
        str_daddr = daddr;
    } else {
        if (is_src_agg(agg_idx)) {
            str_saddr = saddr;
        } else {
            p_ls_saddr = get_src_list();
        }

        if (is_dst_agg(agg_idx)) {
            str_daddr = daddr;
        } else {
            p_ls_daddr = get_dst_list();
        }
    }

    if (is_no_agg(agg_idx)) {
        str_sp = to_string(sp);
        str_dp = to_string(dp);
    } else {
        if (is_srcp_agg(agg_idx)) {
            str_sp = to_string(sp);
        } else {
            p_ls_sp = get_srcp_list();
            transform(p_ls_sp->begin(), p_ls_sp->end(), back_inserter(ls_sp),
                                    [&](pkt_port_t t) -> string {return to_string(t);});
        }
        if (is_dstp_agg(agg_idx)) {
            str_dp = to_string(dp);
        } else {
            p_ls_dp = get_dstp_list();
            transform(p_ls_dp->begin(), p_ls_dp->end(), back_inserter(ls_dp),
                                [&](pkt_port_t t) -> string {return to_string(t);});
        }
    }

    printf("[   %15s:%-6s -> %15s:%-6s ] => Agg Type: %s.\n",
                str_saddr.c_str(), str_sp.c_str(), str_daddr.c_str(), str_dp.c_str(), str_agg.c_str());
    if (!is_no_agg(agg_idx))
        for (size_t i = 0; i < get_agg_size(); i ++) {

            str_saddr = i >= p_ls_saddr->size() ? "---" : p_ls_saddr->at(i);
            str_daddr = i >= p_ls_daddr->size() ? "---" : p_ls_daddr->at(i);
            str_sp = i >= ls_sp.size() ? "-" : ls_sp[i];
            str_dp = i >= ls_dp.size() ? "-" : ls_dp[i];

            printf("[-| %15s:%-6s -> %15s:%-6s ]",
                    str_saddr.c_str(), str_sp.c_str(), str_daddr.c_str(), str_dp.c_str());
            printf(" [%s]\n", __get_type_str(p_flow->at(i)).c_str());
            num_len ++;
            if (num_len == max_show) {
                printf("...... [%6ld lines in total]\n", 
                    max(max(p_ls_saddr->size(), p_ls_daddr->size()), max(ls_sp.size(), ls_dp.size())) );
                break;
            }
        }
    printf("[Seq. length]: %ld => [%s].\n\n", seq_len, pkt_seq_str.c_str());
}


auto short_edge::get_src_list() const -> shared_ptr<vector<string> > {
    if (is_dst_agg(agg_indicator)) {
        const auto _ret = make_shared<vector<string> >();
        if (typeid(*p_flow->at(0)) == typeid(tuple5_flow4)) {
            for (const auto pf: *p_flow) {
                const auto p4 = dynamic_pointer_cast<tuple5_flow4>(pf);
                _ret->push_back(get_str_addr(tuple_get_src_addr(p4->flow_id)));
            }
        } else {
            for (const auto pf: *p_flow) {
                const auto p6 = dynamic_pointer_cast<tuple5_flow6>(pf);
                string _addr = get_str_addr(tuple_get_src_addr(p6->flow_id));
#ifdef REDUCE_IPv6_ADDR_LEN
                if (_addr.size() > REDUCE_IPv6_ADDR_LEN) {
                    _addr = _addr.substr(_addr.size() - 1 - REDUCE_IPv6_ADDR_LEN, REDUCE_IPv6_ADDR_LEN);
                }
#endif
                _ret->push_back(_addr);
            }
        }
        return _ret;
    } else {
        WARN("Get short edge src list without approperate aggregation.");
        return nullptr;
    }
}

auto short_edge::get_dst_list() const -> shared_ptr<vector<string> > {
    if (is_src_agg(agg_indicator)) {
        const auto _ret = make_shared<vector<string> >();
        if (typeid(*p_flow->at(0)) == typeid(tuple5_flow4)) {
            for (const auto pf: *p_flow) {
                const auto p4 = dynamic_pointer_cast<tuple5_flow4>(pf);
                _ret->push_back(get_str_addr(tuple_get_dst_addr(p4->flow_id)));
            }
        } else {
            for (const auto pf: *p_flow) {
                const auto p6 = dynamic_pointer_cast<tuple5_flow6>(pf);
                string _addr = get_str_addr(tuple_get_dst_addr(p6->flow_id));
#ifdef REDUCE_IPv6_ADDR_LEN
                if (_addr.size() > REDUCE_IPv6_ADDR_LEN) {
                    _addr = _addr.substr(_addr.size() - 1 - REDUCE_IPv6_ADDR_LEN, REDUCE_IPv6_ADDR_LEN);
                }
#endif
                _ret->push_back(_addr);
            }
        }
        return _ret;
    } else {
        WARN("Get short edge dst list without approperate aggregation.");
        return nullptr;
    }
}

auto short_edge::get_dstp_list() const -> shared_ptr<vector<pkt_port_t> > {

    if (is_dstp_agg(agg_indicator)) {
        WARN("Get short edge dst port list with aggregation.");
        return nullptr;
    }

    const auto _ret = make_shared<vector<pkt_port_t> >();
    if (typeid(*p_flow->at(0)) == typeid(tuple5_flow4)) {
        for (const auto pf: *p_flow) {
            const auto p4 = dynamic_pointer_cast<tuple5_flow4>(pf);
            _ret->push_back(tuple_get_dst_port(p4->flow_id));
        }
    } else {
        for (const auto pf: *p_flow) {
            const auto p6 = dynamic_pointer_cast<tuple5_flow6>(pf);
            _ret->push_back(tuple_get_dst_port(p6->flow_id));
        }
    }
    return _ret;
}

auto short_edge::get_srcp_list() const -> shared_ptr<vector<pkt_port_t> > {

    if (is_srcp_agg(agg_indicator)) {
        WARN("Get short edge src port list with aggregation.");
        return nullptr;
    }

    const auto _ret = make_shared<vector<pkt_port_t> >();
    if (typeid(*p_flow->at(0)) == typeid(tuple5_flow4)) {
        for (const auto pf: *p_flow) {
            const auto p4 = dynamic_pointer_cast<tuple5_flow4>(pf);
            _ret->push_back(tuple_get_src_port(p4->flow_id));
        }
    } else {
        for (const auto pf: *p_flow) {
            const auto p6 = dynamic_pointer_cast<tuple5_flow6>(pf);
            _ret->push_back(tuple_get_src_port(p6->flow_id));
        }
    }
    return _ret;
}


auto short_edge::get_time_range(void) const -> pair<flow_time_t, flow_time_t> {
    flow_time_t str = numeric_limits<flow_time_t>::max();
    flow_time_t end = numeric_limits<flow_time_t>::min();
    for (const auto pf: *p_flow) {
        str = min(str, pf->get_str_time());
        end = max(end, pf->get_end_time());
    }
    return {str, end};
}


auto short_edge::get_src_str(void) const -> string {
    const auto p_f = p_flow->at(0);
    if (typeid(*p_f) == typeid(tuple5_flow4)) {
        const auto pf4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
        return get_str_addr(tuple_get_src_addr(pf4->flow_id));
    } else {
        const auto pf6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
        return get_str_addr(tuple_get_src_addr(pf6->flow_id));
    }
}


auto short_edge::get_dst_str(void) const -> string {
    const auto p_f = p_flow->at(0);
    if (typeid(*p_f) == typeid(tuple5_flow4)) {
        const auto pf4 = dynamic_pointer_cast<tuple5_flow4>(p_f);
        return get_str_addr(tuple_get_dst_addr(pf4->flow_id));
    } else {
        const auto pf6 = dynamic_pointer_cast<tuple5_flow6>(p_f);
        return get_str_addr(tuple_get_dst_addr(pf6->flow_id));
    }
}

