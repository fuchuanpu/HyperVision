#pragma once

#include "../common.hpp"
#include "../packet_parse/pcap_parser.hpp"


namespace Hypervision
{


using binary_label_t = vector<bool>;


class basic_dataset {
private:
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_result;
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_train, p_parse_test;
    double_t train_ratio = 0.25;

    shared_ptr<binary_label_t> p_label;
    double_t attack_time_after = 0.0;
    shared_ptr<vector<string> > p_attacker_src4, p_attacker_src6;
    shared_ptr<vector<string> > p_attacker_dst4, p_attacker_dst6;
    shared_ptr<vector<pair<string, string> > > p_attacker_srcdst4, p_attacker_srcdst6;

    string export_data_path = "";
    string export_label_path = "";

    string load_data_path = "";
    string load_label_path = "";

public:
    basic_dataset() {}
    basic_dataset(const decltype(p_parse_result) & p_parse_result,
                  const double_t train_ratio=0.25, const double_t attack_time_after=0.0): 
                  p_parse_result(p_parse_result), train_ratio(train_ratio), attack_time_after(attack_time_after) {}

    void set_attacker_mach_list(const decltype(p_attacker_src4) p_attacker_src4=nullptr, 
                                const decltype(p_attacker_src6) p_attacker_src6=nullptr,
                                const decltype(p_attacker_dst4) p_attacker_dst4=nullptr,
                                const decltype(p_attacker_dst6) p_attacker_dst6=nullptr,
                                const decltype(p_attacker_srcdst4) p_attacker_srcdst4=nullptr,
                                const decltype(p_attacker_srcdst6) p_attacker_srcdst6=nullptr) {
        this->p_attacker_src4 = p_attacker_src4;
        this->p_attacker_src6 = p_attacker_src6;
        this->p_attacker_dst4 = p_attacker_dst4;
        this->p_attacker_dst6 = p_attacker_dst6;
        this->p_attacker_srcdst4 = p_attacker_srcdst4;
        this->p_attacker_srcdst6 = p_attacker_srcdst6;
    }

    void set_attacker_mach_list(const vector<string> & attacker_src4={}, 
                                const vector<string> & attacker_src6={},
                                const vector<string> & attacker_dst4={},
                                const vector<string> & attacker_dst6={},
                                const vector<pair<string, string> > & attacker_srcdst4={},
                                const vector<pair<string, string> > & attacker_srcdst6={}) {
        p_attacker_src4 = make_shared<decltype(p_attacker_src4)::element_type>
                                (attacker_src4.cbegin(), attacker_src4.cend());
        p_attacker_src6 = make_shared<decltype(p_attacker_src6)::element_type>
                                (attacker_src6.cbegin(), attacker_src6.cend());
        p_attacker_dst4 = make_shared<decltype(p_attacker_dst4)::element_type>
                                (attacker_dst4.cbegin(), attacker_dst4.cend());
        p_attacker_dst6 = make_shared<decltype(p_attacker_dst6)::element_type>
                                (attacker_dst6.cbegin(), attacker_dst6.cend());
        p_attacker_srcdst4 = make_shared<decltype(p_attacker_srcdst4)::element_type>
                                (attacker_srcdst4.cbegin(), attacker_srcdst4.cend());
        p_attacker_srcdst6 = make_shared<decltype(p_attacker_srcdst6)::element_type>
                                (attacker_srcdst6.cbegin(), attacker_srcdst6.cend());
    }

    void do_dataset_construct(size_t multiplex=64);
    void configure_via_json(const json & jin);

    inline auto get_train_test_dataset(void) const -> pair<decltype(p_parse_train), decltype(p_parse_train)> {
        return {p_parse_train, p_parse_test};
    }

    inline auto get_label(void) const -> decltype(p_label) {
        return p_label;
    }

    inline auto get_raw_pkt(void) const -> decltype(p_parse_result) {
        return p_parse_result;
    }

    void import_dataset(void) {
        __START_FTIMMER__
        ifstream _ifd(load_data_path);
        vector<string> string_temp;
        while (true) {
            string _s;
            if (getline(_ifd, _s)) {
                string_temp.push_back(_s);
            } else {
                break;
            }
        }
        _ifd.close();
        size_t num_pkt = string_temp.size();
        p_parse_result = make_shared<decltype(p_parse_result)::element_type>(num_pkt);

        const size_t multiplex_num = 64;
        const u_int32_t part_size = ceil(((double) num_pkt) / ((double) multiplex_num));
        vector<pair<size_t, size_t> > _assign;
        for (size_t core = 0, idx = 0; core < multiplex_num; ++ core, idx = min(idx + part_size, num_pkt)) {
            _assign.push_back({idx, min(idx + part_size, num_pkt)});
        }
        mutex add_m;
        auto __f = [&] (size_t _from, size_t _to) -> void {
            for (size_t i = _from; i < _to; ++ i) {
                const string & str = string_temp[i];
                if (str[0] == '4') {
                    const auto make_pkt = make_shared<basic_packet4>(str);
                    p_parse_result->at(i) = make_pkt;
                } else if (str[0] == '6') {
                    const auto make_pkt = make_shared<basic_packet6>(str);
                    p_parse_result->at(i) = make_pkt;
                } else {
                    const auto make_pkt = make_shared<basic_packet_bad>();
                    p_parse_result->at(i) = make_pkt;
                }
            }
        };

        vector<thread> vt;
        for (size_t core = 0; core < multiplex_num; ++core) {
            vt.emplace_back(__f, _assign[core].first, _assign[core].second);
        }

        for (auto & t : vt)
            t.join();


        ifstream _ifl(load_label_path);
        p_label = make_shared<decltype(p_label)::element_type>();
        string ll;
        _ifl >> ll;
        for (const char a: ll) {
            p_label->push_back(a == '1');
        }
        _ifl.close();
        assert(p_label->size() == p_parse_result->size());

        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }

};


}