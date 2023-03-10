#pragma once


#include "../common.hpp"
#include "pcpp_common.hpp"
#include "packet_basic.hpp"
#include "packet_info.hpp"


using namespace std;

namespace Hypervision {


class pcap_parser final  {
private:
    const string target_file_path;
    shared_ptr<pcpp::IPcapDevice::PcapStats> p_parse_state;
    shared_ptr<pcpp::RawPacketVector> p_raw_packet;
    shared_ptr<pcpp::PcapFileReaderDevice> p_pcpp_file_reader;
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_result;

public:
    auto parse_raw_packet(size_t num_to_parse=-1) -> decltype(p_raw_packet);
    auto parse_basic_packet_fast(size_t multiplex=16) -> decltype(p_parse_result);
    void type_statistic(void) const;

    pcap_parser(const pcap_parser &) = delete;
    pcap_parser & operator=(const pcap_parser &) = delete;
    virtual ~pcap_parser() {}

    explicit pcap_parser(const string & s): target_file_path(s) {
        p_pcpp_file_reader = make_shared<pcpp::PcapFileReaderDevice>(s.c_str());
        if (!p_pcpp_file_reader->open()) {
            FATAL_ERROR("Fail to read traget traffic file.");
        }
        p_parse_result = nullptr;
        p_raw_packet = nullptr;
        p_parse_state = make_shared<pcpp::IPcapDevice::PcapStats>();
    }

    auto inline get_raw_packet_vector() const -> const decltype(p_raw_packet) {
        if (p_raw_packet) {
            return p_raw_packet;
        } else {
            WARN("Raw packet vector acquired without initialization.");
            return nullptr;
        }
    }

    auto inline get_basic_packet_rep() const -> const decltype(p_parse_result) {
        if (p_parse_result) {
            return p_parse_result;
        } else {
            WARN("Void parse results returned.");
            return nullptr;
        }
    }

    auto inline get_parse_state() -> const decltype(p_parse_state) {
        p_pcpp_file_reader->getStatistics(*p_parse_state);
        return p_parse_state;
    }
};

}