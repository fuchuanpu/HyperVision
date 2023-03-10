#pragma once

#include "../packet_parse/pcap_parser.hpp"
#include "../flow_construct/explicit_constructor.hpp"
#include "edge_constructor.hpp"
#include "graph_define.hpp"


namespace Hypervision
{


class hypervision_detector {
private:

    json jin_main;
    string file_path = "";
    
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_result;
    
    shared_ptr<binary_label_t> p_label;
    shared_ptr<vector<double_t> > p_loss;
    
    shared_ptr<vector<shared_ptr<basic_flow> > > p_flow;

    shared_ptr<vector<shared_ptr<short_edge> > > p_short_edges;
    shared_ptr<vector<shared_ptr<long_edge> > > p_long_edges;


    bool save_result_enable = false;
    string save_result_path = "../temp/default.json";

public:
    void start(void) {
        __START_FTIMMER__

        if (jin_main.count("packet_parse") &&
            jin_main["packet_parse"].count("target_file_path")) {
            
            LOGF("Parse packet from file.");
            file_path = jin_main["packet_parse"]["target_file_path"];
            const auto p_packet_parser = make_shared<pcap_parser>(file_path);
            p_packet_parser->parse_raw_packet();
            p_packet_parser->parse_basic_packet_fast();
            p_parse_result = p_packet_parser->get_basic_packet_rep();

            LOGF("Split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->do_dataset_construct();
            p_label = p_dataset_constructor->get_label();

        } else if (jin_main["dataset_construct"].count("data_path") && 
                    jin_main["dataset_construct"].count("label_path")){
            LOGF("Load & split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->import_dataset();
            p_label = p_dataset_constructor->get_label();
            p_parse_result = p_dataset_constructor->get_raw_pkt();
        } else {
            LOGF("Dataset not found.");
        }

        LOGF("Construct flow.");
        const auto p_flow_constructor = make_shared<explicit_flow_constructor>(p_parse_result);
        p_flow_constructor->config_via_json(jin_main["flow_construct"]);
        p_flow_constructor->construct_flow();
        p_flow = p_flow_constructor->get_constructed_raw_flow();

        LOGF("Construct edge.");
        const auto p_edge_constructor = make_shared<edge_constructor>(p_flow);
        p_edge_constructor->config_via_json(jin_main["edge_construct"]);
        p_edge_constructor->do_construct();
        // p_edge_constructor->dump_short_edge();
        // p_edge_constructor->dump_long_edge();
        tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

        LOGF("Construct Graph.");
        const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
        p_graph->config_via_json(jin_main["graph_analyze"]);
        p_graph->parse_edge();
        // p_graph->dump_graph_statistic();
        // p_graph->dump_edge_anomly();
        // p_graph->dump_vertex_anomly();
        p_graph->graph_detect();
        p_loss = p_graph->get_final_pkt_score(p_label);

        if (save_result_enable) {
            do_save(save_result_path);
        }

        __STOP_FTIMER__
        __PRINTF_EXE_TIME__

    }

    void config_via_json(const json & jin) {
        try {
            if (
                jin.count("dataset_construct") &&
                jin.count("flow_construct") &&
                jin.count("edge_construct") &&
                jin.count("graph_analyze") &&
                jin.count("result_save")) {
                    jin_main = jin;
                } else {
                    throw logic_error("Incomplete json configuration.");
                }
                const auto j_save = jin["result_save"];
                if (j_save.count("save_result_enable")) {
                    save_result_enable = static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
                }
                if (j_save.count("save_result_path")) {
                    save_result_path = static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
                }
        } catch (const exception & e) {
            FATAL_ERROR(e.what());
        }
    }

    void do_save(const string & save_path) {
        __START_FTIMMER__

        ofstream _f(save_path);
        if (_f.is_open()) {
            try {
                _f << setprecision(4);
                for (size_t i = 0; i < p_label->size(); ++i) {
                    _f << p_label->at(i) << ' '<< p_loss->at(i) << '\n';
                    if (i % 1000 == 0) {
                        _f << flush;
                    }
                }
            } catch(const exception & e) {
                FATAL_ERROR(e.what());
            }
            _f.close();
        } else {
            FATAL_ERROR("File Error.");
        }
        
        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }

};

}
