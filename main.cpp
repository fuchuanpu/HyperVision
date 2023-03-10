#include <gflags/gflags.h>


#include "common.hpp"
#include "./graph_analyze/detector_main.hpp"


using namespace std;


DEFINE_string(config, "../configuration/lrscan/http_lrscan.json",  "Configuration file location.");


int main(int argc, char * argv[]) {
    __START_FTIMMER__

    google::ParseCommandLineFlags(&argc, &argv, true);

    json config_j;
    try {
        ifstream fin(FLAGS_config, ios::in);
        fin >> config_j;
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }

    auto hv1 = make_shared<Hypervision::hypervision_detector>();
    hv1->config_via_json(config_j);
    hv1->start();
 
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return 0;
}
