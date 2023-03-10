#include "graph_define.hpp"


using namespace Hypervision;


auto traffic_graph::_proc_each_component(const vector<addr_t> & addr_ls) -> void {

    unordered_set<size_t> _long_index, _short_index;
    _acquire_edge_index(addr_ls, _long_index, _short_index);

# ifdef DISP_PROC_COMP    
    printf("Size of Components: %ld\n", addr_ls.size());
    printf("Number of edge: %6ld, [long: %5ld / short: %5ld]\n", 
    _long_index.size() + _short_index.size(), 
    _long_index.size(), _short_index.size());
#endif
    
#ifdef CLUSTERING_SHORT
    if (_short_index.size() >= 1) {
        arma::mat centroids_short;
        arma::mat dataset_short;
        arma::Row<size_t> assignments_short;
        if (_pre_process_short(_short_index, dataset_short, centroids_short, assignments_short) >= 1) {
            _process_short(_short_index, dataset_short, centroids_short, assignments_short);
        }
    }
#endif

#ifdef CLUSTERING_LONG
    if (_long_index.size() >= 1) {
        arma::mat centroids_long;
        arma::Row<size_t> assignments_long;
        if (_pre_process_long(_long_index, centroids_long, assignments_long) >= 1) {
            _process_long(_long_index, centroids_long, assignments_long);
        }
    }
#endif

}


auto traffic_graph::proc_components(const shared_ptr<component> p_com) -> void {
    __START_FTIMMER__

    const auto p_select = component_select(p_com);
    for (const auto index: *p_select) {
        _proc_each_component(p_com->at(index));
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}
