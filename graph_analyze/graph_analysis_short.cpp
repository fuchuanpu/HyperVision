#include "graph_define.hpp"


using namespace Hypervision;


void traffic_graph::_process_short(const unordered_set<size_t> & _short_index, const arma::mat & dataset_short,
                                   const arma::mat & centroids_short, const arma::Row<size_t> & assignments_short) {

    if (centroids_short.size() == 0) {
        FATAL_ERROR("The cluster center for short edge is zero.");
    }

    const auto __f_get_inout_degree2 = [&] (const addr_t addr) -> pair<size_t, size_t> {
        size_t in_degree_ctr = 0, out_degree_ctr = 0;
        if (short_edge_out.count(addr)) {
            out_degree_ctr += short_edge_out.at(addr).size();
        }
        if (short_edge_in.count(addr)) {
            in_degree_ctr += short_edge_in.at(addr).size();
        }
        if (short_edge_out_agg.count(addr)) {
            for (const auto index: short_edge_out_agg.at(addr)) {
                assert(is_src_agg(p_short_edge->at(index)->get_agg_code()));
                out_degree_ctr += p_short_edge->at(index)->get_agg_size();
            }
        }
        if (short_edge_in_agg.count(addr)) {
            for (const auto index: short_edge_in_agg.at(addr)) {
                assert(is_dst_agg(p_short_edge->at(index)->get_agg_code()));
                in_degree_ctr += p_short_edge->at(index)->get_agg_size();
            }
        }
        return {in_degree_ctr, out_degree_ctr};
    };

    unordered_map<size_t, size_t> __short_clustering_size;
    for (const auto v : assignments_short) {
        if (__short_clustering_size.count(v)) {
            __short_clustering_size[v] ++;
        } else {
            __short_clustering_size.insert({v, 1});
        }
    }

    vector<size_t> index_short_remap(_short_index.cbegin(), _short_index.cend());
    assert(index_short_remap.size() == assignments_short.size());
    unordered_map<size_t, vector<size_t> > __short_clustering_id_vec;
    for (size_t i = 0; i < assignments_short.size(); i ++) {
        if (__short_clustering_id_vec.count(assignments_short[i])) {
            __short_clustering_id_vec[assignments_short[i]].push_back(index_short_remap[i]);
        } else {
            __short_clustering_id_vec.insert({assignments_short[i], {index_short_remap[i]}});
        }
    }

    vector<size_t> short_origin_index;
    vector<vector<size_t> > short_origin_index_vec;

    vector<size_t> short_clustering_size;
    vector<size_t> short_aggregate_size;
    vector<double_t> short_time_range;
    vector<double_t> short_cluster_time_range;

    unordered_set<size_t> has_counted;

    const auto __get_time_indicator = [&] (size_t index) -> double_t {
        auto original_index = index_short_remap[index];
        const auto _range = p_short_edge->at(original_index)->get_time_range();
        const auto _agg = p_short_edge->at(original_index)->get_agg_code();
        if (is_no_agg(_agg))
            return 0;
        else
            return _range.second - _range.first;
    };

    for (size_t i = 0; i < assignments_short.size();  i ++ ) {
    
        if (assignments_short[i] == SIZE_MAX) {
            if (p_short_edge->at(index_short_remap[i])->get_agg_code() == NO_AGG) {
                continue;
            } else {
                short_clustering_size.push_back(1);
                short_origin_index_vec.push_back({index_short_remap[i]});
                short_origin_index.push_back(index_short_remap[i]);
                short_time_range.push_back(__get_time_indicator(i));
                short_aggregate_size.push_back(p_short_edge->at(index_short_remap[i])->get_agg_size());
                continue;
            }
        }
        if (!has_counted.count(assignments_short[i])) {
            short_clustering_size.push_back(__short_clustering_size[assignments_short[i]]);
            short_origin_index_vec.push_back(__short_clustering_id_vec[assignments_short[i]]);
            short_origin_index.push_back(index_short_remap[i]);
            short_time_range.push_back(__get_time_indicator(i));
            short_aggregate_size.push_back(p_short_edge->at(index_short_remap[i])->get_agg_size());
            has_counted.insert(assignments_short[i]);
        }
    }

    // Get the aggregated edge time loss.
    unordered_set<addr_t> addr_set;
    for (size_t i : short_origin_index) {
        const auto pe = p_short_edge->at(i);
        const auto _agg = pe->get_agg_code();
        if (is_src_agg(_agg)) {
            addr_set.insert(pe->get_src_str());
        }
        if (is_dst_agg(_agg)) {
            addr_set.insert(pe->get_dst_str());
        }
    }
    unordered_map<addr_t, pair<double_t, double_t>> addr_tim_mp;
    for (const auto a : addr_set) {
        addr_tim_mp.insert({a, {HUG, 0}});
    }
    for (size_t i : short_origin_index) {
        const auto pe = p_short_edge->at(i);
        const auto _agg = pe->get_agg_code();
        const auto _range = pe->get_time_range();
        const auto src = pe->get_src_str();
        const auto dst = pe->get_dst_str();
        if (is_src_agg(_agg)) {
            addr_tim_mp[src].first = min(addr_tim_mp[src].first, _range.first);
            addr_tim_mp[src].second = max(addr_tim_mp[src].second, _range.second);
        }
        if (is_dst_agg(_agg)) {
            addr_tim_mp[dst].first = min(addr_tim_mp[dst].first, _range.first);
            addr_tim_mp[dst].second = max(addr_tim_mp[dst].second, _range.second);
        }
    }

    for (size_t i = 0; i < short_clustering_size.size(); i ++) {
        double_t res = 0;
        assert(short_origin_index_vec[i].size() == short_clustering_size[i]);
        if (short_clustering_size[i] > 1) {
            double_t mx = 0, mi = HUG;
            for (const auto index: short_origin_index_vec[i]) {
                const auto pe = p_short_edge->at(index);
                mi = min(mi, pe->get_time());
                mx = max(mx, pe->get_time());
            }
            res = mx - mi;
        } else {
            const auto _range = p_short_edge->at(short_origin_index_vec[i][0])->get_time_range();
            res = _range.second - _range.first;
        }
        short_cluster_time_range.push_back(res);
    }

    vector<feature_t> _short_feature;
    for (const auto index: short_origin_index) {
        _short_feature.push_back(_f_exeract_feature_short2(index));
    }

    arma::mat __short_data;
    __short_data = __f_trans_armadillo_mat_T(_short_feature);
    mlpack::data::MinMaxScaler __scale_short;
    __scale_short.Fit(__short_data);
    decltype(__short_data) __long_pre_norm_feature = __short_data;
    __scale_short.Transform(__long_pre_norm_feature, __short_data);

    arma::mat centroids_short2;
    arma::Row<size_t> assignments_short2;
    mlpack::kmeans::KMeans<> k_short2;
    k_short2.Cluster(__short_data, val_K, assignments_short2, centroids_short2);

    const auto __get_loss = [&] (const decltype(__short_data.col(0)) & _vec) -> double {
        double_t res = HUG;
        mlpack::metric::EuclideanDistance euclidean_eval;
        for (size_t i = 0; i < centroids_short2.n_cols; i ++) {
            res = min(res, euclidean_eval.Evaluate(centroids_short2.col(i), _vec) );
        }
        return res;
    };

    vector<double_t> loss_raw_vec;
    for (size_t i = 0; i < __short_data.n_cols; i ++) {
        loss_raw_vec.push_back(__get_loss(__short_data.col(i)));
    }

    vector<double_t> loss_short_vec;
    for(size_t i = 0; i < __short_data.n_cols; i ++ ) {
        loss_short_vec.push_back(
            as * loss_raw_vec[i]
            + bs * log2(short_aggregate_size[i] * short_clustering_size[i] + 1) 
            - cs * short_cluster_time_range[i]
        );
    }

#ifdef SHORT_RESULT_PRINT
    vector<pair<size_t, double> > res_mp;
    assert(short_origin_index.size() == loss_short_vec.size());
    for (size_t i = 0; i < loss_short_vec.size(); i ++) {
        res_mp.push_back({i, loss_short_vec[i]});
    }
    assert(res_mp.size() == loss_short_vec.size());
    sort(res_mp.begin(), res_mp.end(), 
        [] (decltype(res_mp[0]) a, decltype(res_mp[0]) b) -> bool {
        return a.second < b.second;
    });

    for (const auto & ref: res_mp) {
        printf("[Short Edge Overall Loss: %lf]: Clustering Loss: %lf, Clustering Size: %ld, Aggregation size: %ld, Time Range: %lf.\n",
            ref.second, 
            loss_raw_vec[ref.first], 
            short_clustering_size[ref.first], 
            short_aggregate_size[ref.first], 
            short_cluster_time_range[ref.first]);
        p_short_edge->at(short_origin_index[ref.first])->show_edge();
        cout << endl;
    }
#endif

    vector<double_t> & _vec_score_short = * p_short_edge_score;
    for (size_t i = 0; i < __short_data.n_cols; i ++ ) {
        for (const auto j: short_origin_index_vec[i]) {
            _vec_score_short[j] = loss_short_vec[i];
        }
    }

}

