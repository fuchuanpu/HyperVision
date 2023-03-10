#include "graph_define.hpp"


using namespace Hypervision;


void traffic_graph::_process_long(const unordered_set<size_t> & _long_index,
                                const arma::mat & centroids_long, const arma::Row<size_t> & assignments_long) {

    if (centroids_long.size() == 0) {
        FATAL_ERROR("The cluster center for long edge is zero.");
    }

    vector<size_t> index_long_remap(_long_index.cbegin(), _long_index.cend());

    unordered_map<size_t, size_t> __long_clustering_size;
    unordered_map<size_t, double_t> __long_clustering_str;
    unordered_map<size_t, double_t> __long_clustering_stp;
    unordered_map<size_t, vector<size_t> > __long_clustering_index;
    for (size_t i = 0; i < assignments_long.size(); i ++) {
        const auto v = assignments_long[i];
        const auto _range = p_long_edge->at(index_long_remap[i])->get_time_range();
        if (__long_clustering_size.count(v)) {
            __long_clustering_size[v] ++;
            __long_clustering_index[v].push_back(index_long_remap[i]);

            __long_clustering_str[v] = min(__long_clustering_str[v], _range.first);
            __long_clustering_stp[v] = max(__long_clustering_stp[v], _range.second);
        } else {
            __long_clustering_size.insert({v, 1});
            __long_clustering_index.insert({v, {index_long_remap[i]}});

            __long_clustering_str.insert({v, _range.first});
            __long_clustering_stp.insert({v, _range.second});
        }
    }

    vector<size_t> long_origin_index;
    
    vector<size_t> long_clustering_size;
    vector<vector<size_t> > long_origin_index_vec;
    vector<double_t> long_cluster_time;
    unordered_set<size_t> has_counted_long;
    unordered_map<addr_t, size_t> addr_rank_mp;
    
    for (size_t i = 0; i < assignments_long.size(); i ++ ) {

        if (assignments_long[i] == SIZE_MAX) {
            continue;
        }

        if (!has_counted_long.count(assignments_long[i])) {
            long_clustering_size.push_back(__long_clustering_size[assignments_long[i]]);
            long_origin_index.push_back(index_long_remap[i]);
            const auto pe = p_long_edge->at(index_long_remap[i]);
            const auto _src = pe->get_src_str();
            const auto _dst = pe->get_dst_str();
            if (addr_rank_mp.count(_src)) {
                addr_rank_mp[_src] ++;
            } else {
                addr_rank_mp.insert({_src, 1});
            }
            if (addr_rank_mp.count(_dst)) {
                addr_rank_mp[_dst] ++;
            } else {
                addr_rank_mp.insert({_dst, 1});
            }
            has_counted_long.insert(assignments_long[i]);
            long_cluster_time.push_back(__long_clustering_stp[assignments_long[i]] - __long_clustering_str[assignments_long[i]]);
            long_origin_index_vec.push_back(__long_clustering_index[assignments_long[i]]);
        }
    }

    vector<pair<addr_t, size_t> > _vec_addr_rank(addr_rank_mp.cbegin(), addr_rank_mp.cend());
    sort(_vec_addr_rank.begin(), _vec_addr_rank.end(), 
        [] (decltype(_vec_addr_rank)::value_type a, decltype(_vec_addr_rank)::value_type b) 
        -> bool { return a.second > b.second;});
    vector<addr_t> addr_long;
    transform(begin(_vec_addr_rank), end(_vec_addr_rank), back_inserter(addr_long), 
        [] (decltype(_vec_addr_rank)::value_type a) -> addr_t { return a.first; });

    map<addr_t, size_t> addr_long_index;
    vector<pair<addr_t, size_t> > addr_long_lst;
    for (size_t i = 0; i < addr_long.size(); i ++) {
        addr_long_index.insert({addr_long[i], i});
        addr_long_lst.push_back({addr_long[i], i});
    }
    vector<pair<size_t, size_t> > addr_index_mp;
    for (const auto index: long_origin_index) {
        const auto pe = p_long_edge->at(index);
        addr_index_mp.push_back({
            addr_long_index[pe->get_src_str()],
            addr_long_index[pe->get_dst_str()]
        });
    }

    using namespace z3;

    context c;

    expr_vector x(c);
    expr target = c.int_val(0);
    
    for (const auto & ref: addr_long_index) {
        std::stringstream _name;
        _name << "x_" << ref.second;
        expr xe = c.bool_const(_name.str().c_str());
        x.push_back(xe);
        target = target + ite(xe, c.int_val(1), c.int_val(0));
    }

    optimize opt(c);
    for (auto p: addr_index_mp) {
        opt.add(x[p.first] || x[p.second]);
    }
    optimize::handle h1 = opt.minimize(target);
    unordered_set<size_t> z3_res;
    unordered_map<addr_t, vector<size_t> > selected_long_daddr;

    if (opt.check() == sat) {

        model m = opt.get_model();
        for (size_t i = 0; i < x.size(); i ++) {
            if (m.eval(x[i])) {
                z3_res.insert(i);
            }
        }
        vector<bool> is_add(addr_index_mp.size(), false);
        for (const auto & ref: addr_long_lst) {
            if (true) {
                vector<size_t> _conn_edge;
                for (size_t i = 0; i < addr_index_mp.size(); i ++) {
                    if (!is_add[i] && 
                    (addr_index_mp[i].first == ref.second || addr_index_mp[i].second == ref.second)) {
                        _conn_edge.push_back(i);
                        is_add[i] = true;
                    }
                }
                selected_long_daddr.insert({ref.first, _conn_edge});
            }
        }
    } else {
        FATAL_ERROR("Z3 SMT unsat");
        return;
    }

    for (const auto & ref : selected_long_daddr) {

#ifdef LONG_CRITICAL_RESULT_PRINT
        printf("Critical Address: [%15s], Connected Edges: [%4ld].\n", ref.first.c_str(), ref.second.size());
        for (const auto index: ref.second) {
            p_long_edge->at(long_origin_index[index])->show_edge();
        }
#endif

        vector<feature_t> _long_feature;
        for (const auto index: ref.second) {
            _long_feature.push_back(_f_exeract_feature_long2(long_origin_index[index]));
        }

        if (_long_feature.size() == 0) {
            continue;
        }

        arma::mat __long_data;
        if (ref.second.size() >= val_K) {
            __long_data = __f_trans_armadillo_mat_T(_long_feature);
            mlpack::data::MinMaxScaler __scale_long;
            __scale_long.Fit(__long_data);
            decltype(__long_data) __long_pre_norm_feature = __long_data;
            __scale_long.Transform(__long_pre_norm_feature, __long_data);
        }

        arma::mat _centroids_long;
        arma::Row<size_t> _assignments_long;
        mlpack::kmeans::KMeans<> _k_long;

        const auto __get_loss_long = [&_centroids_long] (const decltype(__long_data.col(0)) & _vec) -> double_t {
            double_t res = 1e10;
            mlpack::metric::EuclideanDistance euclidean_eval;
            for (size_t i = 0; i < _centroids_long.n_cols; i ++) {
                res = min(res, euclidean_eval.Evaluate(_centroids_long.col(i), _vec) );
            }
            return res;
        };

        vector<double_t> _cluster_loss_2;
        if (ref.second.size() >= val_K) {
            _k_long.Cluster(__long_data, val_K, _assignments_long, _centroids_long);
            for (size_t i = 0; i < __long_data.n_cols; i ++ ) {
                _cluster_loss_2.push_back(__get_loss_long(__long_data.col(i)));
            }
        } else {
            for (size_t i = 0; i < ref.second.size(); i ++ ) {
                _cluster_loss_2.push_back(0);
            }
        }

        vector<double_t> _loss_long_vec;
        for (size_t i = 0; i < ref.second.size(); i ++) {
            _loss_long_vec.push_back(
                _cluster_loss_2[i] * al
                + log2(long_clustering_size[ref.second[i]] + 1) * bl
                - long_cluster_time[ref.second[i]] * cl);
        }

        vector<double_t> & ve_loss = *p_long_edge_score;
        for (size_t i = 0; i < ref.second.size(); i ++) {
            for (auto idx: long_origin_index_vec[ref.second[i]]) {
                ve_loss[idx] = _loss_long_vec[i];
            }
        }

#ifdef LONG_RESULT_PRINT
        vector<pair<size_t, double> > long_res_mp;
        for (size_t i = 0; i < _loss_long_vec.size(); i ++) {
            long_res_mp.push_back({i, _loss_long_vec[i]});
        }
        std::sort(long_res_mp.begin(), long_res_mp.end(), 
            [] (decltype(long_res_mp[0]) a, decltype(long_res_mp[0]) b) -> bool {
            return a.second < b.second;
        });
        for (size_t i = 0; i < long_res_mp.size(); i ++) {
            const auto index = long_res_mp[i].first;
            printf("[Long Edge Overal Loss: %6.4lf]: Clustering Loss: %6.4lf, Size: %6ld, Time: %4.2lf.\n", 
                   _loss_long_vec[index], 
                   _cluster_loss_2[index],
                   long_clustering_size[ref.second[index]], 
                   long_cluster_time[ref.second[index]]);

            p_long_edge->at(long_origin_index[ref.second[index]])->show_edge();
        }
        putchar('\n');
#endif
    }

}

