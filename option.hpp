#pragma once


#define DEBUG_HYPERVISION
#ifdef DEBUG_HYPERVISION
    #define REDUCE_IPv6_ADDR_LEN 14
    // #define DUMP_DEGREE

    // #define DISP_COMPONENT_STA
    // #define DISP_COMPONENT_DEGREE
    // #define DISP_SELECTED_COMPONENT_STA

    #define ADD_GLOBAL_SHORT_CLUSTER

    // #define DISP_PROC_COMP
    // #define DISP_PRE_CLUSTER_LONG
    // #define DISP_PRE_CLUSTER_SHORT

    #define CLUSTERING_LONG
    #define CLUSTERING_SHORT
    #if defined(CLUSTERING_LONG)
        // #define LONG_CRITICAL_RESULT_PRINT
        // #define LONG_RESULT_PRINT
    #endif
    #if defined(CLUSTERING_SHORT)
        // #define SHORT_RESULT_PRINT
    #endif

#endif