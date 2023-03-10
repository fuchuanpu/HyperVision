cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(HyperVision)
set(CMAKE_CXX_STANDARD 14)

add_subdirectory(flow_construct)
add_subdirectory(dataset_construct)
add_subdirectory(packet_parse)
add_subdirectory(graph_analyze)

aux_source_directory(. DIR_SRCS)
add_executable(${PROJECT_NAME} "${DIR_SRCS}")

target_link_libraries(${PROJECT_NAME} gflags)
target_link_libraries(${PROJECT_NAME} graph_analysis)
target_link_libraries(${PROJECT_NAME} flow_construct)
target_link_libraries(${PROJECT_NAME} dataset_construct)
target_link_libraries(${PROJECT_NAME} packet_parse)
