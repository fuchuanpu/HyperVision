cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(flow_construct)
set(CMAKE_CXX_STANDARD 14)

aux_source_directory(. DIR_LIB_SRCS)
add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

target_link_libraries(${PROJECT_NAME}
    pthread
)
