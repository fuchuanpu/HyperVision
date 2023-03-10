cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(graph_analysis)
set(CMAKE_CXX_STANDARD 14)

add_compile_options(-fopenmp)

aux_source_directory(. DIR_LIB_SRCS)
add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX)
endif()

target_link_libraries(${PROJECT_NAME}
    armadillo
    mlpack
)

target_link_libraries(${PROJECT_NAME} z3)
