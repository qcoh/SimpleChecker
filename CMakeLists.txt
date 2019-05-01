cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(llvm_static_analyzer)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
message(STATUS "Use LLVM includes from ${LLVM_INCLUDE_DIRS}")

add_definitions(${LLVM_DEFINITIONS})
message(STATUS "Use LLVM definitions ${LLVM_DEFINITIONS}")

add_library(llvm_static_analyzer SHARED
	llvm_static_analyzer.cpp
)

target_link_libraries(llvm_static_analyzer PRIVATE
	LLVM
)

# this shit doesnt work
#add_llvm_library(llvm_static_analyzer MODULE
#       llvm_static_analyzer.cpp
#      
#       PLUGIN_TOOL
#       clang
#)
