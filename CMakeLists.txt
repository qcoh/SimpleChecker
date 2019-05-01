cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(autosar_checker)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
message(STATUS "Use LLVM includes from ${LLVM_INCLUDE_DIRS}")

add_definitions(${LLVM_DEFINITIONS})
message(STATUS "Use LLVM definitions ${LLVM_DEFINITIONS}")

add_library(autosar_checker SHARED
	StaticNonPODChecker.cpp
)

target_link_libraries(autosar_checker PRIVATE
	LLVM
)
