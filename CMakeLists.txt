cmake_minimum_required(VERSION 3.4.3)

project(GBRStaticAnalyzers CXX)

find_package(LLVM REQUIRED CONFIG)
set(CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_CMAKE_DIR}")
include(AddLLVM)

find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
message(STATUS "LLVM_DEFINITIONS:   ${LLVM_DEFINITIONS}")
message(STATUS "LLVM_INCLUDE_DIRS:  ${LLVM_INCLUDE_DIRS}")
message(STATUS "CLANG_INCLUDE_DIRS: ${CLANG_INCLUDE_DIRS}")

add_llvm_library(SimpleErrorChecker MODULE SimpleErrorChecker.cpp PLUGIN_TOOL clang)

if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  target_link_libraries(AllocFreePlugin PRIVATE
    clangAnalysis
    clangAST
    clangStaticAnalyzerCore
    LLVMSupport
    )
endif()

#set(tests
#  alloc-free-checker
#  glib-array
#  glib-byte-array
#  glib-ptr-array
#  wireshark-tvb
#  wmem-alloc
#  wmem-scope
#)

#add_custom_target(check-AllocFreePlugin)
#foreach(_test ${tests})
#  add_custom_target(check-${_test}
#    COMMAND
#        ${LLVM_TOOLS_BINARY_DIR}/clang -cc1 -analyze
#        -load $<TARGET_FILE:AllocFreePlugin>
#        -analyzer-checker=core,alpha.AllocFree
#        -verify ${CMAKE_CURRENT_SOURCE_DIR}/test/Analysis/${_test}.c
#    DEPENDS AllocFreePlugin
#    )
#  add_dependencies(check-AllocFreePlugin check-${_test})
#endforeach()
#add_custom_target(check DEPENDS check-AllocFreePlugin)
