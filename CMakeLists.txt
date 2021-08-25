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
execute_process(COMMAND /usr/bin/bash -c "clang -Wp,-v -x c - -fsyntax-only < /dev/null 2>&1 | grep /clang/" OUTPUT_VARIABLE CLANG_INTERNAL_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE " " "" CLANG_INTERNAL_INCLUDE_DIR "${CLANG_INTERNAL_INCLUDE_DIR}")
message(STATUS "CLANG_INTERNAL_INCLUDE_DIR: ${CLANG_INTERNAL_INCLUDE_DIR}")
enable_testing()

add_llvm_library(SimpleErrorChecker MODULE SimpleErrorChecker.cpp PLUGIN_TOOL clang)

if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  target_link_libraries(AllocFreePlugin PRIVATE
    clangAnalysis
    clangAST
    clangStaticAnalyzerCore
    LLVMSupport
    )
endif()

set(tests
  diffFnOutParam_false
  diffFnOutParam_true
  diffFnReturn_false
  diffFnReturn_true
  sameFn_false
  sameFnIf_false
  sameFnIf_true
  sameFn_true
)

foreach(_test ${tests})
    add_test(NAME check-${_test}
    COMMAND
        ${LLVM_TOOLS_BINARY_DIR}/clang -cc1 -analyze
        -load $<TARGET_FILE:SimpleErrorChecker>
        -analyzer-checker=example.ErrorChecker
        -internal-externc-isystem /include -internal-externc-isystem /usr/include
        -internal-isystem ${CLANG_INTERNAL_INCLUDE_DIR}
        -verify ${CMAKE_CURRENT_SOURCE_DIR}/test/${_test}.c
    )
endforeach()

#add_custom_target(check-SimpleErrorChecker)
#foreach(_test ${tests})
#  add_custom_target(check-${_test}
#    COMMAND
#        ${LLVM_TOOLS_BINARY_DIR}/clang -cc1 -analyze
#        -load $<TARGET_FILE:SimpleErrorChecker>
#        -analyzer-checker=example.ErrorChecker
#        -internal-externc-isystem /include -internal-externc-isystem /usr/include
#        -internal-isystem ${CLANG_INTERNAL_INCLUDE_DIR}
#        -verify ${CMAKE_CURRENT_SOURCE_DIR}/test/${_test}.c
#        DEPENDS SimpleErrorChecker
#    )
#add_dependencies(check-SimpleErrorChecker check-${_test})
#endforeach()
#add_custom_target(check DEPENDS check-SimpleErrorChecker)
