# Static Analyzer #

I've build this to learn about LLVM's static Analyzer. This is just for learning purposes.

## Building Analyzer ##

Building as Plugin

```bash
mkdir build
cd build
cmake ..
make
```

Building in Tree

1. Copy SimpleErrorChecker.cpp to clang/lib/StaticAnalyzer/Checkers/
2. Comment Register Plugin Section out in SimpleErrorChecker and Uncomment Register in tree section
3. Add SimpleErrorChecker.cpp to the CMakeLists.txt in clang/lib/StaticAnalyzer/Checkers/
4. Add SimpleErrorChecker to llvm/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td by copying SimpleStreamCheckers entry and modifying it accordingly.
5. Build llvm

## Running this Checker ##

Can be run with any tools that allow to load llvm plugins

```bash
export MY_INCLUDES="-I/usr/local/include -I/usr/local/lib/clang/12.0.1/include -I/usr/include"
clang -cc1 ${=MY_INCLUDES} -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyze -analyzer-checker=example.ErrorChecker ~/testerror.c
```

scan-build
```bash
scan-build -load-plugin /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -enable-checker example.ErrorChecker -disable-checker unix.Malloc clang -c ~/testerror.c
```

clang with html output
```bash
/usr/local/bin/clang-12 -cc1 -triple x86_64-unknown-linux-gnu -analyze -disable-free -analyzer-store=region -analyzer-opt-analyze-nested-blocks -w -setup-static-analyzer -mrelocation-model static -mframe-pointer=all -fmath-errno -fno-rounding-math -mconstructor-aliases -munwind-tables -target-cpu x86-64 -tune-cpu generic -fno-split-dwarf-inlining -debugger-tuning=gdb -resource-dir /usr/local/lib/clang/12.0.1 -internal-isystem /usr/local/include -internal-isystem /usr/local/lib/clang/12.0.1/include -internal-externc-isystem /include -internal-externc-isystem /usr/include -fdebug-compilation-dir /home/mschroetter/project/SimpleErrorChecker/build -ferror-limit 19 -fgnuc-version=4.2.1 -analyzer-display-progress -analyzer-checker example.ErrorChecker -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyzer-output=html -faddrsig -o /tmp/scan-build -x c test/sameFnIf_true.c
```

## Debugging ##

```bash
gdb --args clang -cc1 ${=MY_INCLUDES} -analyze -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyzer-checker=example.ErrorChecker testerror.c
```

```bash
(gdb) add-symbol-file /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so
(gdb) br /home/mschroetter/project/SimpleErrorChecker/SimpleErrorChecker.cpp:251
```

### Generate exploded Graph ###

add the following flag to the clang -cc1 call:
    ```
    -analyzer-dump-egraph=FILE.dot
    ```
    
to generate good html view
```bash
exploded-graph-rewriter.py FILE.dot
```

## Running Tests ##

```bash
make test
```

## Problems ##

[See Issues](https://gitup.uni-potsdam.de/maxschro/llvm-static-analyzers/issues)
