# Static Analyzer #

## Building Analyzer ##

```bash
mkdir build
cd build
cmake ..
make
```

There is no install target, yet ...

## Running this Checker ##

Can be run with any tools that allow to load llvm plugins

```bash
export MY_INCLUDES="-I/usr/local/include -I/usr/local/lib/clang/12.0.1/include -I/usr/include"
clang -cc1 ${=MY_INCLUDES} -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyze -analyzer-checker=example.ErrorChecker ~/testerror.c
```

```bash
scan-build -load-plugin /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -enable-checker example.ErrorChecker -disable-checker unix.Malloc clang -c ~/testerror.c
```

## Debugging ##

```bash
gdb --args clang -cc1 ${=MY_INCLUDES} -analyze -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyzer-checker=example.ErrorChecker testerror.c
```

```bash
(gdb) add-symbol-file /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so
(gdb) br /home/mschroetter/project/SimpleErrorChecker/SimpleErrorChecker.cpp:251
```

## Problems ##

[See Issues](https://gitup.uni-potsdam.de/maxschro/llvm-static-analyzers/issues)
