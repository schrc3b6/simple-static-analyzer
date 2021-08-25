# Static Analyzer #

## Running this Checker ##

```bash
export MY_INCLUDES="-I/usr/local/include -I/usr/local/lib/clang/12.0.1/include -I/usr/include"
clang -cc1 ${=MY_INCLUDES} -load /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -analyze -analyzer-checker=example.ErrorChecker ~/testerror.c
```

```bash
scan-build -load-plugin /home/mschroetter/project/SimpleErrorChecker/build/SimpleErrorChecker.so -enable-checker example.ErrorChecker -disable-checker unix.Malloc clang -c ~/testerror.c
```

## Problems ##

see issues
