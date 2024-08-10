## vfk_uoj_sandbox

A modified version of the sandbox from [UOJ](https://github.com/vfleaking/uoj) to be used in Fortuna OJ.

**Thanks to the original author [@vfleaking](https://github.com/vfleaking), and former contributor [@roastduck](https://github.com/roastduck), for their work!**

### Usage

```
Usage: uoj_run [OPTION...] program arg1 arg2 ...
run_program: a tool to run program safely

  -T, --tl=TIME_LIMIT        Set time limit (in millisecond)
  -R, --rtl=TIME_LIMIT       Set real time limit (in millisecond)
  -M, --ml=MEMORY_LIMIT      Set memory limit (in KB)
  -O, --ol=OUTPUT_LIMIT      Set output limit (in KB)
  -S, --sl=STACK_LIMIT       Set stack limit (in KB)
  -i, --in=IN                Set input file name
  -o, --out=OUT              Set output file name
  -e, --err=ERR              Set error file name
  -w, --work-path=WORK_PATH  Set the work path of the program
  -r, --res=RESULT_FILE      Set the file name for outputing the result
  -t, --type=TYPE            Set the program type (for some program such as
                             python)
      --add-readable=FILE    Add a readable file
      --add-writable=FILE    Add a writable file
      --unsafe               Don't check dangerous syscalls
      --show-trace-details   Show trace details
      --allow-proc           Allow fork, exec... etc.
      --add-readable-raw=FILE   Add a readable (don't transform to its real
                             path)
      --add-writable-raw=FILE   Add a writable (don't transform to its real
                             path)
      --use-rss              Use Resident Set Size as memory usage (Use
                             Allocated Size as default)
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

### Modifications

- Adapt the sandbox for Ubuntu 22.04
- Changed time measuring unit into millisecond.
- Changed memory, stack and output file size measuring unit into kilobyte.
- Altered memory measuring method
  - Measure allocated memory size (num of pages of data/stack) by default
  - Add switch `--use-rss` to measure Resident Set Size (RSS) instead, which is the default for UOJ
- Dump away error logs from sandboxed program by default
- Fix a bug caused by `AT_EMPTY_PATH` flag of syscall `newfstatat`

### Build Pre-requisite

Need `libseccomp-dev` to build.

To install this package in Ubuntu/Debian: `sudo apt install libseccomp-dev`

### Compile & Install

`make && sudo make install`
