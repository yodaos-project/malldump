# Malldump

[![Build Status](https://travis-ci.com/yonzkon/libcx.svg?branch=master)](https://travis-ci.com/yonzkon/libcx)

Attach to a process and dump statistics of low level malloc(ptmalloc, the glibc implementation) of the process.

## Supported malloc implementations

- ptmalloc, also known as ptmalloc2

## Supported platforms

- Linux

## Supported architectures

- x86_64
- aarch64
- arm

## Build
```
./tools/build.sh
```

## Usage

```
usage:
  -h           print this usage
  -D           debug mode [defaut: false]
  -t <arg>     type of malloc [default: ptmalloc]
  -p <arg>     pid of the target process
  -I <arg>     offset of mallinfo [default: ...]
  -P <arg>     offset of mp_ [default: ...]
  -H           display size of memory in human mode [default: false]
```
```
malldump -H -p <pid>
```

## Outputs

```
Process cmd:    nmap -sP 172.17.0.0/16
Process pid:    49457
Threads:        1
Arenas:         1
Total memory:   10248.0K
Avail memory:   403.1K
Used memory:    9844.9K
Used memory%:   96.07%
Free chunks:    2
Fastbin chunks: 3
Fastbin memory: 0.2K
Mmapped chunks: 1
Mmapped memory: 516.0K
Trim threshold: 128.0K
Mmap threshold: 128.0K
```
- Arenas: Number of created arenas.
- Total memory: Total memory that allocated from OS through brk() or mmap().
- Avail memory: Memory that kept by low level malloc but not used by application.
- Used memory: Memory that used by application through malloc().
- Used memory%: used memory / total memory.
- Free chunks: Chunks that linked in the double-linked list of bins except fastbins.
- Fastbin chunks: Chunks that linked in the single-linked list of fastbins.
- Mmapped chunks: Chunks that allocated from OS directly by mmap().
- Mmapped memory: Total memory of mmapped chunks.
- Trim threshold: The maximum amount of unused top-most memory to keep before releasing via malloc_trim in free().
- Mmap_threshold: The request size threshold for using mmap() to service a request. Requests of at least this size that cannot be allocated using already-existing space will be serviced via mmap.
