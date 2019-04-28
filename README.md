# Malldump

Attach to a process and dump status of low level malloc(ptmalloc, the glibc implementation) of the process.

## Supported malloc implementations

- ptmalloc, also known as ptmalloc2

## Supported platforms

- x86_64
- aarch64

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
process cmd:    sshd: root@pts/0
process pid:    447
total memory:   488.0K
avail memory:   172.2K
used memory:    315.8K
used memory%:   64.71%
free chunks:    7
fastbin chunks: 0
fastbin memory: 0.0K
mmapped chunks: 1
mmapped memory: 320.0K
trim threshold: 632.0K
mmap threshold: 316.0K
```

- total memory: Total memory that allocated from OS through brk() or mmap().
- avail memory: Memory that kept by low level malloc but not used by application.
- used memory: Memory that used by application through malloc().
- used memory%: used memory / total memory.
- free chunks: Chunks that linked in the double-linked list of bins except fastbins.
- fastbin chunks: Chunks that linked in the single-linked list of fastbins.
- mmapped chunks: Chunks that allocated from OS directly by mmap().
- mmapped memory: Total memory of mmapped chunks.
- trim threshold: The maximum amount of unused top-most memory to keep before releasing via malloc_trim in free().
- mmap_threshold: The request size threshold for using mmap() to service a request. Requests of at least this size that cannot be allocated using already-existing space will be serviced via mmap.
