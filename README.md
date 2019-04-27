# Malldump

Malldump attachs a process, and dumps the status of low level malloc of the process.

## Support malloc implementations

- ptmalloc, also known as ptmalloc2

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
