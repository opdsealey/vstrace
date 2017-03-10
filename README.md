# vstrace
A simple visualisation / display tool for strace. Might even get finished one day

*Example Usage*
```
  python vstrace -s open close write -p ls -la /tmp
  ```

```
  python vstrace -h
  

usage: vstrace.py [-h] -s SYSCALLS [SYSCALLS ...] -p PROGRAM [PROGRAM ...]
                  [-v] [-d] [-ng | -g GRAPH_NAME]

optional arguments:
  -h, --help            show this help message and exit
  -s SYSCALLS [SYSCALLS ...], --syscalls SYSCALLS [SYSCALLS ...]
                        Syscalls to monitor , currently supported syscalls:
                        Open, Write, Close or 'all' for all supported
  -p PROGRAM [PROGRAM ...], --program PROGRAM [PROGRAM ...]
                        The program and arguments you wish to run
  -v, --verbose         Display realtime verbose messaging
  -d, --display         Display info to stdout 
  -ng, --no-graph       Do not display a graph (NOT YET IMPLEMENTED)
  -g GRAPH_NAME, --graph-name GRAPH_NAME       (NOT YET IMPLEMENTED)
  ```
