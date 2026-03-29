
```bash
clang -O2 -target bpf -g -c xdp.c -o xdp.o
sudo ip link set dev ens18 xdp obj xdp.o sec xdp
```

```bash
gcc map.c -lbpf
sudo ./map.c
```
