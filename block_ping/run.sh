sudo bpftool net detach xdp dev enp6s0
sudo rm -f /sys/fs/bpf/my_xdp_program
sudo bpftool prog load main.bpf.o /sys/fs/bpf/my_xdp_program
sudo ip link set dev enp6s0 xdp obj /sys/fs/bpf/my_xdp_program
sudo bpftool net attach xdp pinned /sys/fs/bpf/my_xdp_program dev enp6s0
sudo /lib64/ld-linux-x86-64.so.2 --library-path /lib64 ./main
