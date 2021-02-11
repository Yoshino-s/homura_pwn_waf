all: x86_64 x86 clean_mid

x86_64:
	gcc -g gen.c -o gen -lseccomp && ./gen | ./gen.py > bpf64 && gcc gen_64.c -o gen_64 -fno-pie && ./dis_seccomp.py gen_64 > hpwnwaf_64.py
x86:
	gcc -g gen.c -o gen -m32 -lseccomp && ./gen | ./gen.py > bpf32 && gcc gen_32.c -o gen_32 -m32 -fno-pie && ./dis_seccomp.py gen_32 > hpwnwaf_32.py
clean_mid:
	rm -f gen gen_32 gen_64 bpf32 bpf64