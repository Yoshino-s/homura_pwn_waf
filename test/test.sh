gcc ./test.c -o test
./test
../patch ./test ../gen/hpwnwaf_64.py
./test.patched