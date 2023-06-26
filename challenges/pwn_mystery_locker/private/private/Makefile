.PHONY: build
build: mystery_locker.c md5.c
	# gcc mystery_locker.c md5.c -O1 -fno-toplevel-reorder -o mystery_locker_dev -ggdb
	gcc mystery_locker.c md5.c -O1 -fno-toplevel-reorder -s -o mystery_locker

.PHONY: public
public:
	mkdir -p ../public
	cp flag.txt ../flag.txt
	cp mystery_locker ../public/mystery_locker
	cp libc.so.6 ../public/libc.so.6

.PHONY: solve
solve:
	cp mystery_locker ./solver/mystery_locker
	cp libc.so.6 ./solver/libc.so.6
	cd ./solver && ./solve.sh localhost 1337

.PHONY: run-local
run-local:
	./mystery_locker

.PHONY: run
run:
	cd .. && ./run.sh

.PHONY: clean
clean:
	rm -rf -- fs mystery_locker mystery_locker_dev
