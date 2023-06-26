.DEFAULT_GOAL := help

REAL_FLAG=$$(cat ../flag.txt)
TCPDUMP_OUTFILE=/pcap/trace.pcap

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'


.PHONY: vm-prog
vm-prog: ## generate encoded flag
	cd ./vm_prog && gcc main.c -o vm-prog && ./vm-prog | tee ./enc.txt
	cp ./vm_prog/enc.txt ./client/enc.txt


.PHONY: test
test: ## test if real flag works and test if fake flag does not work
	@echo "Executing positive test case..."
	make docker-run TCPDUMP_OUTFILE=/dev/null | tee test_log

	@echo "Executing negative test case #1 ..."
	make docker-run REAL_FLAG="justCTF{random_wrong_flag_12345}" TCPDUMP_OUTFILE=/dev/null | tee -a test_log

	@echo "Executing negative test case #2 ..."
	make docker-run REAL_FLAG="ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" TCPDUMP_OUTFILE=/dev/null | tee -a test_log

	cat test_log | grep FIN
	@rm -f test_log


.PHONY: client
client: vm-prog ## run client
	cd client && cp ../vm_prog/enc.txt . && python3 client.py $$(cat ../../flag.txt)


.PHONY: worker
worker: build-worker ## run worker (vm)
	cd worker && ./worker


.PHONY: build-worker
build-worker: vm-prog ## build worker binary
	docker run -it --rm --user $$(id -u):$$(id -g) -w /tmp -v $$(pwd)/worker:/code rikorose/gcc-cmake bash -c "cmake -DCMAKE_BUILD_TYPE=Release /code && make && chmod +x src/worker && cp src/worker /code"


.PHONY: solve
solve: vm-prog ## solve vm-prog
	cp ./vm_prog/enc.txt ./solver/
	docker rm -f re_nvm_solver || true
	docker build -t re_nvm_solver -f ./solver/Dockerfile .
	docker run --rm -it re_nvm_solver


.PHONY: docker-run
docker-run: clean vm-prog build-worker ## run worker and client in docker containers
	docker rm -f re_nvm_worker re_nvm_client || true
	docker network rm re_nvm_network || true

	docker build -t re_nvm_image_client -f ./gen_pcap/client.Dockerfile --build-arg HOST=re_nvm_worker --build-arg PORT=2137 --build-arg FLAG=$(REAL_FLAG) .
	docker build -t re_nvm_image_worker -f ./gen_pcap/worker.Dockerfile --build-arg TCPDUMP_OUTFILE=$(TCPDUMP_OUTFILE) .
	docker network create re_nvm_network

	docker run -dit --rm --name re_nvm_worker -v $$(pwd)/gen_pcap:/pcap --network re_nvm_network re_nvm_image_worker
	docker run -it --rm --name re_nvm_client --network re_nvm_network re_nvm_image_client
	docker wait re_nvm_worker


.PHONY: public
public: ## bundle public files
	make docker-run REAL_FLAG="ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	cp ./gen_pcap/trace.pcap ../public
	cp ./worker/worker ../public


.PHONY: clean
clean: ## clean all artifacts
	rm -rf worker/worker
	rm -rf vm-prog/vm-prog
	rm -rf client/__pycache__
	rm -rf gen_pcap/trace.pcap
	find . -type f -name "enc.txt" -delete


