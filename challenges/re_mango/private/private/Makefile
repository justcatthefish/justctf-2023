build: main.go
	docker run -v $$(pwd):/w -w /w golang:1.20 go build

clean:
	rm -r mango

solve:
	cd solver && ./solve.sh

public: build
	cat ../flag.txt | tr -d '\n' | ./mango | tail -1 | tr -d '\n' > ../public/output.txt
	cp ./mango ../public


