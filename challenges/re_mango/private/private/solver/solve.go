package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

func decode(s []byte, chunkSize int) string {
	decoded := []byte{}
	for num := 0; num < len(s); num += 3 {
		chunk := string(s[num:(num + 3)])
		letter, _ := strconv.ParseInt(chunk, 8, 32)
		decoded = append(decoded, byte(letter^0x37))
	}

	return string(decoded)
}

func rev_shuffle(enc string, translate []uint32) []byte {
	rev_mapping := map[uint32]uint32{}
	out := make([]byte, 0, len(enc))
	for i, v := range translate {
		rev_mapping[v] = uint32(i)
	}

	for i := range translate {
		r := rev_mapping[uint32(i)]
		out = append(out, enc[r])
	}
	return out
}

func gen_table(str_len int, candidate uint32) []uint32 {

	idx := make([]uint32, 0, str_len)
	uniq := map[uint32]bool{}

	rand.Seed(int64(candidate))

	for {
		if len(uniq) == str_len {
			break
		}

		r := uint32(rand.Intn(str_len))

		if exists, ok := uniq[r]; !ok || !exists {
			idx = append(idx, r)
		}

		uniq[r] = true
	}

	return idx
}

func get_primes(start, end uint32) []uint32 {
	primes := []uint32{}
	for num := start; num < end; num++ {
		isPrime := true
		for i := uint32(2); i <= uint32(math.Sqrt(float64(num))); i++ {
			if num%i == 0 {
				isPrime = false
				break
			}
		}
		if isPrime {
			primes = append(primes, num)
		}
	}
	return primes
}

func rev_mangoify(encoded string) string {
	encoded = strings.ReplaceAll(encoded, "O", "1")
	parts := strings.Split(encoded, "o")
	decoded := []byte{}

	for _, p := range parts {
		c, _ := strconv.ParseInt(p, 2, 8)
		decoded = append(decoded, byte(c))
	}

	return string(decoded)
}

func solve(encoded string, start, stop uint32) {
	fmt.Println("Generating primes...")
	primes := get_primes(start, stop)

	fmt.Println("Solving...")
	for _, prime := range primes {
		translate := gen_table(len(encoded), prime)
		rev := rev_shuffle(encoded, translate)
		decoded := decode(rev, 3)
		if strings.HasPrefix(decoded, "justCTF") {
			fmt.Printf("Seed was %d\n", prime)
			fmt.Println(decoded)
		}
	}
}

func main() {
	data, err := os.ReadFile("output.txt")
	if err != nil {
		fmt.Print(err)
		return
	}

	range_start, range_end := (1 << 19), (1 << 20)
	encoded := rev_mangoify(strings.TrimSpace(string(data)))
	solve(encoded, uint32(range_start), uint32(range_end))
}
