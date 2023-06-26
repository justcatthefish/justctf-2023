package main

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

//go:noinline
func conv(plain string) string {
	parts := []string{}

	for i := 0; i < len(plain); i++ {
		parts = append(parts, fmt.Sprintf("%03o", int(plain[i])^0x37))
	}

	return strings.Join(parts, "")
}

//go:noinline
func gen_table(str_len int) []uint32 {
	idx := make([]uint32, 0, str_len)
	uniq := map[uint32]bool{}

	e, err := crand.Prime(crand.Reader, 20)
	if err != nil {
		fmt.Println("Cannot get prime")
		os.Exit(1)
	}

	rand.Seed(int64(e.Int64()))

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

//go:noinline
func shuffle(plain string, translate []uint32) string {
	out := make([]byte, 0, len(plain))

	for i := range plain {
		out = append(out, plain[translate[i]])
	}
	return string(out)
}

//go:noinline
func mangoify(encoded string) string {
	parts := []string{}
	for _, c := range encoded {
		parts = append(parts, strconv.FormatInt(int64(c), 2))
	}
	s := strings.Join(parts, "o")
	return strings.ReplaceAll(s, "1", "O")
}

func main() {
	fmt.Print("Type plain text that will be converted to mangos: ")
	var input string
	fmt.Scanln(&input)

	oct := conv(input)
	translate := gen_table(len(oct))
	shuffled := shuffle(oct, translate)
	mangos := mangoify(shuffled)
	fmt.Println("Here are your mangos:")
	fmt.Println(mangos)
}
