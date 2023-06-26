#!/usr/bin/env python3
from pwn import *

LENGTH = 5
ERRORS = 3
ENCODED_SIZE = 8
LETTERS = 6

def binary(n):
    return bin(n)[2:]

def base_convert(value, base):
	result = []
	while value > 0:
		result.insert(0, value % base)
		value = value // base
	return "".join(map(lambda x: str(x), result))


def count_differences(lhs, rhs):
    assert(len(lhs) == len(rhs))
    diff = 0
    for left, right in zip(lhs, rhs):
        if left != right:
            diff += 1
    return diff


def build_mapping(length: int, errors: int, encoded_size: int, available_symbols: int):
	mapping = {}
	distance = errors * 2
	value = 0
	counter = 0
	while len(mapping) < 2**length:
		encoded = base_convert(counter, available_symbols).rjust(encoded_size, '0')
		counter += 1

		collision = False
		for key, symbol in mapping.items():
			if count_differences(symbol, encoded) < distance:
				collision = True
				break

		if not collision:
			mapping[binary(value).rjust(LENGTH, "0")] = encoded
			value += 1

	return mapping

mappings = build_mapping(LENGTH, ERRORS, ENCODED_SIZE, LETTERS)
# mappings = {'0000000': '000000000', '0000001': '000111111', '0000010': '000222222', '0000011': '000333333', '0000100': '000444444', '0000101': '000555555', '0000110': '001012345', '0000111': '001103254', '0001000': '001234501', '0001001': '001325410', '0001010': '001450123', '0001011': '001541032', '0001100': '010013452', '0001101': '010102543', '0001110': '010235014', '0001111': '010324105', '0010000': '010451230', '0010001': '010540321', '0010010': '011005131', '0010011': '011114020', '0010100': '011221353', '0010101': '011330242', '0010110': '011443515', '0010111': '011552404', '0011000': '022001212', '0011001': '022110303', '0011010': '022223030', '0011011': '022332121', '0011100': '023014534', '0011101': '023105425', '0011110': '023240152', '0011111': '023351043', '0100000': '024020441', '0100001': '024131550', '0100010': '024254315', '0100011': '024345204', '0100100': '025404051', '0100101': '025515140', '0100110': '032025324', '0100111': '032134235', '0101000': '032242413', '0101001': '032353502', '0101010': '033033110', '0101011': '033122001', '0101100': '033415253', '0101101': '033504342', '0101110': '035201104', '0101111': '035310015', '0110000': '042211525', '0110001': '042300434', '0110010': '043431402', '0110011': '043520513', '0110100': '044043023', '0110101': '044152132', '0110110': '045253241', '0110111': '045342350', '0111000': '055032203', '0111001': '055123312', '0111010': '100021435', '0111011': '100130524', '0111100': '100204153', '0111101': '100315042', '0111110': '100452301', '0111111': '100543210', '1000000': '101054014', '1000001': '101145105', '1000010': '101401540', '1000011': '101510451', '1000100': '102042552', '1000101': '102153443', '1000110': '103433055', '1000111': '103522144', '1001000': '110034340', '1001001': '110125251', '1001010': '111203002', '1001011': '111312113', '1001100': '112050205', '1001101': '112141314', '1001110': '112422420', '1001111': '112533531', '1010000': '113215335', '1010001': '113304224', '1010010': '114251121', '1010011': '114340030', '1010100': '120424512', '1010101': '120535403', '1010110': '121231234', '1010111': '121320325', '1011000': '122455154', '1011001': '122544045', '1011010': '124002333', '1011011': '124113222', '1011100': '125200410', '1011101': '125311501', '1011110': '133041241', '1011111': '133150350', '1100000': '134210543', '1100001': '134301452', '1100010': '135003525', '1100011': '135112434', '1100100': '141425033', '1100101': '141534122', '1100110': '144224200', '1100111': '144335311', '1101000': '155414323', '1101001': '155505232', '1101010': '202004421', '1101011': '202115530', '1101100': '202220115', '1101101': '202331004', '1101110': '203045313', '1101111': '203154202', '1110000': '204232440', '1110001': '204323551', '1110010': '204441225', '1110011': '204550334', '1110100': '205051150', '1110101': '205140041', '1110110': '212212051', '1110111': '212303140', '1111000': '213020022', '1111001': '213131133', '1111010': '213455441', '1111011': '213544550', '1111100': '215043234', '1111101': '215152325', '1111110': '220201341', '1111111': '220310250'}
print(mappings)

def build_question(mappings, question_no, letters, letter_mapping):
	subquestions_groups = [[] for _ in range(letters - 1)]
	for value, entry in mappings.items():
		to_detect = entry[question_no]
		if int(to_detect) == letters - 1:
			continue

		subquery = []
		for index, bit in enumerate(value):
			if bit == '0':
				subquery.append("not cards["+str(index)+"]")
			else:
				subquery.append("cards["+str(index)+"]")

		subquery = "(" + " and ".join(subquery) + ")"
		subquestions_groups[int(to_detect)].append(subquery)

	question = "False"
	for index, subquestions in enumerate(subquestions_groups):
		if len(subquestions) == 0:
			continue
		question += " or ((" + " or ".join(subquestions) + ") and " + letter_mapping[index] + ")"

	return question

def find_nearest(mappings, token, errors):
	min_distance = 1000
	result = None
	for value, mapping in mappings.items():
		distance = 0
		for lhs, rhs in zip(token, mapping):
			if lhs != rhs:
				distance += 1
		if distance <= min_distance:
			min_distance = distance
			result = value

	if not result:
		raise Exception("Not found")
	else:
		return result

LETTER_MAPPING = {
	0: "True",
	1: "~True",
	2: "~~True",
	3: "~False",
	4: "~~False"
}

REVERSE_TOKEN_MAPPING = {
	"True": 0,
	"-2": 1,
	"1": 2,
	"-1": 3,
	"0": 4,
	"False": 5
}

# Locally on MacOS use: PROXY=host.docker.internal
if args.PROXY:
    info("SETTING PROXY: " + args.PROXY)
    context.proxy = args.PROXY

with remote(args.HOST, args.PORT) as p:
	info("CONNECTING")
	p.recvline()
	p.recvline()
	p.recvline()
	p.recvline()
	p.recvline()

	responses = []

	for i in range(ENCODED_SIZE):
		question = build_question(mappings, i, LETTERS, LETTER_MAPPING)
		p.sendline(question.encode("utf-8"))
		response = p.recvline()
		responses.append(response.decode("utf-8").split(": ")[2][:-1])

	response = "".join([str(REVERSE_TOKEN_MAPPING[token]) for token in responses])
	info("Message received: " + response)
	solution = find_nearest(mappings, response, ERRORS)
	solution = " ".join(solution)
	info("Nearest word: " + solution)

	p.sendline(solution.encode("utf-8"))
	print(p.recvall().decode())

