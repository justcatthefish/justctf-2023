import random
import signal
import time
import sys

from sandbox import evaluate
#################### POW #######################
from pow import NcPowser
powser = NcPowser(22)
prefix = powser.get_challenge()
print(f"sha256({prefix} + ???) == {'0'*powser.difficulty}({powser.difficulty})...")

powser_solution = input()
if not powser.verify_hash(prefix, powser_solution):
	exit(0)

###############################################

def handler(signum, frame):
    print('Time limit exceeded. Try again!')
    sys.stdout.flush()
    sys.exit(1)

signal.signal(signal.SIGALRM, handler)

FLAG = open("./flag.txt", "r").read()

WRONG_ANSWERS = 3
CARD_COUNT = 11
QUESTION_COUNT = 11
QUESTION_TIME = 5


print("Hello there!")
print("Would you like to play a little game?")
print("This time it will be little bit harder")
print(f"I have written {CARD_COUNT} values (yes, no) on cards. I am curious if you are able to guess which values they are.")
print(f"You can ask me {QUESTION_COUNT} logic questions.")

print(f"I know you're smart, so I won't always be honest about the answers. No worries, I will fool you only {WRONG_ANSWERS} times.")

while True:
	cards = [bool(random.getrandbits(1)) for _ in range(CARD_COUNT)]
	if cards.count(True) >= CARD_COUNT //3 and cards.count(False) >= CARD_COUNT // 3:
		break

wrong_answers = random.sample(range(QUESTION_COUNT), WRONG_ANSWERS)

for i in range(QUESTION_COUNT):
	question = input(f"{i}.Question: ")

	start_time = time.time()
	signal.alarm(QUESTION_TIME)
	try:
		value = evaluate(cards, question)
	except:
		value = bool(random.getrandbits(1))

	if i in wrong_answers:
		value = bool(random.getrandbits(1))
	end_time = time.time()

	elapsed = end_time - start_time
	signal.alarm(0)
	if elapsed < QUESTION_TIME:
		time.sleep(QUESTION_TIME - elapsed)
	else:
		exit(0)

	print(f"Question resolves to: {value}")

print("You have used all the questions.")
print("Now tell me one by one what I have written down on the cards.")

response = input("Your response: ")
response = response.split(" ")

print("If you are so smart, you should also be able to point out on which questions I deceived you.")
wrong_responses = input("Wrong responses: ")
wrong_responses = wrong_responses.split(" ")

if len(response) != CARD_COUNT:
	print("Your answer did not include all the cards")
	exit(0)
elif len(wrong_responses) != WRONG_ANSWERS:
	print("Your answer did not point all the wrong answers")
	exit(0)
else:
	received_cards = []
	for response_card in response:
		if response_card == "0":
			received_cards.append(False)
		elif response_card == "1":
			received_cards.append(True)
		else:
			print("Invalid response format")
			exit(0)

	try:
		wrong_responses = [int(wrong_response) for wrong_response in wrong_responses]
	except ValueError:
		wrong_responses = []
		print("Invalid response format")
		exit(0)

	if received_cards == cards and wrong_responses == wrong_answers:
		print("Great work!")
		print("This is yours flag: ", FLAG)
	else:
		print("You need to try harder!")
