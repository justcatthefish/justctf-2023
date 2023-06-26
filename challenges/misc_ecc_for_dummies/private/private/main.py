import random

from sandbox import evaluate

FLAG = open("./flag.txt", "r").read()

WRONG_ANSWERS = 3
CARD_COUNT = 5
QUESTION_COUNT = 8


print("Hello there!")
print("Would you like to play a little game?")
print(f"I have written {CARD_COUNT} values (yes, no) on cards. I am curious if you are able to guess which values they are.")
print(f"You can ask me {QUESTION_COUNT} logic questions.")

print(f"I know you're smart, so I won't always be honest about the answers. No worries, I will fool you only {WRONG_ANSWERS} times.")

cards = [bool(random.getrandbits(1)) for _ in range(CARD_COUNT)]

wrong_answers = random.sample(range(QUESTION_COUNT), WRONG_ANSWERS)

for i in range(QUESTION_COUNT):
	question = input(f"{i}.Question: ")

	try:
		value = evaluate(cards, question)
	except:
		value = bool(random.getrandbits(1))

	if i in wrong_answers:
		value = bool(random.getrandbits(1))

	print(f"Question resolves to: {value}")

print("You have used all the questions.")
print("Now tell me one by one what I have written down on the cards.")

response = input("Your response: ")
response = response.split(" ")
if len(response) != CARD_COUNT:
	print("Your answer did not include all the cards")
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

	if received_cards == cards:
		print("Great work!")
		print("This is yours flag: ", FLAG)
	else:
		print("You need to try harder!")
