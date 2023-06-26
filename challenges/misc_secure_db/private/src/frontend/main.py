import os
import sys
import signal
import termios

import grpc

from generated import oracle_pb2
from generated import oracle_pb2_grpc


def get_full_line():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~termios.ECHO & ~termios.ICANON        # lflags
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        text = input()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return text


def handler(signum, frame):
    print('Time limit exceeded. Try again!')
    sys.stdout.flush()
    sys.exit(1)


signal.signal(signal.SIGALRM, handler)
signal.alarm(8 * 60 + 20)

oracle_address = os.environ['ORACLE']
print(oracle_address)

channel = grpc.insecure_channel(oracle_address)
stub = oracle_pb2_grpc.OracleStub(channel)

print("Hello there!")
print("We have recently gathered a tremendous amount of data from our new fitness app \"IFitt\" users.")
print("We want to perform some operations on this dataset, but our infrastructure cannot make it in a reasonable time(8 minutes).")
print("Could you help us? We cannot give you actual data due to legal concerns,")
print("but we think that you can overcome these difficulties and give us answers quickly.")

new_task: oracle_pb2.Task = stub.generateNewTask(oracle_pb2.Void())

question = new_task.question
token = new_task.token

print(question)

print("Please provide answer as base64 encoded raw data (only selected columns, no separator)")

response = get_full_line()

task_response = oracle_pb2.TaskResponse()
task_response.response = response
task_response.token = token

result = stub.checkResponse(task_response)

print(result.result)
