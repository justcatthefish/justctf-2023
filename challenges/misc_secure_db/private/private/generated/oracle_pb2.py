# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: oracle.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0coracle.proto\"\x06\n\x04Void\"\'\n\x04Task\x12\x10\n\x08question\x18\x01 \x01(\t\x12\r\n\x05token\x18\x02 \x01(\t\"/\n\x0cTaskResponse\x12\x10\n\x08response\x18\x01 \x01(\t\x12\r\n\x05token\x18\x02 \x01(\t\"\x1c\n\nTaskResult\x12\x0e\n\x06result\x18\x01 \x01(\t2V\n\x06Oracle\x12\x1f\n\x0fgenerateNewTask\x12\x05.Void\x1a\x05.Task\x12+\n\rcheckResponse\x12\r.TaskResponse\x1a\x0b.TaskResultb\x06proto3')



_VOID = DESCRIPTOR.message_types_by_name['Void']
_TASK = DESCRIPTOR.message_types_by_name['Task']
_TASKRESPONSE = DESCRIPTOR.message_types_by_name['TaskResponse']
_TASKRESULT = DESCRIPTOR.message_types_by_name['TaskResult']
Void = _reflection.GeneratedProtocolMessageType('Void', (_message.Message,), {
  'DESCRIPTOR' : _VOID,
  '__module__' : 'oracle_pb2'
  # @@protoc_insertion_point(class_scope:Void)
  })
_sym_db.RegisterMessage(Void)

Task = _reflection.GeneratedProtocolMessageType('Task', (_message.Message,), {
  'DESCRIPTOR' : _TASK,
  '__module__' : 'oracle_pb2'
  # @@protoc_insertion_point(class_scope:Task)
  })
_sym_db.RegisterMessage(Task)

TaskResponse = _reflection.GeneratedProtocolMessageType('TaskResponse', (_message.Message,), {
  'DESCRIPTOR' : _TASKRESPONSE,
  '__module__' : 'oracle_pb2'
  # @@protoc_insertion_point(class_scope:TaskResponse)
  })
_sym_db.RegisterMessage(TaskResponse)

TaskResult = _reflection.GeneratedProtocolMessageType('TaskResult', (_message.Message,), {
  'DESCRIPTOR' : _TASKRESULT,
  '__module__' : 'oracle_pb2'
  # @@protoc_insertion_point(class_scope:TaskResult)
  })
_sym_db.RegisterMessage(TaskResult)

_ORACLE = DESCRIPTOR.services_by_name['Oracle']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _VOID._serialized_start=16
  _VOID._serialized_end=22
  _TASK._serialized_start=24
  _TASK._serialized_end=63
  _TASKRESPONSE._serialized_start=65
  _TASKRESPONSE._serialized_end=112
  _TASKRESULT._serialized_start=114
  _TASKRESULT._serialized_end=142
  _ORACLE._serialized_start=144
  _ORACLE._serialized_end=230
# @@protoc_insertion_point(module_scope)
