#pragma once

template <class T>
class VM;

template <class T>
class Instruction {
public:
protected:
    T opcode_type;
    T imm;

public:
    Instruction(T opcode_type, T imm) : opcode_type{opcode_type}, imm{imm} {};
    virtual int execute(VM<T>& vm) = 0;
};
