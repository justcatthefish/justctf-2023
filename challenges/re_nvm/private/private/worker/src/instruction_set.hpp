#pragma once

#include "instruction.hpp"
#include "vm.hpp"
#include <iostream>
#include <functional>
#include <sstream>

template <class T>
class Mov : public Instruction<T> {
    public:

    Mov(T opcode_type, T imm) : Instruction<T>(opcode_type, imm) {};
    virtual ~Mov() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. mov reg1, reg2
            1. mov reg1, imm
            2. mov reg1, [reg2]
            3. mov [reg1], reg2
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        uint8_t reg1 = this->opcode_type & 0b00001111;
        T reg2 = this->imm;
        switch(variant) {
        case 0: 
            vm.reg[reg1] = vm.reg[reg2];
            break;
        case 1:
            vm.reg[reg1] = this->imm;
            break;
        case 2:
            vm.reg[reg1] = vm.mem[vm.reg[reg2]];
            break;
        case 3:
            vm.mem[vm.reg[reg1]] = vm.reg[reg2];
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};

template<class T, class Operator>
class Arithmetic : public Instruction<T> {
    private:
    Operator operation;

    public:
    Arithmetic(T opcode_type, T imm) : Instruction<T>(opcode_type, imm), operation{} {};
    virtual ~Arithmetic() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. op reg1, reg2
            1. op reg1, imm
            2. op reg1, [reg2]
            3. op [reg1], reg2
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        uint8_t reg1 = this->opcode_type & 0b00001111;
        auto reg2 = this->imm;
        switch(variant) {
        case 0: 
            vm.reg[reg1] = operation(vm.reg[reg1], vm.reg[reg2]);
            break;
        case 1:
            vm.reg[reg1] = operation(vm.reg[reg1], this->imm);
            break;
        case 2:
            vm.reg[reg1] = operation(vm.reg[reg1], vm.mem[vm.reg[reg2]]);
            break;
        case 3:
            vm.mem[vm.reg[reg1]] = operation(vm.mem[vm.reg[reg1]], vm.reg[reg2]);
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};

template <class T>
using Add = Arithmetic<T, std::plus<T>>;
template <class T>
using Sub = Arithmetic<T, std::minus<T>>;
template <class T>
using Mul = Arithmetic<T, std::multiplies<T>>;
template <class T>
using Mod = Arithmetic<T, std::modulus<T>>;
template <class T>
using Xor = Arithmetic<T, std::bit_xor<T>>;
template <class T>
using And = Arithmetic<T, std::bit_and<T>>;


template <class T>
class Call : public Instruction<T> {
    public:

    Call(T opcode_type, T imm) : Instruction<T>(opcode_type, imm) {};
    virtual ~Call() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. call imm
            1. call reg
            2. call [reg]
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        uint8_t reg1 = this->opcode_type & 0b00001111;
        switch(variant) {
        case 0:
            vm.ret_stack.push_back(vm.ip());
            vm.set_ip(this->imm);
            break;
        case 1: 
            vm.ret_stack.push_back(vm.ip());
            vm.set_ip(vm.reg[reg1]);
            break;
        case 2: 
            vm.ret_stack.push_back(vm.ip());
            vm.set_ip(vm.mem[vm.reg[reg1]]);
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};

template <class T>
class Ret : public Instruction<T> {
    public:

    Ret(T opcode_type, T imm) : Instruction<T>(opcode_type, imm) {};
    virtual ~Ret() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. ret
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        switch(variant) {
        case 0:
            vm.set_ip(vm.ret_stack.back());
            vm.ret_stack.pop_back();
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};

template<class T, class Condition>
class Jump : public Instruction<T> {
    public:
    Condition cond;

    Jump(T opcode_type, T imm) : Instruction<T>(opcode_type, imm), cond{} {};
    virtual ~Jump() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. jump imm
            1. jump reg
            2. jump [reg]
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        uint8_t reg1 = this->opcode_type & 0b00001111;
        auto reg2 = this->imm;
        switch(variant) {
        case 0:
            if(cond(vm.reg[reg1])){
                vm.set_ip(this->imm);
            }
            break;
        case 1: 
            if(cond(vm.reg[reg2])){
                vm.set_ip(vm.reg[reg1]);
            }
            break;
        case 2: 
            if(cond(vm.reg[reg2])){
                vm.set_ip(vm.mem[vm.reg[reg1]]);
            }
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};


auto is_zero = []<class T>(T val)->bool { return val == 0; };
auto is_non_zero = []<class T>(T val)->bool { return !(is_zero(val)); };

template <class T>
using JumpZero = Jump<T, decltype(is_zero)>;
template <class T>
using JumpNotZero = Jump<T, decltype(is_non_zero)>;

template <class T>
class DebugCommand : public Instruction<T> {
    public:

    DebugCommand(T opcode_type, T imm) : Instruction<T>(opcode_type, imm) {};
    virtual ~DebugCommand() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. dump vm
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        std::stringstream out;
        std::string_view view;
        switch(variant) {
        case 0:
            out << vm;
            view = out.view();
            vm.socket->send_n(view.data(), view.size());
            break;
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};

template <class T>
class Stop: public Instruction<T> {
    public:

    Stop(T opcode_type, T imm) : Instruction<T>(opcode_type, imm) {};
    virtual ~Stop() = default;

    int execute(VM<T>& vm) {
        /*
        variants:
            0. stop imm
            1. stop reg
            2. stop [reg]
        */ 

        uint8_t variant = (this->opcode_type & 0b11110000) >> 4;
        uint8_t reg1 = this->opcode_type & 0b00001111;
        switch(variant) {
        case 0:
            vm.running = false;
            return this->imm;
        case 1:
            vm.running = false;
            return vm.reg[reg1];
        case 2:
            vm.running = false;
            return vm.mem[vm.reg[reg1]];
        default:
            std::cerr << "Invalid variant!" << std::endl;
            return 1;
        }
        return 0;
    }
};
