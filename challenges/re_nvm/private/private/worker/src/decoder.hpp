#pragma once
#include <array>
#include "socket.hpp"
#include "instruction_set.hpp"
#include "utils.hpp"


template <class T>
class Decoder {
private:
    std::array<Instruction<T>*, 256> code;
    Socket *socket;

public:
    Decoder(Socket* socket) : socket(socket), code{nullptr} {};

    ~Decoder() {
        for(const auto instr : code){
            delete instr;
        }
    }

    Instruction<T>* decode(T requested_ip) {
        if(code[requested_ip] != nullptr){
            DEBUG("using cached instruction: 0x" << std::hex << requested_ip);
            return code[requested_ip];
        }

        while(1) {
            DEBUG("receiving instruction for: 0x" << std::hex << requested_ip);

            T offset = socket->read2();
            uint8_t instr_type = socket->read1();
            T opcode_type = socket->read2();
            T data = socket->read2();

            Instruction<T> *parsed_instr;
            switch(instr_type){
                case 0:
                    parsed_instr = new Mov<T>(opcode_type, data);
                    break;
                case 1:
                    parsed_instr = new Add<T>(opcode_type, data);
                    break;
                case 2:
                    parsed_instr = new Sub<T>(opcode_type, data);
                    break;
                case 3:
                    parsed_instr = new Mul<T>(opcode_type, data);
                    break;
                case 4:
                    parsed_instr = new Mod<T>(opcode_type, data);
                    break;
                case 5:
                    parsed_instr = new Xor<T>(opcode_type, data);
                    break;
                case 6:
                    parsed_instr = new And<T>(opcode_type, data);
                    break;

                
                case 0x12:
                    parsed_instr = new Call<T>(opcode_type, data);
                    break;
                case 0x13:
                    parsed_instr = new Ret<T>(opcode_type, data);
                    break;
                case 0x14:
                    parsed_instr = new JumpZero<T>(opcode_type, data);
                    break;
                case 0x15:
                    parsed_instr = new JumpNotZero<T>(opcode_type, data);
                    break;


                case 0x21:
                    parsed_instr = new DebugCommand<T>(opcode_type, data);
                    break;
                case 0x22:
                    parsed_instr = new Stop<T>(opcode_type, data);
                    break;
                default:
                    std::cerr << "Unknown instr_type" << std::endl;
                    parsed_instr = new Stop<T>(0, -1);
                    break;
            }

            DEBUG(std::hex << "received tuple: (0x" << (int)offset << ", 0x" << (int)instr_type << ", 0x" << (int)opcode_type << ", 0x" << (int)data << ")");

            code[offset] = parsed_instr;
            if(offset == requested_ip) {
                break;
            }else{
                DEBUG("instr ip 0x" << std::hex << (int)offset << " cached");
            }
        }

        return code[requested_ip];
    };
};
