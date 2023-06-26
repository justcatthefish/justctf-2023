#pragma once

#include <vector>
#include <experimental/iterator>

#include "decoder.hpp"
#include "instruction.hpp"
#include "utils.hpp"

template <class T>
class VM
{
public:
    bool running;
    std::array<T, 4> reg;
    std::array<T, 128> mem;
    std::vector<T> ret_stack;

    Socket* socket;
    Decoder<T>* decoder;

    VM() :  running(false),
            reg{},
            mem{},
            ret_stack(),
            socket(new Socket()),
            decoder(new Decoder<T>(socket)) {
        socket->start_listening(2137);
    }

    ~VM() {
        delete socket;
        delete decoder;
    }

    VM(const VM &) = delete;
    VM &operator=(const VM &) = delete;

    VM(VM &&) = delete;
    VM &operator=(VM &&) = delete;

    T ip() const { return reg[0]; };
    void set_ip(T new_ip) { reg[0] = new_ip; };

    int run()
    {
        load_input();
        int ec;
        running = true;
        while (running)
        {
            ec = step();
            if (ec != 0 && running){
                finish("ERR", ec);
                return ec;
            }
        }

        finish("FIN", ec);
        return ec;
    }

    int step() {
        auto instr = decoder->decode(ip());
        set_ip(ip() + 1);
        return instr->execute(*this);
    }

    void finish(const char* msg, int ec) {
        DEBUG("vm finish: " << std::hex << ec);
        char buffer[0x64];
        sprintf(buffer, "%s (0x%x)", msg, ec);
        socket->send(buffer);
    }

    void load_input() {
        auto* input = socket->read_n(0x20);
        DEBUG("load_input: " << input);
        std::copy(input, input + 0x20, mem.begin());
    }

    template<class TT>
    friend std::ostream &operator<<(std::ostream &os, const VM<TT> &vm);
};

template <class T>
std::ostream& operator<<(std::ostream& os, const VM<T>& vm){
    os << std::hex;
    for(int i = 0; i < vm.reg.size(); i++ ) {
        os << "reg" << i << ": 0x" << vm.reg[i] << '\n';
    }

    os << "stack: [";
    std::copy(
        vm.ret_stack.begin(),
        vm.ret_stack.end(),
        std::experimental::make_ostream_joiner(os, ", ")
    );
    os << "]\n";
    os << "mem: [";
    std::copy(
        vm.mem.begin(),
        vm.mem.end(),
        std::experimental::make_ostream_joiner(os, ' ')
        );
    os << "]\n";
    os << std::dec;

    return os;
}
