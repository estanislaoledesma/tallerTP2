#include <iostream>
#include "Assembler.h"
#include "Sniffer.h"

#define PATH "multiple_packets.cap"

int main() {
    Assembler assembler;
    Sniffer sniffer(PATH, assembler);
    sniffer.sniff1();
    return 0;
}