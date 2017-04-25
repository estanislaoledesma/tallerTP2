#include <netinet/in.h>
#include <sstream>
#include <iostream>
#include <bitset>
#include <vector>
#include "Sniffer.h"

#define LINE1 0
#define LINE2 1
#define LINE4 3
#define LINE5 4
#define HEADERBTS 5
#define MFBIT 0x00002000
#define OFFBITS 13
#define HALFWORD 16

Sniffer::Sniffer(const char *ipPackagePath, Assembler& assembler) {
    packagesFile.open(ipPackagePath, std::ios::in | std::ios::binary);
    assembler = assembler;
}

Sniffer::~Sniffer(){
    packagesFile.close();
}

void Sniffer::sniff1() {
    while (packagesFile.good()) {
        std::vector<uint32_t> header(HEADERBTS);
        packagesFile.read(reinterpret_cast<char *>(header.data()),\
                          HEADERBTS * sizeof(uint32_t));
        uint16_t len = (ntohl(header[LINE1]) >> HALFWORD) - HEADERBTS;
        uint32_t scndLine = ntohl(header[LINE2]);
        uint16_t id = scndLine << HALFWORD;
        uint16_t offset = scndLine >> OFFBITS;
        bool MF = (scndLine & MFBIT) == MFBIT;
        uint32_t src = ntohl(header[LINE4]);
        uint32_t dst = ntohl(header[LINE5]);
        //for (int i = 0; i < 5; i++) {
        //    std::cout << header[i] << "\n";
        //}
        std::vector<uint8_t> data(len);
        packagesFile.read(reinterpret_cast<char *>(data.data()), \
                          len * sizeof(uint8_t));
        std::string dataString(data.begin(), data.end());
        Package package = Package(src, dst, dataString, MF, offset);
        assembler.addPackage(id, package);
        //for (int i = 0; i < len; i++) {
        //    std::cout << data[i];
        //}
        //std::cout << "\n";
    }
}
