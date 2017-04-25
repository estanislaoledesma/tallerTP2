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

void Sniffer::sniff() {
    uint64_t line = 0, src = 0, dst = 0;
    uint16_t packLen = 0, id = 0, offset = 0;
    bool MF = false;
    std::stringstream data, lineStream;
    std::string dataString;
    int step = 0;
    while(packagesFile.good()) { // DATA RACE
        packagesFile.readsome(reinterpret_cast<char *>(&line), 4);
        std::cout << (uint16_t)line;
        std::cout << "\n";
        line = ntohl(line);
        std::cout << (uint16_t)line;
        std::cout << "\n";
        //std::cout << line;
        //std::cout << "\n";
        std::cout << "STEP: ";
        std::cout << step;
        std::cout << "\n";
        switch(step) {
            case 0:
                packLen = (uint16_t)line;
                step++;
                break;
            case 1:
                id = line << 16;
                offset = line >> 13;
                MF = ((line & 0x00002000) << 19) == 1;
                step++;
                break;
            case 2:
                step++;
                break;
            case 3:
                src = line;
                step++;
                packLen -= 0x14;
                break;
            case 4:
                dst = line;
                step++;
                packLen -= 0x4;
                break;
            default:
                data << std::hex << line;
        }
        //std::cout << "LEN: ";
        //std::cout << std::hex << packLen;
        //std::cout << "\n";
        //std::cout << data.str();
        if (packLen == 0) {
            dataString = data.str();
            std::cout << "String: ";
            std::cout << dataString;
            std::cout << "\n";
            Package package = Package(src, dst, dataString, MF, offset);
            assembler.addPackage(id, package);
            data.str("");
            step = 0;
        }
    }
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
