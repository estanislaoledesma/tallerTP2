#include <netinet/in.h>
#include <sstream>
#include "Sniffer.h"

Sniffer::Sniffer(const char *ipPackagePath, Assembler& assembler) {
    packagesFile.open(ipPackagePath, std::ios::in | std::ios::binary);
    assembler = assembler;
}

Sniffer::~Sniffer(){
    packagesFile.close();
}

void Sniffer::sniff() {
    uint32_t line, src, dst;
    uint16_t packLen, id, offset;
    bool MF;
    std::stringstream data;
    int step = 0;
    while(packagesFile.peek() != EOF) { // DATA RACE
        packagesFile >> std::hex >> line;
        line = ntohl(line);
        switch(step) {
            case 0:
                packLen = (uint16_t) line;
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
                break;
            case 4:
                dst = line;
                step++;
                break;
            default:
                data << line;
                break;
        }
        packLen -= 4;
        if (packLen == 0) {
            std::string dataStr = data.str();
            Package package = Package(src, dst, dataStr, MF, offset);
            assembler.addPackage(package);
            step = 0;
        }
    }
}