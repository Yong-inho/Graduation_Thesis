#ifndef __ID_MAP_HPP__
#define __ID_MAP_HPP__

#include <stdlib.h>
#include <stdint.h>
#include "Enclave.h"
#include "Enclave_t.h"

#include "../global_config.h"

typedef struct _ID_Map {
    char *idx;
    uint32_t block_id;
} ID_Map;

class IDMap {
    public:
        uint32_t map_cnt;
        ID_Map *ID_map;

        IDMap(){};
        void initialize();
        int convertIdxToBlockID(char *idx, char op_type);
};

#endif