#include "ID_Map.hpp"

void IDMap::initialize() {
    map_cnt = 0;
    ID_map = (ID_Map *)malloc(sizeof(ID_Map) * MAX_BLOCKS);
}

int IDMap::convertIdxToBlockID(char *idx, char op_type) {
    int ret = -1;
    int ocall_status;

    for(int i = 0; i < MAX_BLOCKS; i++) {
        if(ID_map[i].idx != NULL) {
            if(strncmp((const char *)(ID_map[i].idx), (const char *)idx, MAX_IDX_SIZE) == 0)
                ret = (int)(ID_map[i].block_id);
        }
    }

    if(ret == -1 && op_type == 'w') {
        ID_map[map_cnt].block_id = map_cnt;
        ID_map[map_cnt].idx = (char *)malloc(MAX_IDX_SIZE);
        memcpy(ID_map[map_cnt].idx, idx, MAX_IDX_SIZE);
        ret = map_cnt;
        map_cnt++;
    }

    return ret;
}
