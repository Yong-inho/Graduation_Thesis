#include "Stash.hpp"

Stash::Stash() {

}

void Stash::setup(uint32_t p_stash_size, uint32_t p_data_size, uint32_t p_gN) {
    gN = p_gN;
    STASH_SIZE = p_stash_size;
    stash_data_size = p_data_size;
    current_size = 0;
    for(uint32_t i = 0; i < STASH_SIZE; i++) {
        insertNewBlock();
    }
}

void Stash::insertNewBlock() {
    Block block(stash_data_size, gN);
    struct nodev2 *new_node = (struct nodev2 *)malloc(sizeof(struct nodev2));

    if(current_size == STASH_SIZE) {
        ;//ocall_print_string("Stash Overflow")
    } else {
        unsigned char *serialized_block = block.serialize(stash_data_size);
        new_node->serialized_block = serialized_block;
        new_node->next = getStart();
        setStart(new_node);
        current_size++;
    }
}

struct nodev2 *Stash::getStart(){
	return start;
}

void Stash::setStart(struct nodev2 *new_start){
	start = new_start;
}

void Stash::performAccessOperation(char op_type, uint32_t id, uint32_t newleaf, unsigned char *data_in, unsigned char *data_out) {
    struct nodev2 *iter = getStart();
	uint8_t cnt = 1;
	uint32_t flag_id = 0, flag_w = 0, flag_r = 0;
	unsigned char *data_ptr;
	uint32_t *leaflabel_ptr;

    while(iter && cnt <= STASH_SIZE) {
		data_ptr = (unsigned char*)getDataPtr(iter->serialized_block);
		leaflabel_ptr = getTreeLabelPtr(iter->serialized_block);
		flag_id = ( getId(iter->serialized_block) == id);

        //Replace leaflabel in block with newleaf
		oassign_newlabel(leaflabel_ptr, newleaf, flag_id);

		flag_w = (flag_id && op_type == 'w');
		omove_buffer((unsigned char*) data_ptr, data_in, stash_data_size, flag_w);
		flag_r = (flag_id && op_type == 'r');
        omove_buffer(data_out, (unsigned char*) data_ptr, stash_data_size, flag_r);

        iter = iter->next;
		cnt++;
    }
}

void Stash::passInsert(unsigned char *serialized_block, bool is_dummy) {
    struct nodev2 *iter = start;
    bool block_written = false;
    uint8_t cnt = 1;

    while(iter && cnt<=STASH_SIZE)	{
        bool flag = (!is_dummy && (isBlockDummy(iter->serialized_block, gN)) && !block_written);
        stash_serialized_insert(iter->serialized_block, serialized_block, stash_data_size, flag, &block_written);
        iter = iter->next;
        cnt++;
    }
}

uint32_t Stash::stashOccupancy() {
    uint32_t count = 0,cntr=1;
    nodev2 *iter = getStart();
    while(iter&&cntr<=STASH_SIZE)	{
        if( (!isBlockDummy(iter->serialized_block, gN)) ) {
            count++;
        }
        iter = iter->next;
        cntr++;
    }
    return count;
}

#ifdef OC_DEBUG

uint32_t Stash::displayStashContents(uint64_t nlevel, bool recursive_block) {
    uint32_t count = 0, cntr = 1;
    nodev2 *iter = getStart();

    while(iter && cntr<=STASH_SIZE) {
        unsigned char *tmp;
    
        if( (!isBlockDummy(iter->serialized_block, gN)) ) {
            tmp = iter->serialized_block + ADDITIONAL_METADATA_SIZE;
            uint32_t pbuckets = getTreeLabel(iter->serialized_block);
            count++;
        
            while(pbuckets >= 1) {
                //printf("%d, ", pbuckets);
                ocall_print_uint((uint64_t)pbuckets);
                ocall_print_string(", ");
                pbuckets = pbuckets>>1;
            }

            //printf("\n");
            //printf("Data: ");
            ocall_print_string("\nData: ");

            if(recursive_block){
                uint32_t *data_ptr = (uint32_t *) tmp;
                for(uint32_t j = 0; j<stash_data_size/(sizeof(uint32_t)); j++){
                    //printf("%d,", *data_ptr);
                    ocall_print_uint((uint64_t)(*data_ptr));
                    ocall_print_string(",");
                    data_ptr++; 
                }
            } 
            else{
                unsigned char *data_ptr = tmp;
                for(uint32_t j=0; j<stash_data_size; j++){
                    //printf("%c", data_ptr[j]);
                    ocall_print_character((const char*)(&data_ptr[j]));
                }
            }
            //printf("\n");       
            ocall_print_string("\n");
        }
        iter = iter->next;
        cntr++;
    }
    //printf("\n");
    ocall_print_string("\n");
    return count;
}

#endif