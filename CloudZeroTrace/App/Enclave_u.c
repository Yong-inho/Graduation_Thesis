#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_createNewORAM_t {
	uint8_t ms_retval;
	uint32_t ms_max_blocks;
	uint32_t ms_data_size;
	uint32_t ms_stash_size;
	uint32_t ms_recursion_data_size;
	int8_t ms_recursion_levels;
	uint8_t ms_Z;
} ms_ecall_createNewORAM_t;

typedef struct ms_ecall_ssl_connection_handler_t {
	long int ms_thread_id;
	thread_info_t* ms_thread_info;
} ms_ecall_ssl_connection_handler_t;

typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	size_t ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;

typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;

typedef struct ms_ocall_uploadBucket_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_recursion_level;
} ms_ocall_uploadBucket_t;

typedef struct ms_ocall_downloadBucket_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_level;
} ms_ocall_downloadBucket_t;

typedef struct ms_ocall_downloadPath_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_lev;
} ms_ocall_downloadPath_t;

typedef struct ms_ocall_uploadPath_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_level;
} ms_ocall_uploadPath_t;

typedef struct ms_ocall_buildFetchChildHash_t {
	uint32_t ms_left;
	uint32_t ms_right;
	unsigned char* ms_lchild;
	unsigned char* ms_rchild;
	uint32_t ms_hash_size;
	uint32_t ms_recursion_level;
} ms_ocall_buildFetchChildHash_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_mbedtls_net_connect_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_host;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_connect_t;

typedef struct ms_ocall_mbedtls_net_bind_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_bind_ip;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_bind_t;

typedef struct ms_ocall_mbedtls_net_accept_t {
	int ms_retval;
	mbedtls_net_context* ms_bind_ctx;
	mbedtls_net_context* ms_client_ctx;
	void* ms_client_ip;
	size_t ms_buf_size;
	size_t* ms_ip_len;
} ms_ocall_mbedtls_net_accept_t;

typedef struct ms_ocall_mbedtls_net_set_block_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_block_t;

typedef struct ms_ocall_mbedtls_net_set_nonblock_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_nonblock_t;

typedef struct ms_ocall_mbedtls_net_usleep_t {
	unsigned long int ms_usec;
} ms_ocall_mbedtls_net_usleep_t;

typedef struct ms_ocall_mbedtls_net_recv_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_recv_t;

typedef struct ms_ocall_mbedtls_net_send_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_send_t;

typedef struct ms_ocall_mbedtls_net_recv_timeout_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
	uint32_t ms_timeout;
} ms_ocall_mbedtls_net_recv_timeout_t;

typedef struct ms_ocall_mbedtls_net_free_t {
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_free_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_uploadBucket(void* pms)
{
	ms_ocall_uploadBucket_t* ms = SGX_CAST(ms_ocall_uploadBucket_t*, pms);
	ms->ms_retval = ocall_uploadBucket(ms->ms_serialized_bucket, ms->ms_bucket_size, ms->ms_label, ms->ms_hash, ms->ms_hash_size, ms->ms_size_for_level, ms->ms_recursion_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_downloadBucket(void* pms)
{
	ms_ocall_downloadBucket_t* ms = SGX_CAST(ms_ocall_downloadBucket_t*, pms);
	ms->ms_retval = ocall_downloadBucket(ms->ms_serialized_bucket, ms->ms_bucket_size, ms->ms_label, ms->ms_hash, ms->ms_hash_size, ms->ms_size_for_level, ms->ms_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_downloadPath(void* pms)
{
	ms_ocall_downloadPath_t* ms = SGX_CAST(ms_ocall_downloadPath_t*, pms);
	ms->ms_retval = ocall_downloadPath(ms->ms_serialized_path, ms->ms_path_size, ms->ms_label, ms->ms_path_hash, ms->ms_path_hash_size, ms->ms_level, ms->ms_D_lev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_uploadPath(void* pms)
{
	ms_ocall_uploadPath_t* ms = SGX_CAST(ms_ocall_uploadPath_t*, pms);
	ms->ms_retval = ocall_uploadPath(ms->ms_serialized_path, ms->ms_path_size, ms->ms_label, ms->ms_path_hash, ms->ms_path_hash_size, ms->ms_level, ms->ms_D_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_buildFetchChildHash(void* pms)
{
	ms_ocall_buildFetchChildHash_t* ms = SGX_CAST(ms_ocall_buildFetchChildHash_t*, pms);
	ocall_buildFetchChildHash(ms->ms_left, ms->ms_right, ms->ms_lchild, ms->ms_rchild, ms->ms_hash_size, ms->ms_recursion_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_user_check(void* pms)
{
	ms_ocall_pointer_user_check_t* ms = SGX_CAST(ms_ocall_pointer_user_check_t*, pms);
	ocall_pointer_user_check(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in(void* pms)
{
	ms_ocall_pointer_in_t* ms = SGX_CAST(ms_ocall_pointer_in_t*, pms);
	ocall_pointer_in(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_out(void* pms)
{
	ms_ocall_pointer_out_t* ms = SGX_CAST(ms_ocall_pointer_out_t*, pms);
	ocall_pointer_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in_out(void* pms)
{
	ms_ocall_pointer_in_out_t* ms = SGX_CAST(ms_ocall_pointer_in_out_t*, pms);
	ocall_pointer_in_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_function_allow(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_function_allow();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_connect(void* pms)
{
	ms_ocall_mbedtls_net_connect_t* ms = SGX_CAST(ms_ocall_mbedtls_net_connect_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_connect(ms->ms_ctx, ms->ms_host, ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_bind(void* pms)
{
	ms_ocall_mbedtls_net_bind_t* ms = SGX_CAST(ms_ocall_mbedtls_net_bind_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_bind(ms->ms_ctx, ms->ms_bind_ip, ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_accept(void* pms)
{
	ms_ocall_mbedtls_net_accept_t* ms = SGX_CAST(ms_ocall_mbedtls_net_accept_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_accept(ms->ms_bind_ctx, ms->ms_client_ctx, ms->ms_client_ip, ms->ms_buf_size, ms->ms_ip_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_block(void* pms)
{
	ms_ocall_mbedtls_net_set_block_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_block_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_block(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_nonblock(void* pms)
{
	ms_ocall_mbedtls_net_set_nonblock_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_nonblock_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_nonblock(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_usleep(void* pms)
{
	ms_ocall_mbedtls_net_usleep_t* ms = SGX_CAST(ms_ocall_mbedtls_net_usleep_t*, pms);
	ocall_mbedtls_net_usleep(ms->ms_usec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv(void* pms)
{
	ms_ocall_mbedtls_net_recv_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv(ms->ms_ctx, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_send(void* pms)
{
	ms_ocall_mbedtls_net_send_t* ms = SGX_CAST(ms_ocall_mbedtls_net_send_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_send(ms->ms_ctx, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv_timeout(void* pms)
{
	ms_ocall_mbedtls_net_recv_timeout_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_timeout_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv_timeout(ms->ms_ctx, ms->ms_buf, ms->ms_len, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_free(void* pms)
{
	ms_ocall_mbedtls_net_free_t* ms = SGX_CAST(ms_ocall_mbedtls_net_free_t*, pms);
	ocall_mbedtls_net_free(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[26];
} ocall_table_Enclave = {
	26,
	{
		(void*)Enclave_ocall_uploadBucket,
		(void*)Enclave_ocall_downloadBucket,
		(void*)Enclave_ocall_downloadPath,
		(void*)Enclave_ocall_uploadPath,
		(void*)Enclave_ocall_buildFetchChildHash,
		(void*)Enclave_ocall_pointer_user_check,
		(void*)Enclave_ocall_pointer_in,
		(void*)Enclave_ocall_pointer_out,
		(void*)Enclave_ocall_pointer_in_out,
		(void*)Enclave_ocall_function_allow,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_ocall_mbedtls_net_connect,
		(void*)Enclave_ocall_mbedtls_net_bind,
		(void*)Enclave_ocall_mbedtls_net_accept,
		(void*)Enclave_ocall_mbedtls_net_set_block,
		(void*)Enclave_ocall_mbedtls_net_set_nonblock,
		(void*)Enclave_ocall_mbedtls_net_usleep,
		(void*)Enclave_ocall_mbedtls_net_recv,
		(void*)Enclave_ocall_mbedtls_net_send,
		(void*)Enclave_ocall_mbedtls_net_recv_timeout,
		(void*)Enclave_ocall_mbedtls_net_free,
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t ecall_createNewORAM(sgx_enclave_id_t eid, uint8_t* retval, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z)
{
	sgx_status_t status;
	ms_ecall_createNewORAM_t ms;
	ms.ms_max_blocks = max_blocks;
	ms.ms_data_size = data_size;
	ms.ms_stash_size = stash_size;
	ms.ms_recursion_data_size = recursion_data_size;
	ms.ms_recursion_levels = recursion_levels;
	ms.ms_Z = Z;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ssl_conn_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_ssl_connection_handler(sgx_enclave_id_t eid, long int thread_id, thread_info_t* thread_info)
{
	sgx_status_t status;
	ms_ecall_ssl_connection_handler_t ms;
	ms.ms_thread_id = thread_id;
	ms.ms_thread_info = thread_info;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val)
{
	sgx_status_t status;
	ms_ecall_type_char_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_ecall_type_int_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val)
{
	sgx_status_t status;
	ms_ecall_type_float_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val)
{
	sgx_status_t status;
	ms_ecall_type_double_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val)
{
	sgx_status_t status;
	ms_ecall_type_size_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val)
{
	sgx_status_t status;
	ms_ecall_type_wchar_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val)
{
	sgx_status_t status;
	ms_ecall_type_struct_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2)
{
	sgx_status_t status;
	ms_ecall_type_enum_union_t ms;
	ms.ms_val1 = val1;
	ms.ms_val2 = val2;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz)
{
	sgx_status_t status;
	ms_ecall_pointer_user_check_t ms;
	ms.ms_val = val;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_const_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_size_t ms;
	ms.ms_ptr = ptr;
	ms.ms_len = len;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, size_t cnt)
{
	sgx_status_t status;
	ms_ecall_pointer_count_t ms;
	ms.ms_arr = arr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_isptr_readonly_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_ecall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_function_public(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_function_private_t ms;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_malloc_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf)
{
	sgx_status_t status;
	ms_ecall_sgx_cpuid_t ms;
	ms.ms_cpuinfo = (int*)cpuinfo;
	ms.ms_leaf = leaf;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_exception(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_map(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_increase_counter(sgx_enclave_id_t eid, size_t* retval)
{
	sgx_status_t status;
	ms_ecall_increase_counter_t ms;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_producer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_consumer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 34, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 35, &ocall_table_Enclave, NULL);
	return status;
}

