#ifndef _VAULT
#define _VAULT

#include "utils.h"
#define ARENA_IMPLEMENTATION  
#include "arena.h"
#include <stdint.h>

#if defined(_WIN32) | defined(WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#define VAULT_VERSION 1

typedef struct Slice {
    void* ptr;
    size_t len;
} Slice;

Slice slice_alloc(Arena* a, size_t capacity);
Slice slice_cstr_clone(Arena* a, const char* cstr, size_t len);
Slice slice_cstr_copy(char* cstr, size_t len);

typedef struct StrSlice {
    char* ptr;
    size_t len;
} StrSlice;

StrSlice str_slice_from(Slice s);
StrSlice str_slice_alloc(Arena* a, size_t capacity);
StrSlice str_slice_copy(const char* src);
StrSlice str_slice_clone(Arena* a, const char* src);
void str_slice_append(StrSlice* dst, StrSlice src, size_t idx); 
void str_slice_print(StrSlice* s);
StrSlice str_slice_from(Slice s);

// Vault contents: 
// 2 bytes  -> version
// 8 bytes  -> password hash
// 4 bytes  -> payload len in bytes
// N bytes  -> payload
typedef struct VaultMetadata {
    uint64_t psw_hash;
    uint32_t payload_len;
    uint16_t version;
    uint8_t is_password_set;
} VaultMetadata;

size_t vault_metadata_size_bytes(VaultMetadata* metadata);

typedef struct Vault {
    StrSlice absolute_file_path;
    VaultMetadata metadata;
    Arena arena;
    Slice payload;
    uint8_t is_empty_payload;
} Vault;

#define VAULT_PARSE_ERR_NONE 0
#define VAULT_PARSE_ERR_VERSION 1
#define VAULT_PARSE_ERR_INCORRECT_PAYLOAD_LEN 2

typedef uint8_t vault_parse_err_t;

vault_parse_err_t vault_parse(Vault* v, Slice* raw_data);
Vault vault_init(char* file_path, uint8_t* err);
void vault_free(Vault* v);
uint64_t vault_hash(const void* key, size_t len);
void vault_write_to_file(Vault* v);
void vault_set_password_hash(Vault* v, uint64_t new_psw_hash);
Slice vault_decrypt_payload(Vault* v, uint8_t is_allocate_new_payload, Slice key);
void vault_decrypt_ex(Slice* src_buffer, Slice* dst_buffer, Slice key);

typedef struct File {
    FILE* handle;
    size_t file_size;
} File;

File file_open(const char* __restrict__ file_name,
                             const char* __restrict__ mode);
int file_size(File* file, size_t* size);

typedef struct Reader {
    Slice* buffer;
    size_t pivot;
} Reader;

Reader reader_new(Slice* buffer);
uint8_t reader_try_read_slice(Reader* r, Slice* dst_buffer, size_t bytes_to_read);
uint8_t reader_try_read(Reader* r, void* dst_ptr, size_t bytes_to_read);

#if defined(__GNUC__) || defined(__clang__)
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define ntohll(x) __builtin_bswap64(x)
    #define htonll(x) __builtin_bswap64(x)
  #else
    #define ntohll(x) (x)
    #define htonll(x) (x)
  #endif
#else
  #error "LOL"
#endif

#define slice(x) ((Slice){.ptr = &(x), .len = sizeof(x)})

typedef struct Writer {
    Slice* buffer;
    size_t pivot;
} Writer;

void writer_write(Writer* w, Slice src);
Writer writer_new(Slice* buffer);

#endif  // _VAULT