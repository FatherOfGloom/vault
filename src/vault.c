#include "vault.h"
#include "../thirdparty/rapidhash/rapidhash.h"

#include <stdbool.h>

StrSlice str_slice_alloc(Arena* a, size_t capacity) {
    char* ptr = arena_alloc(a, capacity);
    return (StrSlice){.ptr = ptr, .len = capacity};
}

void str_slice_print(StrSlice* s) {
    printf("%.*s", (int)unwrap(s->len), (char*)nonnull(s->ptr));
}

StrSlice str_slice_from(Slice s) {
    return (StrSlice){.ptr = s.ptr, .len = s.len};
}

size_t vault_metadata_size_bytes(VaultMetadata* metadata) {
    return sizeof(metadata->payload_len) 
        + sizeof(metadata->psw_hash) 
        + sizeof(metadata->version);
}

File file_open(const char* __restrict__ file_name,
                             const char* __restrict__ mode) {
    return (File){.handle = nonnull(fopen(file_name, mode))};
}

int file_size(File* file, size_t* size) {
    long saved = ftell(file->handle);
    if (saved < 0) return errno;
    if (fseek(file->handle, 0, SEEK_END) < 0) return errno;
    long result = ftell(file->handle);
    if (result < 0) return errno;
    if (fseek(file->handle, saved, SEEK_SET) < 0) return errno;
    *size = (size_t)result;
    return 0;
}

int file_read_alloc(Arena* a, File* file, Slice* buffer) {
    size_t size_bytes = 0;

    int err = file_size(file, &size_bytes);

    if (err != 0) return err;

    *buffer = slice_alloc(a, size_bytes);

    fread(buffer->ptr, buffer->len, 1, file->handle);

    if (ferror(file->handle)) return errno;

    return 0;
}

int file_write(File* file, Slice* buffer) {
    fwrite(buffer->ptr, 1, buffer->len, file->handle);
    if (ferror(file->handle)) return errno;

    return 0;
}

int file_close(File* file) {
    if (file->handle == NULL) return 0;
    int result = fclose(file->handle);
    file->handle = NULL;
    return result;
}

Slice slice_alloc(Arena* a, size_t capacity) {
    void* ptr = arena_alloc(a, capacity);
    return (Slice){.ptr = ptr, .len = capacity};
}

Slice slice_cstr_clone(Arena* a, const char* cstr, size_t len) {
    void* ptr = arena_alloc(a, len);
    Slice result = (Slice){.ptr = ptr, .len = len};
    (void)memcpy(ptr, cstr, len);
    return result;
}

Slice slice_cstr_copy(char* cstr, size_t len) {
    return (Slice){.ptr = cstr, .len = len};
}

uint64_t vault_hash(const void* key, size_t len) {
    return rapidhash(key, len);
}

Reader reader_new(Slice* buffer) {
    return (Reader){.buffer = buffer, .pivot = 0};
}

uint8_t reader_try_read_slice(Reader* r, Slice* dst_buffer, size_t bytes_to_read) {
    uint8_t* ptr = (uint8_t*)r->buffer->ptr + r->pivot;
    
    uint8_t has_space = (uintptr_t)bytes_to_read + (uintptr_t)ptr <
                        (uintptr_t)r->buffer->ptr + (uintptr_t)r->buffer->len;

    if (!has_space) {
        return false;
    }

    *dst_buffer = (Slice) {.ptr = ptr, .len = bytes_to_read};

    r->pivot += bytes_to_read;

    return true;
}

uint8_t reader_try_read(Reader* r, void* dst_ptr, size_t bytes_to_read) {
    uint8_t* ptr = (uint8_t*)r->buffer->ptr + r->pivot;

    uint8_t has_space = (uintptr_t)bytes_to_read + (uintptr_t)ptr <
                        (uintptr_t)r->buffer->ptr + (uintptr_t)r->buffer->len;

    if (!has_space) {
        return false;
    }

    memcpy(dst_ptr, ptr, bytes_to_read);
    r->pivot += bytes_to_read;

    return true;
}

vault_parse_err_t vault_parse(Vault* v, Slice* raw_data) {
    // Vault contents:
    // 2 bytes  -> version
    // 8 bytes  -> password hash
    // 4 bytes  -> payload len in bytes
    // N bytes  -> payload
    Reader reader = reader_new(raw_data);
    
    uint16_t version_be = 0;
    uint64_t password_hash_be = 0;
    uint32_t payload_len_be = 0;

    if (!reader_try_read(&reader, &version_be, sizeof(version_be))) {
        return VAULT_PARSE_ERR_NONE;
    }

    v->metadata.version = ntohs(version_be);

    if (VAULT_VERSION != v->metadata.version) {
        return VAULT_PARSE_ERR_VERSION;
    }

    if (!reader_try_read(&reader, &password_hash_be, sizeof(password_hash_be))) {
        return VAULT_PARSE_ERR_NONE;
    }

    v->metadata.psw_hash = ntohll(password_hash_be);
    v->metadata.is_password_set = true;

    if (!reader_try_read(&reader, &payload_len_be, sizeof(payload_len_be))) {
        return VAULT_PARSE_ERR_NONE;
    }

    v->metadata.payload_len = ntohl(payload_len_be);

    Slice payload = {0};

    if (!reader_try_read_slice(&reader, &payload, v->metadata.payload_len)) {
        return VAULT_PARSE_ERR_INCORRECT_PAYLOAD_LEN;
    }

    v->payload = payload;
    v->is_empty_payload = false;

    return VAULT_PARSE_ERR_NONE;
}

Vault vault_init(char* file_path, vault_parse_err_t* err) {
    *err = VAULT_PARSE_ERR_NONE;
    Vault vault = {0};
    vault.is_empty_payload = true;
    vault.metadata.is_password_set = false;

    char absolute_file_path_cstr[MAX_PATH_LEN] = {0};
    assert(get_absolute_path(absolute_file_path_cstr, file_path));

    uint64_t file_path_hash = vault_hash(absolute_file_path_cstr, MAX_PATH_LEN);

    StrSlice absolute_file_path = str_slice_alloc(&vault.arena, MAX_PATH_LEN + sizeof(file_path_hash) + 1);

    (void)snprintf(
        absolute_file_path.ptr, 
        absolute_file_path.len,
        "%s\\%llu",
        absolute_file_path_cstr, 
        file_path_hash
    );

    vault.absolute_file_path = absolute_file_path;
    int file_exists = access(absolute_file_path.ptr, F_OK) == 0;

#ifdef VAULT_DEBUG
    printf("hash: %llu\n", file_path_hash);
    printf("new file_path: %s\n", absolute_file_path.ptr);
    printf("file exists: %s\n", file_exists ? "true" : "false");
#endif  // VAULT_DEBUG

    File file = {0};
    
    if (file_exists) {
        file = file_open(absolute_file_path.ptr, "r");
        Slice raw_contents = {0};
        assert(file_read_alloc(&vault.arena, &file, &raw_contents) == 0);
        *err = vault_parse(&vault, &raw_contents);
        file_close(&file);
    } else {
        if (vault.is_empty_payload) {
            vault.metadata.version = VAULT_VERSION;
        }
    }

    return vault;
}

void vault_free(Vault* v) {
    arena_free(&v->arena);
}

void writer_write(Writer* w, Slice src) {
    void* offset_ptr = (uint8_t*)w->buffer->ptr + w->pivot;
    (void)memcpy(offset_ptr, src.ptr, src.len);
    w->pivot += src.len;
}

Writer writer_new(Slice* buffer) {
    return (Writer){.buffer = buffer, .pivot = 0};
}

void vault_write_to_file(Vault* v) {
    File file = {0};
    file = file_open(v->absolute_file_path.ptr, "wb");

    Slice buffer = slice_alloc(
        &v->arena,
        vault_metadata_size_bytes(&v->metadata) 
    );

    v->metadata.payload_len = v->payload.len;

    Writer writer = writer_new(&buffer);

    uint16_t version = htons(v->metadata.version);
    uint64_t psw_hash = htonll(v->metadata.psw_hash);
    uint32_t payload_len = htonl(v->metadata.payload_len);
    writer_write(&writer, slice(version));
    writer_write(&writer, slice(psw_hash));
    writer_write(&writer, slice(payload_len));

    file_write(&file, &buffer);
    file_write(&file, &v->payload);
    file_close(&file);
}

void vault_set_password_hash(Vault* v, uint64_t new_psw_hash) {
    v->metadata.psw_hash = new_psw_hash;
    v->metadata.is_password_set = true;
}

Slice vault_decrypt_payload(Vault* v, uint8_t is_allocate_new_payload, Slice key) {
    assert(!v->is_empty_payload);
    assert(v->metadata.is_password_set);

    Slice decrypted_payload = {0};
    uint32_t payload_len = v->metadata.payload_len;

    if (is_allocate_new_payload) {
        decrypted_payload = slice_alloc(&v->arena, payload_len);
    } else {
        decrypted_payload = v->payload;
    }

    vault_decrypt_ex(&v->payload, &decrypted_payload, key);

    return decrypted_payload;
}

void vault_decrypt_ex(Slice* src_buffer, Slice* dst_buffer, Slice key) {
    assert(src_buffer->len);
    assert(dst_buffer->len);
    assert(src_buffer->len == dst_buffer->len);
    uint8_t* dst_ptr = dst_buffer->ptr;
    uint8_t* src_ptr = src_buffer->ptr;

    for (size_t i = 0; i < dst_buffer->len; ++i) {
        dst_ptr[i] = src_ptr[i] ^ *((uint8_t*)key.ptr + (i % key.len));
    }
}