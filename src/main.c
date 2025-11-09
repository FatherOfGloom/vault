#define ARENA_LOG
#define VAULT_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include "vault.h"

static const char* const usage =
    "Usage:\n" 
    "vault \t\t\t\t-> tells whether you have a password set\n" 
    "vault [password] \t\t-> prints vault contents\n" 
    "vault [password] [new-entry] \t-> adds a line to your vault\n";

static inline void vault_print(const char* msg) {
    printf("vault: %s", msg); 
}

char* vault_parse_err_to_cstr(vault_parse_err_t err) {
    switch (err) {
        case VAULT_PARSE_ERR_NONE:
            return "None";
        case VAULT_PARSE_ERR_VERSION:
            return "Incompatible version";
        case VAULT_PARSE_ERR_INCORRECT_PAYLOAD_LEN:
            return "Incorrect payload length metadata";
        default:
            return "Unknown error";
    }
}

// TODO: move utils.* to vault.*
// TODO: make arena into a single file library
int main(int argc, char** argv) {
    vault_parse_err_t parse_err = VAULT_PARSE_ERR_NONE;

    switch (argc - 1) {
        case 0: {
            Vault vault = vault_init(".", &parse_err);

            if (parse_err != VAULT_PARSE_ERR_NONE) {
                panic("Unable to open vault due to an error: '%s'\n", vault_parse_err_to_cstr(parse_err));
            }

            if (vault.metadata.is_password_set) {
                vault_print("You have a password set\n\n");
            } else {
                vault_print("In order to use vault you need to set a password\n\n");
            }

            printf(usage);
        } break;
        case 1: {
            Vault vault = vault_init(".", &parse_err);

            if (parse_err != VAULT_PARSE_ERR_NONE) {
                panic("Unable to open vault due to an error: '%s'\n", vault_parse_err_to_cstr(parse_err));
            }

            Slice input_password = slice_cstr_copy(argv[1], strlen(argv[1]));

            if (input_password.len < 5) {
                panic("Your password should contain at least 5 characters\n");
            }

            uint64_t input_password_hash =
                vault_hash(input_password.ptr, input_password.len);

            if (vault.metadata.is_password_set) {
                if (vault.metadata.psw_hash == input_password_hash) {
                    if (vault.is_empty_payload) {
                        vault_print("Vault is empty");
                    } else {
                        StrSlice decrypted_payload = str_slice_from(vault_decrypt_payload(&vault, false, input_password));

                        str_slice_print(&decrypted_payload);
                    }
                } else {
                    panic("Incorrect password.\n");
                }
            } else {
                vault_set_password_hash(&vault, input_password_hash);
                vault_write_to_file(&vault);
            }
        } break;
        case 2: {
            Vault vault = vault_init(".", &parse_err);

            if (parse_err != VAULT_PARSE_ERR_NONE) {
                panic("Unable to open vault due to an error: '%s'\n", vault_parse_err_to_cstr(parse_err));
            }

            Slice input_password = slice_cstr_copy(argv[1], strlen(argv[1]));
            uint64_t input_password_hash = vault_hash(input_password.ptr, input_password.len);
            Slice new_entry = slice_cstr_clone(&vault.arena, argv[2], strlen(argv[2]));

            if (vault.metadata.is_password_set) {
                if (vault.metadata.psw_hash == input_password_hash) {
                    Slice new_payload_buffer = slice_alloc(&vault.arena, new_entry.len + vault.payload.len + 1);
                    Writer writer = writer_new(&new_payload_buffer);

                    if (!vault.is_empty_payload) {
                        vault_decrypt_ex(&vault.payload, &vault.payload, input_password);
                        writer_write(&writer, vault.payload);
                    }

                    writer_write(&writer, new_entry);
                    writer_write(&writer, slicestr("\n"));

                    vault_decrypt_ex(&new_payload_buffer, &new_payload_buffer, input_password);
                    vault.payload = new_payload_buffer;
                    vault_write_to_file(&vault);
                } else {
                    panic("Incorrect password.\n");
                } 
            } else {
                panic("In order to use vault you need to set a password\n");
            }
        } break;
        default:
            panic(usage);
    }

    return 0;
}