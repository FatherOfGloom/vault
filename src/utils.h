#ifndef _VAULT_UTILS
#define _VAULT_UTILS

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#define MAX_PATH_LEN _MAX_PATH

#define panic(...) do { fprintf(stderr, __VA_ARGS__); exit(0); } while (0)
#define todo() panic("panic at f:'%s' l:%d todo!", __FILE__, __LINE__)
#define nonnull(this) __extension__ ({ void* _ptr = (this); if (!_ptr) { panic("f:%s l:%d ERR: %s\n", __FILE__, __LINE__, "unwrap on a null value."); } _ptr; })
#define unwrap(this) __extension__ ({ size_t _this = (this); if (!_this) panic("f:%s l:%d ERR: %s\n", __FILE__, __LINE__, "unwrap failed."); _this; })

#define __check_str_literal(str_literal) ("" str_literal "")
#define __len(str_literal) ((sizeof(str_literal) / sizeof((str_literal)[0])) - sizeof((str_literal)[0]))
#define len(str_literal) (__len(__check_str_literal(str_literal))) 

#if defined(_WIN32) | defined(WIN32)
  #include <direct.h>
#else
  #error "TODO"
#endif

int get_absolute_path(char* out, char* in);

#endif // _VAULT_UTILS