#ifndef ARENA_H_
#define ARENA_H_

#include <stddef.h>
#include <assert.h>

#ifndef ARENA_DEFAULT_ALIGNMENT
  #define ARENA_DEFAULT_ALIGNMENT (2 * sizeof(void*))
#endif

#ifndef ARENA_DEFAULT_CAP
  #define ARENA_DEFAULT_CAP (8 * 1024)
#endif 

typedef struct ArenaChunk {
    struct ArenaChunk* next;
    size_t len;
    size_t cap;
    char memory[];
} ArenaChunk;

ArenaChunk* arena_chunk_alloc(size_t size_bytes);

typedef struct Arena {
    ArenaChunk* start;
    ArenaChunk* end;
} Arena;

void* arena_alloc(Arena* a, size_t size_bytes);
void* arena_alloc_aligned(Arena* a, size_t size_bytes, size_t alignment);
void arena_free(Arena* a);
void arena_reset(Arena* a);

#endif // ARENA_H_