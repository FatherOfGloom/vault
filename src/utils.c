#include "utils.h"

int get_absolute_path(char* out, char* in) {
    return _fullpath(out, in, MAX_PATH_LEN) != NULL;
}