#ifndef FUZZER_TOOL_H
#define FUZZER_TOOL_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#define HALF_BYTE ((sizeof(uint8_t) * 8 * 8) / 2)

const uint8_t *get_word(const uint8_t *, size_t);
char *extract_word(const uint8_t **, size_t *);
int get_fuzzed_argv(const char *, const uint8_t *, size_t ,
                    char***, int *, const uint8_t **, size_t *);
int create_input_file(char **, const uint8_t **, size_t *);
void remove_file(char *);
void free_arguments(int, char **);

#endif /* FUZZER_TOOL_H */
