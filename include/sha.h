#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t

struct internal_state
{
    u32 A;
    u32 B;
    u32 C;
    u32 D;
    u32 E;
};

static void panic(const char* mex);


static void initialize_state(struct internal_state* s);

void print_state(struct internal_state& state);

std::string state_to_string(struct internal_state& state);


static u32 round_constants[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

u32 left_rotate(u32 word, u8 n);

//Converts a little endian word in a big endian
u32 to_big_endian(u32 val);

//Executes the 80 rounds of hashing of a 512 bits block
static void sha1_block(u32* block, struct internal_state* state);


//Computes the SHA1 Hash of a file of any size that will be padded to be multiple of 512 bits
struct internal_state sha1(u8* file, u32 size);