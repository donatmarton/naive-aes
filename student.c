// OPTIONS: -O3 -std=gnu99
#include "student.h"
#include <inttypes.h>
#include <stdlib.h>
// #include <string.h>

void addRoundKey(uint8_t*, uint8_t*);
void subBytes(uint8_t*);
void shiftRows(uint8_t*);
void mixColumns(uint8_t*);
uint8_t xtime(uint8_t);

uint8_t subBytesLookup[] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

void *aes128_init(void *key)
{
    uint8_t* pOriginalKey = key;
    uint8_t roundConstant[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    }; // the round constants as per standard, starting from round 1 to 10
    
    // allocate memory for storing all round keys
    uint8_t *pRoundKeys = (uint8_t*)malloc(11*16*sizeof(uint8_t));
    
    // the first round key is the original key itself
    // copy the 16 bytes of words 0..3 of round 0
    uint8_t i;
    for(i=0; i<16; ++i)
    {
        pRoundKeys[i] = pOriginalKey[i];
    }
    
    // expand keys for every round (rounds 1..10)
    uint8_t expandedRound;
    uint8_t actualKeyWord = 4; // the words 0..3 of round 0 are already done
    for(expandedRound = 1; expandedRound <= 10; ++expandedRound)
    {
        uint8_t * pWordMinusOne;
        uint8_t * pWordMinusFour;
        for(i=0;i<4;++i)
        {
            pWordMinusOne = &pRoundKeys[(actualKeyWord-1)*4];
            pWordMinusFour = &pRoundKeys[(actualKeyWord-4)*4];
            if(actualKeyWord % 4 == 0)
            {
                // rotate the word by a byte left
                uint8_t rotatedWord[4];
                rotatedWord[0] = pWordMinusOne[1];
                rotatedWord[1] = pWordMinusOne[2];
                rotatedWord[2] = pWordMinusOne[3];
                rotatedWord[3] = pWordMinusOne[0];
                
                // for every byte: s-box and XOR with round constant
                uint8_t *pSBoxedWord = (uint8_t*)malloc(4*sizeof(uint8_t)); 
                pSBoxedWord[0] = subBytesLookup[rotatedWord[0]] ^ roundConstant[expandedRound-1];
                pSBoxedWord[1] = subBytesLookup[rotatedWord[1]];
                pSBoxedWord[2] = subBytesLookup[rotatedWord[2]];
                pSBoxedWord[3] = subBytesLookup[rotatedWord[3]];
                
                pWordMinusOne = pSBoxedWord;
            }
            // w_i-1 XOR w_i-4
            pRoundKeys[(actualKeyWord)*4]   = pWordMinusOne[0] ^ pWordMinusFour[0];
            pRoundKeys[(actualKeyWord)*4+1] = pWordMinusOne[1] ^ pWordMinusFour[1];
            pRoundKeys[(actualKeyWord)*4+2] = pWordMinusOne[2] ^ pWordMinusFour[2];
            pRoundKeys[(actualKeyWord)*4+3] = pWordMinusOne[3] ^ pWordMinusFour[3];
            
            // if memory was allocated for transformation, free it
            if(actualKeyWord % 4 == 0)
            {
                free(pWordMinusOne);
            }
            
            // move on to processing the next key word of the actual round
            ++actualKeyWord;
        }
    }
    return pRoundKeys;
}

void aes128_encrypt(void *buffer, void *param)
{
    uint8_t* state = buffer;
    uint8_t* keys = param;
    
    // calculate first round
    addRoundKey(state, keys);
    
    // calculate rounds 1..9
    uint8_t i;
    for(i=1; i<=9; ++i)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, &keys[16*i]);
    }
    
    // calculate last round (10th)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, &keys[16*i]);
}

void addRoundKey(uint8_t* stateMatrix, uint8_t* roundKey)
{
    uint8_t i;
    for(i=0; i<16; ++i)
    {
        stateMatrix[i] = stateMatrix[i] ^ roundKey[i];
    }
}

void subBytes(uint8_t* stateMatrix)
{
    uint8_t i;
    for(i=0; i<16; ++i)
    {
        stateMatrix[i] = subBytesLookup[stateMatrix[i]];
    }
}

void shiftRows(uint8_t* stateMatrix)
{
    uint8_t temporaryByte;
    
    temporaryByte   = stateMatrix[1];
    stateMatrix[1]  = stateMatrix[5];
    stateMatrix[5]  = stateMatrix[9];
    stateMatrix[9]  = stateMatrix[13];
    stateMatrix[13] = temporaryByte;

    temporaryByte   = stateMatrix[2];
    stateMatrix[2]  = stateMatrix[10];
    stateMatrix[10] = temporaryByte;
    temporaryByte   = stateMatrix[6];
    stateMatrix[6]  = stateMatrix[14];
    stateMatrix[14] = temporaryByte;
    
    temporaryByte   = stateMatrix[15];
    stateMatrix[15] = stateMatrix[11];
    stateMatrix[11] = stateMatrix[7];
    stateMatrix[7]  = stateMatrix[3];
    stateMatrix[3]  = temporaryByte;    
}

void mixColumns(uint8_t* stateMatrix)
{
    uint8_t mixedStateMatrix[16];
    uint8_t i;
    for(i=0; i<4; ++i) // for every column
    {
        uint8_t ofs = 4*i; // the first byte index in the current column
        mixedStateMatrix[ofs] = 
                xtime(stateMatrix[ofs]) ^ 
                xtime(stateMatrix[ofs+1]) ^ stateMatrix[ofs+1] ^
                stateMatrix[ofs+2] ^ 
                stateMatrix[ofs+3];
        mixedStateMatrix[ofs+1] = 
                stateMatrix[ofs] ^ 
                xtime(stateMatrix[ofs+1]) ^
                xtime(stateMatrix[ofs+2]) ^ stateMatrix[ofs+2] ^
                stateMatrix[ofs+3];
        mixedStateMatrix[ofs+2] = 
                stateMatrix[ofs] ^ 
                stateMatrix[ofs+1] ^
                xtime(stateMatrix[ofs+2]) ^ 
                xtime(stateMatrix[ofs+3]) ^ stateMatrix[ofs+3];
        mixedStateMatrix[ofs+3] = 
                xtime(stateMatrix[ofs]) ^ stateMatrix[ofs] ^
                stateMatrix[ofs+1] ^
                stateMatrix[ofs+2] ^ 
                xtime(stateMatrix[ofs+3]);
    }
    for(i=0; i<16; ++i)
    {
        stateMatrix[i] = mixedStateMatrix[i];
    }
}

uint8_t xtime(uint8_t byte)
{
    uint8_t result;
    result = byte << 1;
    if (byte & 0x80)
        result ^= 0x1b;
    return result;
}