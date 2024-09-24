`timescale 1ns/1ns
`define AES_BLOCK_SIZE_BYTES    16

//
// In code info:
// If you see `logic [0:15] [7:0] ...` we are operating on a an AES block which is a 4x4 matrix (16 bytes)
// `Attribute: KEEP` - ignore linter warnings about unused lower bits; keeping logic and readability more straightforward
// Interchanged word usage: round key == matrix == 4x4 matrix
//

//
// The top module that instantiates the required amount of AesEncrypt modules to encrypt a message
//
// MSG_SIZE - size of the plaintext message
// ALIGNED_MSG_SIZE - AES block size alignment of plaintext message, i.e. 16 byte aligned
// AES_HW_BLOCKS - maximum number of simultaneous AesEncrypt() modules to handle encrypting plaintext
// msg_i - plaintext to be encrypted
// key_i - private AES key of size 16 bytes
// ciphertext_o - encrypted text on output, will be AES block size aligned
//
module top #(MSG_SIZE = 128, ALIGNED_MSG_SIZE = 128, AES_HW_BLOCKS = 8) (
    input  logic [7:0] msg_i[MSG_SIZE],
    input  logic [0:15] [7:0] key_i,
    output logic [7:0] ciphertext_o[ALIGNED_MSG_SIZE]
);
    logic [0:175] [7:0] expandedKey;    // Holds the expanded key of 10+1 rounds of key matrixes
    logic [7:0] plaintextPaddedAll [AES_HW_BLOCKS * `AES_BLOCK_SIZE_BYTES]; // Zero pad aligned array of paintext
    logic [7:0] ciphertextPaddedAll [AES_HW_BLOCKS * `AES_BLOCK_SIZE_BYTES];
    
    // Instantiate the keyexpansion hardware
    keyExpansion keyExpansion(key_i, expandedKey);

    // Right pad plaintext string with zeroes 
    always_comb begin
        plaintextPaddedAll = '{default:0};
        plaintextPaddedAll[0:$size(msg_i)-1] = msg_i;
    end
    
    // Instantiate a maximum number of aesEncrypt instances, each can process 16 bytes of plaintext
    generate for (genvar i=0; i<AES_HW_BLOCKS; i=i+1)
        begin : gen_aesEncrypt
            aesEncrypt aesEncrypt(plaintextPaddedAll[(i*16) : (i*16)+15], 
                                  expandedKey, ciphertext_o[(i*16) : (i*16)+15]);
        end
    endgenerate

endmodule

//
// Encrypts a message using 9 rounds of ECB AES-128 encryption and given expanded key
// Encryption process:
//   Round 0    : add round key
//   Round 1-10 : sub bytes with sbox, left shift rows, mix columns, add round key (previous round)
//   Round 11   : sub bytes with sbox, left shift rows, add round key (previous round)
//                n.b. last round has no mix columns, this to allow encryption/decryption scheme to be symetric
//
// msg_i - plaintext message to be encrypted
//         must be 16 byte aligned, with right zero padding if required
//         larger plaintext msgs must instantiate a new module to encrypt its 16 bytes
// expandedKey_i - entire 176 expanded key
// encMsg_o - an encrypted 16 bytes of message
//
module aesEncrypt(
    input  logic [7:0] msg_i [16],
    input  logic [0:175] [7:0] expandedKey_i,
    output logic [7:0] encMsg_o [16] 
);
    logic [0:15] [7:0] state;
    logic [0:15] [7:0] roundKey[11];
    logic [0:15] [7:0] addRoundKeyOut [11];
    logic [0:15] [7:0] subBytesOut [10];
    logic [0:15] [7:0] shiftRowsOut [10];
    logic [0:15] [7:0] mixColumnsOut [9];
        
    // Pack bytes for all subsequent operations
    assign state = {>>{msg_i}};
    
    // Setup initial round key
    assign roundKey[0] = expandedKey_i[0:15];
    addRoundKey addRoundKey1(state, roundKey[0], addRoundKeyOut[0]);
    
    // Encrypt using 9 rounds of keys
    generate for (genvar i=0; i<9; i=i+1)
        begin : gen_RoundLoop
            subBytes16 subBytes16(addRoundKeyOut[i], subBytesOut[i]);
            shiftRows shiftRows(subBytesOut[i], shiftRowsOut[i]);
            mixColumns mixColumns(shiftRowsOut[i], mixColumnsOut[i]);
            assign roundKey[i+1] = expandedKey_i[((i+1)*16):((i+1)*16)+15];
            addRoundKey addRoundKeyN(mixColumnsOut[i], roundKey[i+1], addRoundKeyOut[i+1]);
        end
    endgenerate

    // Final round of key encryption
    subBytes16 subBytes16(addRoundKeyOut[9], subBytesOut[9]);
    shiftRows shiftRows(subBytesOut[9], shiftRowsOut[9]);
    assign roundKey[9+1] = expandedKey_i[((9+1)*16):((9+1)*16)+15];
    addRoundKey addRoundKeyN(shiftRowsOut[9], roundKey[9+1], addRoundKeyOut[9+1]);

    // Unpack and retrurn the final round key as the 16 byte ciphertext
    assign {>>{encMsg_o}} = addRoundKeyOut[10];
endmodule

//
// Takes a 4x4 matrix and transforms it such that is represents the Galois Field (256) matrix of a polynomial 
// Algorthim: compute dot product of vectors of Galois fields, then reduction MOD 2 to fit into a byte
// https://en.wikipedia.org/wiki/Rijndael_MixColumns 
//
// state_i - a 4x4 matrix of state
// state_o - result 4x4 matrix after being mixed
//
module mixColumns(
    input  logic [0:15] [7:0] state_i,
    output logic [0:15] [7:0] state_o
);
    // Generate the mul2 and mul3 hardware, since the polynomial used is fixed in the dot product,
    // we can pre-calculate all possible values (lookup table) from 0-255 to speed up arithmetic and 
    // simplify to final addition (xor) logic 
    logic [0:15] [7:0] mul2Out;
    logic [0:15] [7:0] mul3Out;
    generate for (genvar i=0; i<16; i=i+1)
        begin : gen_mul2mul3
            mul2 mul2(state_i[i], mul2Out[i]);
            mul3 mul3(state_i[i], mul3Out[i]);
        end
    endgenerate
    
    // Column 1 entries
    assign state_o[0]  = (mul2Out[0] ^ mul3Out[1] ^ state_i[2] ^ state_i[3]);
    assign state_o[1]  = (state_i[0] ^ mul2Out[1] ^ mul3Out[2] ^ state_i[3]);
    assign state_o[2]  = (state_i[0] ^ state_i[1] ^ mul2Out[2] ^ mul3Out[3]);
    assign state_o[3]  = (mul3Out[0] ^ state_i[1] ^ state_i[2] ^ mul2Out[3]);
    
    // Column 2 entries
    assign state_o[4]  = (mul2Out[4] ^ mul3Out[5] ^ state_i[6] ^ state_i[7]);
    assign state_o[5]  = (state_i[4] ^ mul2Out[5] ^ mul3Out[6] ^ state_i[7]);
    assign state_o[6]  = (state_i[4] ^ state_i[5] ^ mul2Out[6] ^ mul3Out[7]);
    assign state_o[7]  = (mul3Out[4] ^ state_i[5] ^ state_i[6] ^ mul2Out[7]);
    
    // Column 3 entries
    assign state_o[8]  = (mul2Out[8] ^ mul3Out[9] ^ state_i[10] ^ state_i[11]);
    assign state_o[9]  = (state_i[8] ^ mul2Out[9] ^ mul3Out[10] ^ state_i[11]);
    assign state_o[10] = (state_i[8] ^ state_i[9] ^ mul2Out[10] ^ mul3Out[11]);
    assign state_o[11] = (mul3Out[8] ^ state_i[9] ^ state_i[10] ^ mul2Out[11]);
    
    // Column 4 entries
    assign state_o[12] = (mul2Out[12] ^ mul3Out[13] ^ state_i[14] ^ state_i[15]);
    assign state_o[13] = (state_i[12] ^ mul2Out[13] ^ mul3Out[14] ^ state_i[15]);
    assign state_o[14] = (state_i[12] ^ state_i[13] ^ mul2Out[14] ^ mul3Out[15]);
    assign state_o[15] = (mul3Out[12] ^ state_i[13] ^ state_i[14] ^ mul2Out[15]);
endmodule

//
// Shift each row in a 4x4 matrix to the left based on row number
// e.g. row 0 shift left 0
//      row 1 shift left once
//      row 2 shift left twice
//      row 3 shift left thrice
//
// N.b. shiftRows and mixColumns introduces diffision into AES, which disguises properties of the plaintext message
//
// state_i - a 4x4 matrix of state
// state_o - result 4x4 matrix after being shifted
// 
module shiftRows(
    input  logic [0:15] [7:0] state_i,
    output logic [0:15] [7:0] state_o
);
    // First row don't shift
    assign state_o[0] = state_i[0];
    assign state_o[4] = state_i[4];
    assign state_o[8] = state_i[8];
    assign state_o[12] = state_i[12];
    
    // Second row shift left 1
    assign state_o[1] = state_i[5];
    assign state_o[5] = state_i[9];
    assign state_o[9] = state_i[13];
    assign state_o[13] = state_i[1];
    
    // Third row shift left 2
    assign state_o[2] = state_i[10];
    assign state_o[6] = state_i[14];
    assign state_o[10] = state_i[2];
    assign state_o[14] = state_i[6];
    
    // Fourth row shift left 3
    assign state_o[3] = state_i[15];
    assign state_o[7] = state_i[3];
    assign state_o[11] = state_i[7];
    assign state_o[15] = state_i[11];
endmodule

//
// State and round key (as polynomials) are added as Galois fields
// Arithmetic used is binary addition MOD 2
// Simplifys down to XOR
//
// state_i - a 4x4 matrix
// roundKey_i - a round key
// state_o - the xor result
//
module addRoundKey(
    input  logic [0:15] [7:0] state_i,
    input  logic [0:15] [7:0] roundKey_i,
    output logic [0:15] [7:0] state_o
); 
    always_comb begin
        for (int i=0; i<16; i=i+1) begin
            state_o[i] = state_i[i] ^ roundKey_i[i];
        end
    end
endmodule

//
// AES key expansion - a key schedule algorithm that calculates 11 round keys from the user supplied 16 byte AES private key
//
// Algorithim:
//   Initial key: copy AES key into expanded key as initial round
//   Round constants: use a set of round constants in the key expansion module
//   Key schedule: generate all 11 round keys 
//   Expansion rounds: perform expansion core algorithim on first word of every round key
//
// key_i - input AES key of 16 bytes
// expandedKey_o - sequentially stored 11 round keys as 176 bytes 
// done_o - set high on completition of expanded key, otherwise low
//
module keyExpansion(
    input  logic [0:15] [7:0] key_i,
    output logic [0:175] [7:0] expandedKey_o,
    output logic done_o
);
    // Attribute: KEEP - don't optimize these signals and keep unused bits, to simplify logic and make readable
    (*KEEP="TRUE"*)logic [0:159] [7:0] prevRoundkey;    // Temporarily holds the set of all 10 round keys (except last)
    (*KEEP="TRUE"*)int ekByteOffset;                    // Byte offset into the expanded key
    (*KEEP="TRUE"*)int pmByteOffset;                    // Byte offset into prevRoundkey

    // Initial round key is the AES key itself
    assign expandedKey_o[0:15] = key_i[0:15];
    
    // Generate the per round expansionRoundCore hardware instances that operates on first word of every matrix
    logic [0:3] [7:0] coreWordIn [10];
    logic [0:3] [7:0] coreWordOut [10];
    generate for (genvar i=0; i<10; i=i+1)
        begin : gen_expansionRoundCore
            expansionRoundCore expansionRoundCore(coreWordIn[i], i[7:0] + 1'b1, coreWordOut[i]);
        end
    endgenerate

    // Key schedule
    always_comb begin
        done_o = 0;
        // For each of the 10 rounds, calculate a round key
        for (int round=0; round<10; round=round+1) begin
            for (int row=0; row<4; row=row+1) begin
                // Based on the round and row calculate the current expanded key byte offset,
                // add 16 byte offset since we assigned initial round key outside
                ekByteOffset = `AES_BLOCK_SIZE_BYTES + (round*`AES_BLOCK_SIZE_BYTES) + (row*4);
                // Byte offset into previous round ke 
                pmByteOffset = (round*`AES_BLOCK_SIZE_BYTES) + (row*4);
                
                // Read last 4 bytes of the previous round key
                prevRoundkey[pmByteOffset+0] = expandedKey_o[ekByteOffset + 0 - 4];
                prevRoundkey[pmByteOffset+1] = expandedKey_o[ekByteOffset + 1 - 4];
                prevRoundkey[pmByteOffset+2] = expandedKey_o[ekByteOffset + 2 - 4];
                prevRoundkey[pmByteOffset+3] = expandedKey_o[ekByteOffset + 3 - 4];
            
                // Word 0: perform the expansion round on the first word of each round key, 
                //         by setting the expansionRoundCore input, then XOR
                if (row == 0) begin
                    coreWordIn[round] = {prevRoundkey[pmByteOffset+0], 
                                         prevRoundkey[pmByteOffset+1], 
                                         prevRoundkey[pmByteOffset+2], 
                                         prevRoundkey[pmByteOffset+3]};
                                         
                    expandedKey_o[ekByteOffset + 0] = expandedKey_o[ekByteOffset + 0 - 16] ^ coreWordOut[round][0];
                    expandedKey_o[ekByteOffset + 1] = expandedKey_o[ekByteOffset + 1 - 16] ^ coreWordOut[round][1];
                    expandedKey_o[ekByteOffset + 2] = expandedKey_o[ekByteOffset + 2 - 16] ^ coreWordOut[round][2];
                    expandedKey_o[ekByteOffset + 3] = expandedKey_o[ekByteOffset + 3 - 16] ^ coreWordOut[round][3];
                end
                // Word 1-3: just XOR with previous round key's corresponding row
                else begin
                    expandedKey_o[ekByteOffset + 0] = expandedKey_o[ekByteOffset + 0 - 16] ^ prevRoundkey[pmByteOffset+0];
                    expandedKey_o[ekByteOffset + 1] = expandedKey_o[ekByteOffset + 1 - 16] ^ prevRoundkey[pmByteOffset+1];
                    expandedKey_o[ekByteOffset + 2] = expandedKey_o[ekByteOffset + 2 - 16] ^ prevRoundkey[pmByteOffset+2];
                    expandedKey_o[ekByteOffset + 3] = expandedKey_o[ekByteOffset + 3 - 16] ^ prevRoundkey[pmByteOffset+3];
                end
            end
        end
        done_o = 1;
    end  
endmodule

//
// The expansion round algorithim operates on the first word in every round key matrix
// N.b. used in AES to increase difficulty of cryptanaltyic attacks 
// 
// bytes_i - first word in a matrix
// rconIdx_i - rcon lookup table index to be XORed with  
// bytes_o - resultant expanded word
//
module expansionRoundCore(
    input  logic [0:3] [7:0] bytes_i,
    input  logic [7:0] rconIdx_i,
    output logic [0:3] [7:0] bytes_o
);
    logic [0:3] [7:0] rotatedBytes;
    logic [0:3] [7:0] subbedBytes;
    logic [7:0] rconByte;
    
    // Left rotate bytes
    rotateLeft rotateLeft(bytes_i, rotatedBytes);
    
    // Substitue with sbox
    subBytes4 subBytes4(rotatedBytes, subbedBytes);
    
    // Get round constant 
    rcon rcon(rconIdx_i, rconByte);
    
    // XOR sbox byte0 with rcon
    assign bytes_o[0] = subbedBytes[0] ^ rconByte;
    assign bytes_o[1] = subbedBytes[1];
    assign bytes_o[2] = subbedBytes[2];
    assign bytes_o[3] = subbedBytes[3];
endmodule

//
// Rotate left by 32 bits
//
module rotateLeft(
    input  logic [0:3] [7:0] byte_i,
    output logic [0:3] [7:0] byte_o 
); 
    assign byte_o = (byte_i << 8) | (byte_i >> 24);
endmodule

//
// Substitute a matrix (4 words .. 16 bytes) as indexes into S-box lookup
//
// byte_i - 16 bytes of indexes into lookup table
// byte_o - result of indexes into lookup table
//
// Operate on a 4x4 matrix
module subBytes16(
    input  logic [0:15] [7:0] byte_i,
    output logic [0:15] [7:0] byte_o
);
    subBytes4 subWord0 (byte_i[0:3], byte_o[0:3]);
    subBytes4 subWord1 (byte_i[4:7], byte_o[4:7]);
    subBytes4 subWord2 (byte_i[8:11], byte_o[8:11]);
    subBytes4 subWord3 (byte_i[12:15], byte_o[12:15]);
endmodule

//
// Substitute a word (4 bytes) as indexes into S-box lookup
//
// byte_i - 4 bytes of indexes into lookup table
// byte_o - result of indexes into lookup table
//
module subBytes4(
    input  logic [0:3] [7:0] byte_i,
    output logic [0:3] [7:0] byte_o 
);
    subByte subByte0(byte_i[0], byte_o[0]);
    subByte subByte1(byte_i[1], byte_o[1]);
    subByte subByte2(byte_i[2], byte_o[2]);
    subByte subByte3(byte_i[3], byte_o[3]);
endmodule

//
// Substitue a byte index with the S-box lookup
//
// byte_i - byte index into lookup table
// byte_o - result of index into lookup table
//
module subByte(
    input logic [7:0] byte_i,
    output logic [7:0] byte_o
);
    sbox sbox(byte_i, byte_o);
endmodule
