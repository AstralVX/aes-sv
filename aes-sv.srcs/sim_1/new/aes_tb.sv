`timescale 1ns/1ns

// Configurable
//
/*`define MSG                     "This is a message we will encrypt with AES!\x00"
`define MSG_SIZE                44
`define AES_KEY                 8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06, 8'h07, 8'h08, 8'h09, 8'h0a, 8'h0b, 8'h0c, 8'h0d, 8'h0e, 8'h0f, 8'h10*/

// AES tests from NIST document SP800-38A
// For all ECB encrypts and decrypts, the transformed sequence is
//   AES-bits-ECB:key::plaintext:ciphertext:encdec
// ECB-AES128.Encrypt and ECB-AES128.Decrypt
// AES-128-ECB:2B7E151628AED2A6ABF7158809CF4F3C::6BC1BEE22E409F96E93D7E117393172A:3AD77BB40D7A3660A89ECAF32466EF97
`define MSG                     '{8'h6B, 8'hC1, 8'hBE, 8'hE2, 8'h2E, 8'h40, 8'h9F, 8'h96, 8'hE9, 8'h3D, 8'h7E, 8'h11, 8'h73, 8'h93, 8'h17, 8'h2A}
`define MSG_SIZE                16
`define AES_KEY                 8'h2B, 8'h7E, 8'h15, 8'h16, 8'h28, 8'hAE, 8'hD2, 8'hA6, 8'hAB, 8'hF7, 8'h15, 8'h88, 8'h09, 8'hCF, 8'h4F, 8'h3C
//

// Calculate 16 byte alignment of message, as AES128 requires 16 byte multiple as inputs
`define ALIGNED_MSG_SIZE        (($size(plaintext) + 8'd15) & ~(8'd15))
// Number of hardware instances of aesEncrypt (operating 16 bytes each)  
// Determines max size of plaintext that can be be processed
// e.g. if 10, it means max 10 x (4x4 matrix) created to operate on a max message of 160 bytes 
`define AES_HW_BLOCKS           (`ALIGNED_MSG_SIZE / 16)

module testbench(
);
    logic clk;
    logic rst;
    logic [7:0] cycles;
    logic [0:15] [7:0] key = '{`AES_KEY};
    logic [7:0] plaintext[`MSG_SIZE];
    logic [7:0] ciphertext[`ALIGNED_MSG_SIZE];

/*  logic [0:175] [7:0] expectedExpandedKey = '{
    8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06, 8'h07, 8'h08, 8'h09, 8'h0a, 8'h0b, 8'h0c, 8'h0d, 8'h0e, 8'h0f, 8'h10, 
    8'hab, 8'h74, 8'hc9, 8'hd3, 8'hae, 8'h72, 8'hce, 8'hdb, 8'ha7, 8'h78, 8'hc5, 8'hd7, 8'haa, 8'h76, 8'hca, 8'hc7, 
    8'h91, 8'h00, 8'h0f, 8'h7f, 8'h3f, 8'h72, 8'hc1, 8'ha4, 8'h98, 8'h0a, 8'h04, 8'h73, 8'h32, 8'h7c, 8'hce, 8'hb4, 
    8'h85, 8'h8b, 8'h82, 8'h5c, 8'hba, 8'hf9, 8'h43, 8'hf8, 8'h22, 8'hf3, 8'h47, 8'h8b, 8'h10, 8'h8f, 8'h89, 8'h3f, 
    8'hfe, 8'h2c, 8'hf7, 8'h96, 8'h44, 8'hd5, 8'hb4, 8'h6e, 8'h66, 8'h26, 8'hf3, 8'he5, 8'h76, 8'ha9, 8'h7a, 8'hda, 
    8'h3d, 8'hf6, 8'ha0, 8'hae, 8'h79, 8'h23, 8'h14, 8'hc0, 8'h1f, 8'h05, 8'he7, 8'h25, 8'h69, 8'hac, 8'h9d, 8'hff, 
    8'h8c, 8'ha8, 8'hb6, 8'h57, 8'hf5, 8'h8b, 8'ha2, 8'h97, 8'hea, 8'h8e, 8'h45, 8'hb2, 8'h83, 8'h22, 8'hd8, 8'h4d, 
    8'h5f, 8'hc9, 8'h55, 8'hbb, 8'haa, 8'h42, 8'hf7, 8'h2c, 8'h40, 8'hcc, 8'hb2, 8'h9e, 8'hc3, 8'hee, 8'h6a, 8'hd3, 
    8'hf7, 8'hcb, 8'h33, 8'h95, 8'h5d, 8'h89, 8'hc4, 8'hb9, 8'h1d, 8'h45, 8'h76, 8'h27, 8'hde, 8'hab, 8'h1c, 8'hf4, 
    8'h8e, 8'h57, 8'h8c, 8'h88, 8'hd3, 8'hde, 8'h48, 8'h31, 8'hce, 8'h9b, 8'h3e, 8'h16, 8'h10, 8'h30, 8'h22, 8'he2, 
    8'hbc, 8'hc4, 8'h14, 8'h42, 8'h6f, 8'h1a, 8'h5c, 8'h73, 8'ha1, 8'h81, 8'h62, 8'h65, 8'hb1, 8'hb1, 8'h40, 8'h87};
    
    logic [7:0] expectedAesEncryptBlock0 [0:15] = '{
    8'hB6, 8'h4B, 8'h27, 8'hBB, 8'h16, 8'h15, 8'hA6, 8'hF5, 8'h32, 8'h18, 8'h6C, 8'hC5, 8'hFA, 8'h94, 8'hB5, 8'h5E};
   
    logic [7:0] expectedCiphertext [0:`ALIGNED_MSG_SIZE-1] = '{
    8'hB6, 8'h4B, 8'h27, 8'hBB, 8'h16, 8'h15, 8'hA6, 8'hF5, 8'h32, 8'h18, 8'h6C, 8'hC5, 8'hFA, 8'h94, 8'hB5, 8'h5E, 
    8'h5C, 8'h54, 8'hEA, 8'h1B, 8'hDF, 8'h97, 8'h1E, 8'h3D, 8'hE3, 8'h1B, 8'hFC, 8'h02, 8'h75, 8'h22, 8'h76, 8'h52, 
    8'hD5, 8'h7B, 8'hD5, 8'h42, 8'hBA, 8'h0F, 8'h68, 8'h50, 8'hCD, 8'hFD, 8'h59, 8'hB8, 8'hEB, 8'h0E, 8'h83, 8'hD1}; */

    // AES tests from NIST document SP800-38A
    // Expected values
    logic [0:175] [7:0] expectedExpandedKey = '{
    8'h2b, 8'h7e, 8'h15, 8'h16, 8'h28, 8'hae, 8'hd2, 8'ha6, 8'hab, 8'hf7, 8'h15, 8'h88, 8'h09, 8'hcf, 8'h4f, 8'h3c, 
    8'ha0, 8'hfa, 8'hfe, 8'h17, 8'h88, 8'h54, 8'h2c, 8'hb1, 8'h23, 8'ha3, 8'h39, 8'h39, 8'h2a, 8'h6c, 8'h76, 8'h05,
    8'hf2, 8'hc2, 8'h95, 8'hf2, 8'h7a, 8'h96, 8'hb9, 8'h43, 8'h59, 8'h35, 8'h80, 8'h7a, 8'h73, 8'h59, 8'hf6, 8'h7f,
    8'h3d, 8'h80, 8'h47, 8'h7d, 8'h47, 8'h16, 8'hfe, 8'h3e, 8'h1e, 8'h23, 8'h7e, 8'h44, 8'h6d, 8'h7a, 8'h88, 8'h3b, 
    8'hef, 8'h44, 8'ha5, 8'h41, 8'ha8, 8'h52, 8'h5b, 8'h7f, 8'hb6, 8'h71, 8'h25, 8'h3b, 8'hdb, 8'h0b, 8'had, 8'h00, 
    8'hd4, 8'hd1, 8'hc6, 8'hf8, 8'h7c, 8'h83, 8'h9d, 8'h87, 8'hca, 8'hf2, 8'hb8, 8'hbc, 8'h11, 8'hf9, 8'h15, 8'hbc, 
    8'h6d, 8'h88, 8'ha3, 8'h7a, 8'h11, 8'h0b, 8'h3e, 8'hfd, 8'hdb, 8'hf9, 8'h86, 8'h41, 8'hca, 8'h00, 8'h93, 8'hfd, 
    8'h4e, 8'h54, 8'hf7, 8'h0e, 8'h5f, 8'h5f, 8'hc9, 8'hf3, 8'h84, 8'ha6, 8'h4f, 8'hb2, 8'h4e, 8'ha6, 8'hdc, 8'h4f, 
    8'hea, 8'hd2, 8'h73, 8'h21, 8'hb5, 8'h8d, 8'hba, 8'hd2, 8'h31, 8'h2b, 8'hf5, 8'h60, 8'h7f, 8'h8d, 8'h29, 8'h2f, 
    8'hac, 8'h77, 8'h66, 8'hf3, 8'h19, 8'hfa, 8'hdc, 8'h21, 8'h28, 8'hd1, 8'h29, 8'h41, 8'h57, 8'h5c, 8'h00, 8'h6e, 
    8'hd0, 8'h14, 8'hf9, 8'ha8, 8'hc9, 8'hee, 8'h25, 8'h89, 8'he1, 8'h3f, 8'h0c, 8'hc8, 8'hb6, 8'h63, 8'h0c, 8'ha6};
    
    logic [7:0] expectedAesEncryptBlock0 [0:15] = '{
    8'h3a, 8'hd7, 8'h7b, 8'hb4, 8'h0d, 8'h7a, 8'h36, 8'h60, 8'ha8, 8'h9e, 8'hca, 8'hf3, 8'h24, 8'h66, 8'hef, 8'h97};
    
    logic [7:0] expectedCiphertext [0:`ALIGNED_MSG_SIZE-1] = '{
    8'h3a, 8'hd7, 8'h7b, 8'hb4, 8'h0d, 8'h7a, 8'h36, 8'h60, 8'ha8, 8'h9e, 8'hca, 8'hf3, 8'h24, 8'h66, 8'hef, 8'h97}; 

    assign plaintext = `MSG;
    
    // Instantiate AES18 module to be tested
    top #(.MSG_SIZE(`MSG_SIZE), .ALIGNED_MSG_SIZE(`ALIGNED_MSG_SIZE), .AES_HW_BLOCKS(`AES_HW_BLOCKS))
        dut (plaintext, key, ciphertext);

    // Initialize test 
    initial begin
        cycles <= 0;
        rst <= 1; # 5; rst <= 0; 
    end

    // Generate clock to sequence tests
    always begin
        clk <= 1; # 5; clk <= 0; # 5;
        cycles <= cycles + 1; 
    end

    // Check results 
    always @(negedge clk) begin
        if (cycles >= 10) begin      
            // Verify key expansion
            for (int i=0; i<176; i=i+1) begin
                if (dut.expandedKey[i] !== expectedExpandedKey[i]) begin
                    $display("ERR - expanded key [%0d]: got %x, exp %x", i, dut.expandedKey[i], expectedExpandedKey[i]);
                    $stop;
                end
            end
            
            // Verify AES encrypt on first block of message
            if (dut.ciphertext_o[0:15] !== expectedAesEncryptBlock0) begin
                $write("ERR - AES encrypt block 0:");
                $write("\nGot: ");
                for (int i=0; i<16; i=i+1) begin
                    $write("%x ", dut.ciphertext_o[i]);
                end
                $write("\nExp: ");
                for (int i=0; i<16; i=i+1) begin
                    $write("%x ", expectedAesEncryptBlock0[i]);
                end
                $error("");
                $stop;
            end
            
            // Verify AES encrypt output with expected ciphertext
            if (dut.ciphertext_o !== expectedCiphertext) begin
                $write("ERR - AES encrypt block 0:");
                $write("\nGot: ");
                for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) begin
                    $write("%x ", dut.ciphertext_o[i]);
                end
                $write("\nExp: ");
                for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) begin
                    $write("%x ", expectedCiphertext[i]);
                end
                $error("");
                $stop;
            end
            
            $display("SUCCESS! All tests passed!\n");
            $write("Plaintext:  ");
            for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) $write("%x ", plaintext[i]);
            $write("| ");
            for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) $write("%c", plaintext[i]);
            $write("\nKey:        ");
            for (int i=0; i<16; i=i+1) $write("%x ", key[i]);
            $write("| ");
            for (int i=0; i<16; i=i+1) $write("%c", key[i]);
            $write("\nAesEncrypt: ");
            for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) begin
                //if ((i != 0) && (i % 16 == 0)) $write("\n");
                $write("%x ", dut.ciphertext_o[i]); 
            end
            $write("| ");
            for (int i=0; i<`ALIGNED_MSG_SIZE; i=i+1) begin
                //if ((i != 0) && (i % 16 == 0)) $write("\n");
                $write("%c", dut.ciphertext_o[i]); 
            end
            $write("\n\n");
            $stop;
           
        end
    end
endmodule
