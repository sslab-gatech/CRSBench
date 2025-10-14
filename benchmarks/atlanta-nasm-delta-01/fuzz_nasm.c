#include "fuzz_nasm.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int nasm_main(int argc, char **argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char input_filename[256];
    char *output_filename = "/dev/null";
    sprintf(input_filename, "/tmp/libfuzzer.%d", getpid());
    
    FILE *fp = fopen(input_filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);
    // Prepare arguments for nasm_main
    char *argv[] = {
        "nasm",  // Program name
        input_filename,    // Input file
        "-o",    // Output flag
        output_filename,  // output to /dev/null
        "-Z",
        output_filename, // error to /dev/null
    };
    int argc = 6;
    //return 0;
    // Call nasm_main with the arguments
    stopoptions = false;
    if (inname) {
        nasm_free((void *)inname);
        inname = NULL;
    }
    // inname = 0;
    outname = 0;
    depend_file = 0;
    _passn = 0;
    globalrel = 0;
    globalbnd = 0;
    listname = 0;
    errname = 0;
    globallineno = 0;
    dfmt = 0;
    error_file = 0;
    ofile = 0;
    offsets = 0;
    forwrefs = 0;
    include_path = 0;
    depend_list = 0;
    depend_target = 0;
    
    
    nasm_main(argc, argv);
    

    // Clean up
    unlink(input_filename);
    return 0;
}
