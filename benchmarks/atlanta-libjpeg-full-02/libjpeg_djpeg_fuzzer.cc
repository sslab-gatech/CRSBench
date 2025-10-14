#include <stdio.h>
#include <cstddef>
#include <cstdint>
#include <setjmp.h>

extern "C" {
    #include <jpeglib.h>
    #include "cdjpeg.h"
}

struct my_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

typedef struct my_error_mgr* my_error_ptr;

extern "C" void my_error_exit(j_common_ptr cinfo) {
    my_error_ptr myerr = (my_error_ptr)cinfo->err;
    longjmp(myerr->setjmp_buffer, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 0) return 0;

    struct jpeg_decompress_struct cinfo;
    struct my_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;

    if (setjmp(jerr.setjmp_buffer)) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, const_cast<JOCTET*>(data), size);

    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    cinfo.quantize_colors = TRUE;
    cinfo.desired_number_of_colors = 256;

    djpeg_dest_ptr dest = jinit_write_bmp(&cinfo, FALSE, TRUE);
    if (!dest) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    jpeg_start_decompress(&cinfo);

    while (cinfo.output_scanline < cinfo.output_height) {
        JDIMENSION rows_read = jpeg_read_scanlines(
            &cinfo,
            dest->buffer,
            dest->buffer_height
        );
        dest->put_pixel_rows(&cinfo, dest, rows_read);
    }

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return 0;
}
