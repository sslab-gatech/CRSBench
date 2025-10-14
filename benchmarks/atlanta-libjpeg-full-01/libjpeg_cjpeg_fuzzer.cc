#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <setjmp.h>

extern "C" {
  #include <jpeglib.h>
  #include "cdjpeg.h"
}

struct my_error_mgr {
  struct jpeg_error_mgr pub;
  jmp_buf env;
};

typedef struct my_error_mgr * my_err_ptr;

extern "C" void my_error_exit(j_common_ptr cinfo) {
  my_err_ptr err = (my_err_ptr)cinfo->err;
  longjmp(err->env, 1);
}

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;

  struct jpeg_compress_struct cinfo;
  struct my_error_mgr       jerr;

  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = my_error_exit;

  if (setjmp(jerr.env)) {
    jpeg_destroy_compress(&cinfo);
    return 0;
  }

  jpeg_create_compress(&cinfo);

  FILE *infile = fmemopen((void*)data, size, "rb");
  if (!infile) {
    jpeg_destroy_compress(&cinfo);
    return 0;
  }

  cinfo.in_color_space = JCS_RGB;
  jpeg_set_defaults(&cinfo);

  cjpeg_source_ptr src_mgr = jinit_read_bmp(&cinfo, TRUE);
  if (!src_mgr) {
    fclose(infile);
    jpeg_destroy_compress(&cinfo);
    return 0;
  }
  src_mgr->input_file = infile;

  src_mgr->start_input(&cinfo, src_mgr);

  jpeg_default_colorspace(&cinfo);

  unsigned char *outbuf = nullptr;
  unsigned long outsize = 0;
  jpeg_mem_dest(&cinfo, &outbuf, &outsize);

  jpeg_start_compress(&cinfo, TRUE);

  JSAMPARRAY buffer = src_mgr->buffer;
  while (cinfo.next_scanline < cinfo.image_height) {
    JDIMENSION rows = src_mgr->get_pixel_rows(&cinfo, src_mgr);
    (void)jpeg_write_scanlines(&cinfo, buffer, rows);
  }

  jpeg_finish_compress(&cinfo);
  jpeg_destroy_compress(&cinfo);
  fclose(infile);
  if (outbuf) free(outbuf);

  return 0;
}
