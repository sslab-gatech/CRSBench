#include "simple.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  target(data, size);
  return 0;
}
