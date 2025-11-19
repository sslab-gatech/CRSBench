#include "auth.h"

extern "C" {
  #include "audio.h"
  #include "message.h"
  #include "user.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
    
  switch (data[0] % 3) {
    case 0:
      process_audio_data(data + 1, size - 1);
      break;
    case 1:
      process_message(data + 1, size - 1);
      break;
    case 2: {
      authenticate_user(data + 1, size - 1);
      break;
    }
  }
  
  return 0;
}
