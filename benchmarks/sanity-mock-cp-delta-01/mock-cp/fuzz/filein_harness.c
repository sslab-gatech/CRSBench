#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "../mock-cp-src/mock_vp.c"

int pipefd[2];

// Opens a pipe, dupes that over the stdin and writes the fuzz data there
int setup_pipe_data(const uint8_t *data, size_t size)
{
  ssize_t numBytes;
  int flags;

  if (pipe(pipefd) == -1) {
    perror("pipe");
    exit(-1);
  }

  // Write the data
  numBytes = write(pipefd[1], data, size);
  if (numBytes == -1) {
    perror("write");
    exit(-1);
  }

  // Set the read end of the pipe to non-blocking
  flags = fcntl(pipefd[0], F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl F_GETFL");
    exit(-1);
  }

  if (fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl F_SETFL");
    exit(-1);
  }

  // Dup the read end of the pipe over the client fd
  if (dup2(pipefd[0], STDIN_FILENO) == -1) {
    perror("dup2");
    return (EXIT_FAILURE);
  }

  __fpurge(stdin);
  clearerr(stdin);

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  setup_pipe_data(data, size);

  func_a();
  func_b();

  // Clean up the pipes
  close(pipefd[0]);
  close(pipefd[1]);

  return 0;
}