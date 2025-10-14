FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

RUN apt-get update && apt-get install -y make autoconf automake libtool nasm curl cmake
#RUN git clone https://github.com/Team-Atlanta/cp-c-libjpeg.git libjpeg-turbo

RUN mkdir afl-testcases
RUN cd afl-testcases/ && curl -L http://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz | tar -xz
RUN zip libjpeg_turbo_fuzzer_seed_corpus.zip afl-testcases/jpeg/full/images/* afl-testcases/jpeg_turbo/full/images/* $SRC/libjpeg-turbo/testimages/*

WORKDIR libjpeg-turbo
COPY build.sh libjpeg_turbo_fuzzer.cc libjpeg_djpeg_fuzzer.cc libjpeg_djpeg_fuzzer.options $SRC/
COPY .aixcc $SRC/.aixcc