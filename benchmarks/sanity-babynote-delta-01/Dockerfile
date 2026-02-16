FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/cp-user-babynote-src.git

COPY pkgs/cp-user-babynote-src.tar.gz $SRC/cp-user-babynote-src.tar.gz
RUN tar -xzf $SRC/cp-user-babynote-src.tar.gz -C $SRC/ && rm $SRC/cp-user-babynote-src.tar.gz

WORKDIR $SRC/cp-user-babynote-src

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY filein_harness.options $SRC/filein_harness.options
COPY .aixcc $SRC/.aixcc
