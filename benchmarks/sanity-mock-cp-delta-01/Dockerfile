FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/mock-cp-src.git

COPY pkgs/mock-cp-src.tar.gz $SRC/mock-cp-src.tar.gz
RUN tar -xzf $SRC/mock-cp-src.tar.gz -C $SRC/ && rm $SRC/mock-cp-src.tar.gz

WORKDIR $SRC/mock-cp-src

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc
