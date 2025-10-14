FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

RUN apt-get update && apt-get install -y make autoconf automake libtool bison flex

#RUN git clone git@github.com:Team-Atlanta/cp-user-libcue-src.git libcue

WORKDIR $SRC/libcue

COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc