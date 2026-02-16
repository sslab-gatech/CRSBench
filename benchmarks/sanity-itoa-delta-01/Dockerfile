FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/cp-user-itoa.git

COPY pkgs/cp-user-itoa.tar.gz $SRC/cp-user-itoa.tar.gz
RUN tar -xzf $SRC/cp-user-itoa.tar.gz -C $SRC/ && rm $SRC/cp-user-itoa.tar.gz

WORKDIR $SRC/cp-user-itoa

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc
