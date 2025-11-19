FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/cp-user-itoa.git

WORKDIR $SRC/cp-user-itoa

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc