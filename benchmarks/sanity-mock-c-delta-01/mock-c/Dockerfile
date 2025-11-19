FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/mock-c.git

WORKDIR $SRC/mock-c

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc