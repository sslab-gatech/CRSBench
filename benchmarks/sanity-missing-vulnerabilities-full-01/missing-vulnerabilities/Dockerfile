FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/cp-c-missing-vulnerabilities.git missing-vulnerabilites

WORKDIR $SRC/missing-vulnerabilities

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc