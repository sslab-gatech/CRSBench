FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/cp-tkctf-rpn-calculator-source.git

WORKDIR $SRC/cp-tkctf-rpn-calculator-source

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc