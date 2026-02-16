FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

#RUN git clone git@github.com:Team-Atlanta/simple-switch.git

COPY pkgs/simple-switch.tar.gz $SRC/simple-switch.tar.gz
RUN tar -xzf $SRC/simple-switch.tar.gz -C $SRC/ && rm $SRC/simple-switch.tar.gz

WORKDIR $SRC/simple-switch

COPY fuzz $SRC/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc
