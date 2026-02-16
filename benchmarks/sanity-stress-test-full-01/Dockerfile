FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

# git clone git@github.com:Team-Atlanta/cp-user-stress-test-src.git

COPY pkgs/cp-user-stress-test-src.tar.gz $SRC/cp-user-stress-test-src.tar.gz
RUN tar -xzf $SRC/cp-user-stress-test-src.tar.gz -C $SRC/ && rm $SRC/cp-user-stress-test-src.tar.gz

WORKDIR $SRC/cp-user-stress-test-src

COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc
