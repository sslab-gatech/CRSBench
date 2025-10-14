# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM ghcr.io/aixcc-finals/base-builder-jvm:v1.3.0

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV TZ America/New_York
ENV USER root

RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-8-jdk
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        maven 
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

ENV KYLIN_HOME="/kylin_home"
ENV JAZZER_COMMAND_INJECTION="/kylin_home/bin/kylin.sh org.apache.kylin.tool.CubeMigrationCLI srcConfig destConfig null `jazze` false false true true"
COPY kylin_home $KYLIN_HOME
RUN chmod -R 0755 $KYLIN_HOME

#RUN git clone git@github.com:Team-Atlanta/cp-java-kylin-src.git $SRC/src/cp-java-kylin-src
COPY fuzz $SRC/src/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc

WORKDIR $SRC/src/cp-java-kylin-src
