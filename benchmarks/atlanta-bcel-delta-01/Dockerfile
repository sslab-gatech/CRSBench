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

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        maven

# Install sdk man
RUN curl -s "https://get.sdkman.io" | bash
RUN ["/bin/bash", "-c", "source $HOME/.sdkman/bin/sdkman-init.sh && sdk install java 17.0.11-tem"]
RUN ["/bin/bash", "-c", "source $HOME/.sdkman/bin/sdkman-init.sh && sdk install gradle 8.9"]
RUN ["/bin/bash", "-c", "source $HOME/.sdkman/bin/sdkman-init.sh && sdk install maven 3.9.6"]

ENV MVN=/usr/bin/mvn

#RUN git clone git@github.com:Team-Atlanta/cp-java-bcel-source.git $SRC/src/cp-java-bcel-source
COPY fuzz $SRC/src/fuzz
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc

WORKDIR $SRC/src/cp-java-bcel-source
