FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

WORKDIR /repo/utils
RUN gcc stripx.c -o stripx

FROM ubuntu:20.04 as package
COPY --from=builder /install /install
COPY --from=builder /repo/utils/stripx /
