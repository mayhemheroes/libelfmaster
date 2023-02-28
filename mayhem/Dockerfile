FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

WORKDIR /repo/utils
RUN gcc stripx.c -o stripx
RUN clang++ /repo/mayhem/fuzz_elf_open_object.cpp -fsanitize=fuzzer,address -I /install/include/ /install/lib/libelfmaster.a -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /install /install
COPY --from=builder /repo/utils/stripx /
COPY --from=builder /fuzz /fuzz_elf_open_object
