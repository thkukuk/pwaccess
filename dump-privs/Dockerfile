FROM opensuse/tumbleweed:latest AS builder
WORKDIR /app
RUN zypper --non-interactive install gcc libselinux-devel
COPY dump-privs.c .
RUN gcc -Wall -O2 dump-privs.c -o dump-privs -lselinux

FROM opensuse/busybox:latest
COPY --from=builder /app/dump-privs /usr/bin
RUN chmod u+s,g+s /usr/bin/dump-privs
RUN adduser -S -D -H dump-privs
USER dump-privs
CMD ["dump-privs"]
