#!BuildTag: dump-privs:0.4.0
#!BuildTag: dump-privs:latest
#!BuildTag: dump-privs:0.4.0-%RELEASE%
#!UseOBSRepositories

FROM opensuse/tumbleweed:latest AS build-stage
WORKDIR /src
RUN zypper clean && zypper ref -f && zypper --non-interactive install --no-recommends gcc libselinux-devel
COPY dump-privs.c .
RUN gcc -Wall -O2 dump-privs.c -o dump-privs -lselinux

FROM opensuse/busybox:latest
LABEL maintainer="Thorsten Kukuk <kukuk@thkukuk.de>"
ARG BUILDTIME=
ARG VERSION=0.4.0
LABEL org.opencontainers.image.title="dump-privs container"
LABEL org.opencontainers.image.description="Container printing all relevant privileges of an application inside the container"
LABEL org.opencontainers.image.created=$BUILDTIME
LABEL org.opencontainers.image.version=$VERSION

COPY --from=build-stage /src/dump-privs /usr/bin
RUN chmod u+s,g+s /usr/bin/dump-privs
RUN adduser -S -D -H dump-privs
USER dump-privs
CMD ["dump-privs"]
