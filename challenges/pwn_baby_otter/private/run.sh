#!/bin/sh

# Port to which the task will be exposed
PORT=${1-1337}

# No spaces here
NAME="pwn-baby-otter"

# Build task docker image
cd private
docker build \
    -t ${NAME} \
    -f Dockerfile \
    --build-arg FLAG='justCTF{w3lc0me_in_the_l3ague_of_Otter!}' \
    .

# NOTE:
# The options below are generally INSECURE. We use them as we use nsjail anyway.
# Docker is used just for easier bootstraping of nsjail, i.e.:
# - to have a non-host chroot (and consistent environment) for jailed processes/tasks
# - to be able to run task with one command, assuming docker is installed on machine
#
# We need:
# - CHOWN, SETUID, SETGID, AUDIT_WRITE - to use `su -l jailed ...`
# - CAP_DAC_OVERRIDE - so that we can access files in /nix/... like nsjail binary
# - SYS_ADMIN and CHOWN to prepare (mount) cgrops for nsjail
# - no apparmor and no seccomp to prepare cgroups and to spawn jails
# --cgroupns=host so that nsjail can setup cgroups v2 properly
#
# Note:
# - we do not use apparmor in nsjail
# - nsjail allows us to specify a seccomp policy, but we do not do that most of the time

docker rm -f ${NAME} || true
docker run -d \
    --restart=always \
    --name=${NAME} \
    --privileged \
    -p $PORT:31337 \
    ${NAME}
