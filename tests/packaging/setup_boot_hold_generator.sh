#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
source_generator=$root_dir/packaging/systemd/nftfw-setup-boot-hold-generator
temporary=$(mktemp -d /tmp/nftfw-boot-hold-generator.XXXXXX)
cleanup() {
    find "$temporary" -depth -delete
}
trap cleanup EXIT

marker=$temporary/etc/nftfw/setup-boot-hold-v1
vendor_unit=$temporary/usr/lib/systemd/system/nftfw-setup-boot-hold.service
portable_unit=$temporary/etc/systemd/system/nftfw-setup-boot-hold.service
vendor_docker_unit=$temporary/usr/lib/systemd/system/nftfw-setup-docker-hold.service
portable_docker_unit=$temporary/etc/systemd/system/nftfw-setup-docker-hold.service
normal=$temporary/run/systemd/generator
fixture=$temporary/nftfw-setup-boot-hold-generator
install -d -m 0700 "$(dirname "$marker")" "$(dirname "$vendor_unit")" \
    "$(dirname "$portable_unit")" "$normal"
sed \
    -e "s#/etc/nftfw/setup-boot-hold-v1#$marker#g" \
    -e "s#/usr/lib/systemd/system/nftfw-setup-boot-hold.service#$vendor_unit#g" \
    -e "s#/etc/systemd/system/nftfw-setup-boot-hold.service#$portable_unit#g" \
    -e "s#/usr/lib/systemd/system/nftfw-setup-docker-hold.service#$vendor_docker_unit#g" \
    -e "s#/etc/systemd/system/nftfw-setup-docker-hold.service#$portable_docker_unit#g" \
    -e "s#/run/systemd/generator#$temporary/run/systemd/generator#g" \
    "$source_generator" >"$fixture"
chmod 0700 "$fixture"

link=$normal/network-pre.target.requires/nftfw-setup-boot-hold.service
"$fixture" "$normal" "$normal.early" "$normal.late"
[[ ! -e $link && ! -L $link ]] || {
    echo "absent boot-hold marker emitted a dependency" >&2
    exit 1
}

printf '%s\n' nftfw.setup-boot-hold.v1 >"$marker"
printf '%s\n' '[Service]' >"$vendor_unit"
printf '%s\n' '[Service]' >"$vendor_docker_unit"
"$fixture" "$normal" "$normal.early" "$normal.late"
[[ -L $link && $(readlink "$link") == "$vendor_unit" ]] || {
    echo "exact marker did not emit the packaged boot hold" >&2
    exit 1
}
expected_service_fragment='[Unit]
Requires=nftfw-setup-docker-hold.service
After=nftfw-setup-docker-hold.service'
expected_socket_fragment='[Unit]
Requires=nftfw-setup-docker-hold.service'
network_fragment=$normal/network.target.d/50-nftfw-setup-hold.conf
network_expected='[Unit]
Requires=network-pre.target
After=network-pre.target'
[[ -f $network_fragment && ! -L $network_fragment &&
    $(cat "$network_fragment") == "$network_expected" ]] || {
    echo "network target did not receive the exact pre-network hold" >&2
    exit 1
}
producer_expected='[Unit]
Requires=nftfw-setup-boot-hold.service
After=nftfw-setup-boot-hold.service'
for producer in NetworkManager.service dhcpcd.service dhcpcd@.service \
    ifup@.service networking.service systemd-networkd.service; do
    producer_fragment=$normal/$producer.d/50-nftfw-setup-hold.conf
    [[ -f $producer_fragment && ! -L $producer_fragment &&
        $(cat "$producer_fragment") == "$producer_expected" ]] || {
        echo "direct network producer did not receive the exact setup hold: $producer" >&2
        exit 1
    }
done
service_fragment=$normal/docker.service.d/50-nftfw-setup-hold.conf
socket_fragment=$normal/docker.socket.d/50-nftfw-setup-hold.conf
[[ -f $service_fragment && ! -L $service_fragment &&
    $(cat "$service_fragment") == "$expected_service_fragment" ]] || {
    echo "Docker service did not receive the exact ordered hold" >&2
    exit 1
}
[[ -f $socket_fragment && ! -L $socket_fragment &&
    $(cat "$socket_fragment") == "$expected_socket_fragment" ]] || {
    echo "Docker socket did not receive the nonblocking hold pull-in" >&2
    exit 1
}
! grep -Fqx 'After=nftfw-setup-docker-hold.service' "$socket_fragment" || {
    echo "Docker socket hold would deadlock sockets.target" >&2
    exit 1
}
"$fixture" "$normal" "$normal.early" "$normal.late"

printf '%s\n' foreign >"$network_fragment"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "foreign network hold fragment was accepted" >&2
    exit 1
fi
printf '%s\n' "$network_expected" >"$network_fragment"
rm -f -- "$network_fragment"
ln -s /foreign/fragment "$network_fragment"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "symlinked network hold fragment was accepted" >&2
    exit 1
fi
rm -f -- "$network_fragment"
printf '%s\n' "$network_expected" >"$network_fragment"

producer_fragment=$normal/ifup@.service.d/50-nftfw-setup-hold.conf
printf '%s\n' foreign >"$producer_fragment"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "foreign direct-producer hold fragment was accepted" >&2
    exit 1
fi
printf '%s\n' "$producer_expected" >"$producer_fragment"
rm -f -- "$normal/networking.service.d/50-nftfw-setup-hold.conf"
ln -s /foreign/fragment "$normal/networking.service.d/50-nftfw-setup-hold.conf"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "symlinked direct-producer hold fragment was accepted" >&2
    exit 1
fi
rm -f -- "$normal/networking.service.d/50-nftfw-setup-hold.conf"
printf '%s\n' "$producer_expected" >"$normal/networking.service.d/50-nftfw-setup-hold.conf"

docker_fragment=$service_fragment
printf '%s\n' foreign >"$docker_fragment"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "foreign Docker hold fragment was accepted" >&2
    exit 1
fi
printf '%s\n' "$expected_service_fragment" >"$docker_fragment"
rm -f -- "$socket_fragment"
ln -s /foreign/fragment "$socket_fragment"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "symlinked Docker hold fragment was accepted" >&2
    exit 1
fi
rm -f -- "$socket_fragment"
printf '%s\n' "$expected_socket_fragment" >"$socket_fragment"

rm -f -- "$link"
ln -s /foreign/unit "$link"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "foreign dependency link was accepted" >&2
    exit 1
fi
rm -f -- "$link"
printf '%s\n' collision >"$link"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "regular dependency collision was accepted" >&2
    exit 1
fi
rm -f -- "$link"

rm -f -- "$marker"
ln -s /missing/foreign-marker "$marker"
"$fixture" "$normal" "$normal.early" "$normal.late"
[[ -L $link && $(readlink "$link") == "$vendor_unit" ]] || {
    echo "unsafe marker did not fail closed into the boot hold" >&2
    exit 1
}
rm -f -- "$link" "$marker" "$vendor_unit"
printf '%s\n' '[Service]' >"$portable_unit"
printf '%s\n' nftfw.setup-boot-hold.v1 >"$marker"
"$fixture" "$normal" "$normal.early" "$normal.late"
[[ -L $link && $(readlink "$link") == "$portable_unit" ]] || {
    echo "portable service fallback was not selected exactly" >&2
    exit 1
}

if "$fixture" "$normal.evil/../outside" "$normal.early" "$normal.late"; then
    echo "unsafe generator output path was accepted" >&2
    exit 1
fi
rm -f -- "$link"
rmdir "$normal/network-pre.target.requires"
ln -s "$temporary" "$normal/network-pre.target.requires"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "symlinked generator dependency directory was accepted" >&2
    exit 1
fi

rm -f -- "$normal/network.target.d/50-nftfw-setup-hold.conf"
rmdir "$normal/network.target.d"
ln -s "$temporary" "$normal/network.target.d"
if "$fixture" "$normal" "$normal.early" "$normal.late"; then
    echo "symlinked network target drop-in directory was accepted" >&2
    exit 1
fi

echo "setup boot-hold generator fixture: PASS"
