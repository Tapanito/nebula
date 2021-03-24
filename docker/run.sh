set -e

NEBULA_CERT="../nebula-cert"
NEBULA="../nebula"

nodes=(lighthouse host1 host2 host3 host4)

function certificate() {
  printf "Generating $1 certificates...\n"

  $NEBULA_CERT sign -name "$1" \
    -out-crt "$1"/cert.crt \
    -out-key "$1"/pk.key \
    -ip 192.168.0."$2"/24
  cp ca.crt "$1"/
}

# Generate root certificates if they do not exist
if ! [ -f "ca.crt" ]; then
  printf "Creating root certificate...\n"
  $NEBULA_CERT ca -name "Foo..."
fi

# Create the docker network if it does not exist
docker network create --subnet=172.20.0.0/24 nebula || true
docker kill "${nodes[@]}" > /dev/null || true

for i in "${!nodes[@]}"; do
  node="${nodes[$i]}"
  rm -rf "$node"
  mkdir -p "$node"
  certificate "$node" $(("$i" + 1))
	printf "Copying $node config to work dir...\n"
  cp "$node".yml "$node"/config.yml
  cp "$NEBULA" "$node"/
	docker run --detach --rm --name "$node" \
	-v "$(pwd)"/"$node":/"$node" -w /"$node" \
	--cap-add=NET_ADMIN  --device /dev/net/tun --net nebula \
	nebula /"$node"/nebula --config /"$node"/config.yml

done
