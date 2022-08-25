#!/bin/bash

name=$(ip link | awk -F: '$0 ~ "eth*"{print $2;getline}')
if [ -z "$var" ];
then
	name=$(ip link | awk -F: '$0 ~ "wl*"{print $2;getline}')
fi

uploader=192.168.2.200
printf "Uploader: $uploader\n"
sudo ip addr add $uploader dev $name

declare -a peers=("192.168.2.101" "192.168.2.102" "192.168.2.103" "192.168.2.104" "192.168.2.105")
for (( i=0; i<${#peers[@]}; i++ ));
do
	printf "peer $i: ${peers[$i]}\n"
	sudo ip addr add ${peers[$i]} dev $name
done

