#!/bin/bash
# This is the main entrypoint for this tool. Please consult the README and/or run:
#
# ssh-vpn.sh -h
#
# While the hooks are designed very modularly, this script is meant to be very standalone. The
# purpose of this script is to create the initial layer 3 adjacency circuit over SSH. That circuit
# is the foundation for any other configuration to take place.
#
# One of the reasons this was written in bash is that it was desireable for this to run on
# low-powered embedded Linux systems with minimal flash. In such systems, one cannot count on higher
# level programming languages, like python, to be present. However, most all of these systems have
# some kind of POSIX shell, usually bash or ash.  Either of these shells will work for setting up a
# base layer3 adjacency circuit.
#
# Given that the base circuit is all that is needed, it is desireable for a low powered system to be
# able to wget or curl down a single script that can easily establish that connection.
#
# So these goals are the reasons that this script is self-contained while, contrastly, the hooks
# examples are very modular.
#
set -e

# Uncomment the below line to debug
# set -x

##################################
#######CONFIGURATION BLOCK########
##################################
CONFIGURED=0

# The remote host must host sshd and be reachable via IP by this host. This can be an IPv4 or IPv6
# address or a fully qualified domain name as long as the name is resolvable.
REMOTE_HOST='<changeme>'

# The port on which SSH is listenting on the remote host. This can be null. If it is null, the
# default port, TCP/22, is assumed.
REMOTE_PORT=

# The username that can be used to authenticate to sshd on the remote.
REMOTE_USER='<changeme>'

# This is the file path to the SSH private key to use for authentication to the remote host. This
# can be null. If null, then normal SSH key discovery applies.
PRIVATE_KEY_PATH=

# The tunnel interface number really doesn't matter except that it must NOT already be in use.
# ssh-vpn.sh makes a feeble attempt to avoid other tun devices by setting the default to 21. Note
# the BASIC DIAGRAM above; the 21 defined here is integer in tun21 on Host B. This value must be
# a positive integer or 0.
REMOTE_TUNNEL_INTERFACE=21

# Remote address must be on the same subnet as local. This address will be assigned to the remote
# tun interface to establish direct IPv4 connectivity between the hosts. Refer to the BASIC DIAGRAM;
# this IP address will be assigned to the tun0 interface on Host B.
REMOTE_TUNNEL_ADDRESS='172.18.2.2'

# Subnet mask of tunnel link in CIDR notation. Valid values are 1 - 31; though sensible values range
# from 24 - 30. For a point-to-point tunnel (which is what we're creating here), 30 is probably the
# best value because a subnetwork with a 30 bit mask has 2 usable IP addresses. That said, those who
# are sharp with bit math likely thought, "Wait, 30 bits? That has 4 addresses." You are correct,
# but the first address is the network address which is not usable for hosts and the last address is
# the broadcast address which is also not usable for host assignment.
TUNNEL_CIDR='30'

# Local address must be on the same subnet as remote. This address will be assigned to the local run
# interface to establish direct IPv4 connectivity between the hosts. Refer to the BASIC DIAGRAM; this
# IP address will be assinged to the tun0 interface on Host A.
LOCAL_TUNNEL_ADDRESS='172.18.2.1'

# The tunnel interface number really doesn't matter except that it must NOT already be in use.
# ssh-vpn.sh makes a feeble attempt to avoid other tun devices by setting the default to 21. Note
# the BASIC DIAGRAM above; the 21 defined here is the integer in tun21 on Host A. This value must be
# a positive integer or 0.
LOCAL_TUNNEL_INTERFACE=21

# The number of ping packets to send when checking the connection to determine if it is up. The more
# ping packets that are sent means the longer these checks take. Each increment of this value adds
# approximately 1 second to the check time. If you want the check to return more quickly, reduce
# this number. This value MUST be an integer greater than 0.
PING_COUNT=1

# TODO: add logging
# Log facility
# Use a valid syslog facility. Please see man 1 logger for more information.
# Please note that when debugging scripts, your best source of information is by uncommenting the
# set -x line at the top of the file.
LOG_FACILITY="local0"

####################################
#####END OF CONFIGURATION BLOCK#####
####################################

PRIVATE_KEY_OPTIONS=

if [ ! -z "${PRIVATE_KEY_PATH}" ]; then
	PRIVATE_KEY_OPTIONS="-i ${PRIVATE_KEY_PATH}"
fi

if [ -z "${REMOTE_PORT}" ]; then
	REMOTE_PORT=22
fi

if [ -z "${PING_COUNT}" ]; then
	PING_COUNT=3
fi

if [ "${PING_COUNT}" -lt 1 ]; then
	PING_COUNT=1
fi

if [ -z "${REMOTE_HOST}" ] || \
   [ -z "${REMOTE_USER}" ] || \
   [ -z "${REMOTE_TUNNEL_ADDRESS}" ] || \
   [ -z "${LOCAL_TUNNEL_ADDRESS}" ] || \
   [ -z "${TUNNEL_CIDR}" ]; then
	>&2 echo "Configuration required. Please open ssh-vpn.sh in an editor."
	exit 1
fi

function do_remote_command() {
	# Abstraction for doing RPC over SSH
	# Will use a control socket if it exists; however, it will not create it.
    if [ -z "${PRIVATE_KEY_PATH}" ]; then
        ssh -p "${REMOTE_PORT}" -S "${HOME}/.ssh/%C" "${REMOTE_USER}"@"${REMOTE_HOST}" $@
		SSH_EXIT_CODE=$?
    else
        ssh -i "${PRIVATE_KEY_PATH}" -p "${REMOTE_PORT}" -S "${HOME}/.ssh/%C" "${REMOTE_USER}"@"${REMOTE_HOST}" $@
		SSH_EXIT_CODE=$?
    fi
	return ${SSH_EXIT_CODE}
}

function check_tunnel_support() {
	set +e

	# Determine if both ends support tun interfaecs
	ls /dev/net/tun > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "Local does not support tun. You may try loading the module with modprobe."
	else
		echo "Local supports tun."
	fi

	do_remote_command ls /dev/net/tun > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "Remote does not support tun. You may try loading the module with modprobe."
	else
		echo "Remote supports tun."
	fi

	PERMIT_TUNNEL=
	PERMIT_TUNNEL=$(do_remote_command "find /etc/ -type f -name sshd_config -exec egrep '^PermitTunnel[[:space:]]yes$' {} \;")
	if [ -z "${PERMIT_TUNNEL}" ]; then
		echo "Remote sshd does not support tunnels. Please configure PermitTunnel yes in sshd_config."
	else
		echo "Remote ssh supports tunnels."
	fi

	set -e
}

function attempt_enable_tunnel_support(){
	set +e
	check_tunnel_support | grep 'does not support' > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		do_remote_command modprobe tun > /dev/null 2>&1
		modprobe tun > /dev/null 2>&1

		check_tunnel_support | grep 'does not support' > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			echo "Attempt to enable tunnel support failed. Please run check-tunnel-support for more information."
			set -e
			return 1
		fi
	fi
	set -e
	return 0

}

function discover_mtu() {
	# ARGS: $1 = Integer : Maximum PAYLOAD : Example: 1472
	#		$2 = source interface
	#
	# Assuming a customary MTU of 1500 bytes, the maximum payload would caluculate as follows:
	# 1500 - IP encapsulation (20) - ICMP encapsulation (8) = 1472
	#
	# Therefore, if we can transmit a 1472 byte payload without fragmentation, but not a 1473 byte
	# payload, then the MTU is 1500 bytes.

	ICMP_ENCAP=8
	IP_ENCAP=20

	HIGH=$1
	SOURCE_IFACE=$2
	PAYLOAD="${HIGH}"
	LOW=1
	LAST_SUCCESS=0

	set +e
	until [ ${LOW} -gt ${HIGH} ]; do

		ping -I "${SOURCE_IFACE}" -c 1 -W 500 -M do -s "${PAYLOAD}" "${REMOTE_TUNNEL_ADDRESS}" > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			LAST_SUCCESS=${PAYLOAD}
			LOW=$(($PAYLOAD + 1))
		else
			HIGH=$(($PAYLOAD - 1))
		fi

		PAYLOAD=$((($HIGH + $LOW) / 2))

	done
	set -e

	echo $(($LAST_SUCCESS + $ICMP_ENCAP + $IP_ENCAP))
	if [ ${LAST_SUCCESS} -eq 0 ]; then
		return 1
	fi
	return 0
}

function up () {
	set +e
	ping -I tun"${LOCAL_TUNNEL_INTERFACE}" -c 1 "${REMOTE_TUNNEL_ADDRESS}" > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "VPN is already up."
		exit 0
	fi
	set -e

	echo "Attempting to enable tun support on both hosts."
	attempt_enable_tunnel_support
	if [ $? -ne 0 ]; then
		exit 1
	fi
	set -e

	if [ -f ./hooks/$0.pre_up ]; then
		echo "Running pre_up script."
		./hooks/$0.pre_up \
			"${REMOTE_USER}" \
			"${REMOTE_HOST}" \
			"${REMOTE_PORT}" \
			"${LOCAL_TUNNEL_INTERFACE}" \
			"${LOCAL_TUNNEL_ADDRESS}" \
			"${REMOTE_TUNNEL_INTERFACE}" \
			"${REMOTE_TUNNEL_ADDRESS}" \
			"${PRIVATE_KEY_PATH}" \
			"${LOG_FACILITY}"
		echo "pre_up script executed."
	fi

	# Create the tunnel
	# We don't use do_remote_command here because we have additional ssh options to provide.
	if [ ! -z "${PRIVATE_KEY_OPTIONS}" ]; then
		ssh "${PRIVATE_KEY_OPTIONS}" -p "${REMOTE_PORT}" -o ExitOnForwardFailure=yes -o ControlPersist=yes -o ControlMaster=auto -S "${HOME}/.ssh/%C" -Nf -w "${LOCAL_TUNNEL_INTERFACE}":"${REMOTE_TUNNEL_INTERFACE}" "${REMOTE_USER}"@"${REMOTE_HOST}"
	else
		ssh -p "${REMOTE_PORT}" -o ExitOnForwardFailure=yes -o ControlPersist=yes -o ControlMaster=auto -S "${HOME}/.ssh/%C" -Nf -w "${LOCAL_TUNNEL_INTERFACE}":"${REMOTE_TUNNEL_INTERFACE}" "${REMOTE_USER}"@"${REMOTE_HOST}"
	fi

	# Configure local tunnel IP
	ip address add "${LOCAL_TUNNEL_ADDRESS}/${TUNNEL_CIDR}" dev tun"${LOCAL_TUNNEL_INTERFACE}"
	ip link set tun"${LOCAL_TUNNEL_INTERFACE}" up

	# Configure remote tunnel IP
	do_remote_command ip address add "${REMOTE_TUNNEL_ADDRESS}/${TUNNEL_CIDR}" dev tun"${REMOTE_TUNNEL_INTERFACE}"
	do_remote_command ip link set tun"${REMOTE_TUNNEL_INTERFACE}" up

	# Ensure connectivity at layer 3
	ping -I tun"${LOCAL_TUNNEL_INTERFACE}" -c "${PING_COUNT}" "${REMOTE_TUNNEL_ADDRESS}"
	if [ $? -eq 0 ]; then
		echo "Tunnel is up".
	fi

	echo "Finding and setting MTU."
	TUNNEL_MTU="$(discover_mtu 1472 tun${LOCAL_TUNNEL_INTERFACE})"
	ip link set mtu "${TUNNEL_MTU}" dev tun"${LOCAL_TUNNEL_INTERFACE}"
	do_remote_command ip link set mtu "${TUNNEL_MTU}" dev tun"${REMOTE_TUNNEL_INTERFACE}"
	echo "MTU found and set to ${TUNNEL_MTU}."

	echo "VPN is up."

	if [ -f ./hooks/$0.post_up ]; then
		echo "Running post_up script."
		./hooks/$0.post_up \
			"${REMOTE_USER}" \
			"${REMOTE_HOST}" \
			"${REMOTE_PORT}" \
			"${LOCAL_TUNNEL_INTERFACE}" \
			"${LOCAL_TUNNEL_ADDRESS}" \
			"${REMOTE_TUNNEL_INTERFACE}" \
			"${REMOTE_TUNNEL_ADDRESS}" \
			"${PRIVATE_KEY_PATH}" \
			"${LOG_FACILITY}"
		echo "post_up script executed."
	fi
}

function down() {
	# Running "-O stop" kills the local process but leaves the remote sshd-forked process alive.
	# If we kill the client process, the cleanup happens automatically on the remote.

	#ssh -O stop -S "${HOME}/.ssh/%C" "${REMOTE_USER}"@"${REMOTE_HOST}" > /dev/null 2>&1

	if [ -f ./hooks/$0.pre_down ]; then
	echo "Running pre_down script."
		./hooks/$0.pre_down \
			"${REMOTE_USER}" \
			"${REMOTE_HOST}" \
			"${REMOTE_PORT}" \
			"${LOCAL_TUNNEL_INTERFACE}" \
			"${LOCAL_TUNNEL_ADDRESS}" \
			"${REMOTE_TUNNEL_INTERFACE}" \
			"${REMOTE_TUNNEL_ADDRESS}" \
			"${PRIVATE_KEY_PATH}" \
			"${LOG_FACILITY}"
	echo "pre_down script executed."
	fi

	set +e
	ssh -p "${REMOTE_PORT}" -S /root/.ssh/%C -O check ${REMOTE_USER}@${REMOTE_HOST} > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		kill "$(ssh -p "${REMOTE_PORT}" -S /root/.ssh/%C -O check ${REMOTE_USER}@${REMOTE_HOST} 2>&1 | egrep -o '[0-9]{1,5}')"
	else
		echo "Unable to communicate with control socket. Maybe the VPN is already down?"
		exit 1
	fi
	set -e

	echo "VPN is down."

	if [ -f ./hooks/$0.post_down ]; then
	echo "Running post_down script."
		./hooks/$0.post_down \
			"${REMOTE_USER}" \
			"${REMOTE_HOST}" \
			"${REMOTE_PORT}" \
			"${LOCAL_TUNNEL_INTERFACE}" \
			"${LOCAL_TUNNEL_ADDRESS}" \
			"${REMOTE_TUNNEL_INTERFACE}" \
			"${REMOTE_TUNNEL_ADDRESS}" \
			"${PRIVATE_KEY_PATH}" \
			"${LOG_FACILITY}"
	echo "post_down script executed."
	fi
}

function status() {
	set +e
	if [ "$1" == "verbose" ]; then
		# When verbose we'll override PING_COUNT if < 5 and print the last line of the ping output
		if [ "${PING_COUNT}" -lt 5 ]; then
			PING_COUNT=5
		fi
		ping -I tun"${LOCAL_TUNNEL_INTERFACE}" -c "${PING_COUNT}" "${REMOTE_TUNNEL_ADDRESS}" | awk 'END {print $0}'
		PING_EXIT_CODE=$?
	else
		ping -I tun"${LOCAL_TUNNEL_INTERFACE}" -c "${PING_COUNT}" "${REMOTE_TUNNEL_ADDRESS}" > /dev/null 2>&1
		PING_EXIT_CODE=$?
	fi
	set -e

	if [ ${PING_EXIT_CODE} -ne 0 ]; then
		echo "VPN is down."
	else
		echo "VPN is up."

		# We'll also call a hook script for checking the status of the particular application of the
		# VPN if the user defined one.
		if [ -f hooks/$0.status ]; then
			./hooks/$0.status \
				"${REMOTE_USER}" \
				"${REMOTE_HOST}" \
				"${REMOTE_PORT}" \
				"${LOCAL_TUNNEL_INTERFACE}" \
				"${LOCAL_TUNNEL_ADDRESS}" \
				"${REMOTE_TUNNEL_INTERFACE}" \
				"${REMOTE_TUNNEL_ADDRESS}" \
				"${PRIVATE_KEY_PATH}" \
				"${LOG_FACILITY}"
		fi
	fi
}

function get-testing-cli(){
	echo "REMOTE_USER=${REMOTE_USER}; REMOTE_HOST=${REMOTE_HOST}; REMOTE_PORT=${REMOTE_PORT}; LOCAL_TUNNEL_INTERFACE=${LOCAL_TUNNEL_INTERFACE}; LOCAL_TUNNEL_ADDRESS=${LOCAL_TUNNEL_ADDRESS}; REMOTE_TUNNEL_INTERFACE=${REMOTE_TUNNEL_INTERFACE}; REMOTE_TUNNEL_ADDRESS=${REMOTE_TUNNEL_ADDRESS}; PRIVATE_KEY_PATH=${PRIVATE_KEY_PATH}; LOG_FACILITY="${LOG_FACILITY}" do_remote_command echo 'hello from remote'"
}

set +e
which ssh > /dev/null 2>&1 || {
	echo "SSH client is required."
	exit 1
}

which ping > /dev/null 2>&1 || {
	echo "ping is required."
	exit 1
}

which ip > /dev/null 2>&1 || {
	echo "iproute2 is required."
	exit 1
}

which logger > /dev/null 2>&1 || {
	echo "logger is required."
}

# TODO: create a function do_remote_checks and it should be called at the beginning of up, down, etc.
# do_remote_command which ip > /dev/null 2>&1 || {
# 	echo "iproute2 is required on the remote."
# 	exit 1
# }

# TODO: add checks for sshd - PermitTunnel and CAP_NET_ADMIN for both hosts
set -e

if [ ${CONFIGURED} -eq 0 ]; then
	echo "ssh-vpn.sh is not configured. Please open this script and navigate to the CONFIGURATION BLOCK."
	exit 0
fi

case "$1" in
	up)
		up
	;;
	down)
		down
	;;
	status)
		status
	;;
	status-verbose)
		status verbose
	;;
	check-tunnel-support)
		check_tunnel_support
	;;
	get-testing-cli)
		get-testing-cli
	;;
	*)
		>&2 echo "Use either up, down, status, status-verbose, check-tunnel-support, or get-testing-cli."
		exit 1
	;;
esac
