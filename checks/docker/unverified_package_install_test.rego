package builtin.dockerfile.DS033

import rego.v1

run_input(cmd) := {"Stages": [{"Name": "debian:12", "Commands": [
	{"Cmd": "from", "Value": ["debian:12"]},
	{"Cmd": "run", "Value": [cmd]},
]}]}

test_denied if {
	cases := [
		"apt-get update && apt-get install -y --allow-unauthenticated curl",
		"apt-get install -y --force-yes curl",
		"apt install --allow-insecure-repositories curl",
		"apt-get -o APT::Get::AllowUnauthenticated=true install -y curl",
		"apt-get update -o Acquire::AllowInsecureRepositories=true",
		"DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated curl",
		"sudo apt-get install -y --allow-unauthenticated curl",
		"/usr/bin/apt-get install -y --allow-unauthenticated curl",
		"apk add --allow-untrusted /tmp/example.apk",
		"apk update; apk add --no-cache --allow-untrusted example",
		"yum install -y --nogpgcheck example",
		"dnf install -y --setopt=gpgcheck=0 example",
		"dnf install -y --setopt=example.gpgcheck=False example",
		"microdnf install -y --nogpgcheck example",
		"zypper --no-gpg-checks install -y example",
		"rpm -i --nosignature example.rpm",
		"pip install --trusted-host pypi.example.com example",
		"pip3 install --trusted-host=pypi.example.com example",
		"python3 -m pip install --trusted-host pypi.example.com example",
		`echo "deb [trusted=yes] http://example.com/debian stable main" > /etc/apt/sources.list.d/example.list`,
		`echo "deb [arch=amd64 trusted=yes] http://example.com/debian stable main" > /etc/apt/sources.list`,
		`echo 'deb [ trusted=yes ] https://example.com/debian stable main' > /etc/apt/sources.list`,
	]
	every cmd in cases {
		r := deny with input as run_input(cmd)
		count(r) == 1
	}
}

test_denied_message if {
	r := deny with input as run_input("apk add --allow-untrusted /tmp/example.apk")
	count(r) == 1
	r[_].msg == "'--allow-untrusted' disables the verification of packages: apk add --allow-untrusted /tmp/example.apk"
}

test_denied_multiple_settings if {
	r := deny with input as run_input("apt-get install -y --allow-unauthenticated --force-yes curl")
	count(r) == 2
}

test_allowed if {
	cases := [
		"apt-get update && apt-get install -y --no-install-recommends curl",
		"apk add --no-cache curl",
		"dnf install -y example && dnf clean all",
		"dnf install -y --setopt=gpgcheck=1 example",
		"rpm --import https://example.com/RPM-GPG-KEY && rpm -i example.rpm",
		"pip install --no-cache-dir example",
		`echo "deb [signed-by=/usr/share/keyrings/example.gpg] http://example.com/debian stable main" > /etc/apt/sources.list`,
		# local repository of packages built in the same RUN instruction
		`echo "deb [ trusted=yes ] file://$tempDir ./" > /etc/apt/sources.list.d/temp.list`,
		# the flag belongs to another tool
		"curl --nogpgcheck https://example.com",
		"echo --allow-untrusted",
	]
	every cmd in cases {
		r := deny with input as run_input(cmd)
		count(r) == 0
	}
}
