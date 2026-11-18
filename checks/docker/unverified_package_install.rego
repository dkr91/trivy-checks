# METADATA
# title: Package installation without signature verification
# description: "Package managers verify the signatures of packages and repositories. Disabling this verification allows tampered or malicious packages to be installed into the image."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://www.cisecurity.org/benchmark/docker
# - https://manpages.debian.org/bookworm/apt/apt-get.8.en.html
# - https://dnf.readthedocs.io/en/latest/command_ref.html
# - https://pip.pypa.io/en/stable/cli/pip_install/
# custom:
#   id: DS-0033
#   long_id: docker-verify-package-signatures
#   aliases:
#     - AVD-DS-0033
#     - DS033
#     - verify-package-signatures
#     - docker-verify-package-signatures
#   severity: HIGH
#   recommended_action: "Do not disable the signature verification of the package manager. Import the signing key of the repository instead."
#   input:
#     selector:
#     - type: dockerfile
#   examples: checks/docker/unverified_package_install.yaml
package builtin.dockerfile.DS033

import rego.v1

import data.lib.cmdutil
import data.lib.docker

# Flags that disable the verification of packages or repositories, per tool.
insecure_flags := {
	"apt": {"--allow-unauthenticated", "--force-yes", "--allow-insecure-repositories"},
	"apt-get": {"--allow-unauthenticated", "--force-yes", "--allow-insecure-repositories"},
	"aptitude": {"--allow-untrusted"},
	"apk": {"--allow-untrusted"},
	"yum": {"--nogpgcheck"},
	"dnf": {"--nogpgcheck"},
	"microdnf": {"--nogpgcheck"},
	"tdnf": {"--nogpgcheck"},
	"zypper": {"--no-gpg-checks"},
	"rpm": {"--nosignature", "--nodigest", "--nogpgcheck"},
	"pip": {"--trusted-host"},
	"pip3": {"--trusted-host"},
}

# Options that disable the verification when they are set as a value,
# e.g. "--setopt=gpgcheck=0" or "-o APT::Get::AllowUnauthenticated=true".
insecure_option_patterns := {
	"apt": `(?i)^(-o)?(APT::Get::AllowUnauthenticated|Acquire::AllowInsecureRepositories|Acquire::AllowDowngradeToInsecureRepositories)=(true|yes|1)$`,
	"apt-get": `(?i)^(-o)?(APT::Get::AllowUnauthenticated|Acquire::AllowInsecureRepositories|Acquire::AllowDowngradeToInsecureRepositories)=(true|yes|1)$`,
	"yum": `(?i)^(--setopt=)?([^=]*\.)?(gpgcheck|repo_gpgcheck|localpkg_gpgcheck)=(0|false|no)$`,
	"dnf": `(?i)^(--setopt=)?([^=]*\.)?(gpgcheck|repo_gpgcheck|localpkg_gpgcheck)=(0|false|no)$`,
	"microdnf": `(?i)^(--setopt=)?([^=]*\.)?(gpgcheck|repo_gpgcheck|localpkg_gpgcheck)=(0|false|no)$`,
	"tdnf": `(?i)^(--setopt=)?([^=]*\.)?(gpgcheck|repo_gpgcheck|localpkg_gpgcheck)=(0|false|no)$`,
}

deny contains res if {
	some run in docker.run
	raw_cmd := cmdutil.to_command_string(run.Value)
	some tokens in sh.parse_commands(raw_cmd)
	some setting in insecure_settings(command_tokens(tokens))
	msg := sprintf("'%s' disables the verification of packages: %s", [setting, raw_cmd])
	res := result.new(msg, run)
}

# APT sources marked as trusted are used without signature verification,
# e.g. echo "deb [trusted=yes] http://example.com/debian stable main" > /etc/apt/sources.list.d/example.list
# Local repositories ("file:" and "copy:" URIs), e.g. of packages built in the same RUN instruction, are not reported.
deny contains res if {
	some run in docker.run
	raw_cmd := cmdutil.to_command_string(run.Value)
	some uri in trusted_apt_source_uris(raw_cmd)
	not is_local_uri(uri)
	msg := sprintf("'trusted=yes' disables the verification of an APT repository: %s", [raw_cmd])
	res := result.new(msg, run)
}

trusted_apt_source_uris(cmd) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?i)\[[^\]]*\btrusted\s*=\s*yes\b[^\]]*\]\s*([^\s"']+)`, cmd, -1)
}

is_local_uri(uri) if regex.match(`(?i)^(file|copy):`, uri)

insecure_settings(tokens) := {token |
	tool := tool_name(tokens)
	some token in tokens
	is_insecure_setting(tool, token)
}

is_insecure_setting(tool, token) if {
	some flag in insecure_flags[tool]
	flag_matches(token, flag)
}

is_insecure_setting(tool, token) if {
	regex.match(insecure_option_patterns[tool], token)
}

flag_matches(token, flag) if token == flag

# e.g. --trusted-host=pypi.example.com
flag_matches(token, flag) if startswith(token, concat("", [flag, "="]))

# "python -m pip install ..." is handled like "pip install ..."
tool_name(tokens) := "pip" if {
	startswith(base_name(tokens[0]), "python")
	tokens[1] == "-m"
	tokens[2] in {"pip", "pip3"}
} else := base_name(tokens[0])

base_name(path) := parts[count(parts) - 1] if {
	parts := split(path, "/")
}

# Drops leading "sudo" and environment variable assignments,
# e.g. "DEBIAN_FRONTEND=noninteractive apt-get install ..."
command_tokens(tokens) := array.slice(tokens, start, count(tokens)) if {
	starts := [i | some i, token in tokens; not is_prefix_token(token)]
	count(starts) > 0
	start := starts[0]
} else := []

is_prefix_token("sudo")

is_prefix_token(token) if regex.match(`^[A-Za-z_][A-Za-z0-9_]*=`, token)
