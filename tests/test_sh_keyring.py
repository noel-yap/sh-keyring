"""Behavioral tests for sh-keyring.shlib.

Each test sources the library under a controlled PATH (see conftest.py) and
exercises one function through a single input scenario.
"""


# ---------------------------------------------------------------------------
# probe_key_source
# ---------------------------------------------------------------------------

def test_probe_returns_127_when_binary_is_not_installed(runner):
    result = runner.run("probe_key_source no_such_binary_xyz arg1")
    assert result.returncode == 127
    assert result.stdout == ""


def test_probe_returns_zero_and_output_when_command_succeeds(runner):
    runner.stub("okcmd", "echo hello; exit 0")
    result = runner.run("probe_key_source okcmd")
    assert result.returncode == 0
    # The trailing newline is stripped by command substitution in the library.
    assert result.stdout == "hello"


def test_probe_propagates_exit_status_and_combined_output_when_command_fails(runner):
    runner.stub("failcmd", 'echo to-stdout; echo to-stderr >&2; exit 3')
    result = runner.run("probe_key_source failcmd")
    assert result.returncode == 3
    # stderr is folded into stdout via 2>&1 inside the library.
    assert result.stdout == "to-stdout\nto-stderr"


# ---------------------------------------------------------------------------
# get_key_from_mac
# ---------------------------------------------------------------------------

def test_get_key_from_mac_returns_value_when_found(runner):
    runner.stub("security", 'echo "the-secret"; exit 0')
    result = runner.run("get_key_from_mac MY_API_KEY")
    assert result.returncode == 0
    assert result.stdout == "the-secret"


def test_get_key_from_mac_returns_1_when_item_not_in_keychain(runner):
    # 44 == errSecItemNotFound
    runner.stub("security", "exit 44")
    result = runner.run("get_key_from_mac MY_API_KEY")
    assert result.returncode == 1


def test_get_key_from_mac_returns_1_when_security_not_installed(runner):
    # No `security` stub -> command-not-found -> probe returns 127.
    result = runner.run("get_key_from_mac MY_API_KEY")
    assert result.returncode == 1


def test_get_key_from_mac_returns_2_when_access_is_denied(runner):
    # 128 == access prompt denied: reachable source that failed.
    runner.stub("security", "exit 128")
    result = runner.run("get_key_from_mac MY_API_KEY")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# fetch_and_cache_key_in_mac
# ---------------------------------------------------------------------------

def test_fetch_and_cache_stores_and_emits_value_on_success(runner, tmp_path):
    marker = tmp_path / "added"
    runner.stub(
        "security",
        'if [[ "$1" == add-generic-password ]]; then echo "$@" >> "$MARKER"; fi; exit 0',
    )
    snippet = """
    myfetch() { printf 'fetched-value'; }
    fetch_and_cache_key_in_mac MYKEY myfetch
    """
    result = runner.run(snippet, env={"MARKER": marker})
    assert result.returncode == 0
    assert result.stdout == "fetched-value"
    assert marker.exists()
    assert "fetched-value" in marker.read_text()


def test_fetch_and_cache_propagates_failure_and_caches_nothing(runner, tmp_path):
    marker = tmp_path / "added"
    runner.stub(
        "security",
        'if [[ "$1" == add-generic-password ]]; then echo "$@" >> "$MARKER"; fi; exit 0',
    )
    snippet = """
    myfetch() { return 2; }
    fetch_and_cache_key_in_mac MYKEY myfetch
    """
    result = runner.run(snippet, env={"MARKER": marker})
    assert result.returncode == 2
    assert result.stdout == ""
    assert not marker.exists()


# ---------------------------------------------------------------------------
# expire_key_in_mac
# ---------------------------------------------------------------------------

# A `security find` attribute dump line that the library's sed extracts the
# 14-digit modification timestamp from.
def _mdat_line(timestamp):
    return f'    "mdat"<timedate>=0x00 "{timestamp}\\000"'


# Security stub that emits ``$FIND_OUTPUT`` for a find and records a delete to
# ``$MARKER``. The find output is passed via env (not embedded in the stub
# body) so its literal double quotes survive intact for sed to match.
_EXPIRE_SECURITY_STUB = """
case "$1" in
  find-generic-password) printf '%s\\n' "${FIND_OUTPUT}"; exit 0 ;;
  delete-generic-password) echo deleted >> "${MARKER}"; exit 0 ;;
esac
exit 0
"""


def test_expire_keeps_entry_when_no_modification_date_present(runner, tmp_path):
    marker = tmp_path / "deleted"
    runner.stub("security", _EXPIRE_SECURITY_STUB)
    result = runner.run(
        "expire_key_in_mac MY_API_KEY 43200",
        env={"MARKER": marker, "FIND_OUTPUT": '    "acct"<blob>="MY_API_KEY"'},
    )
    assert result.returncode == 0
    assert not marker.exists()


def test_expire_deletes_entry_older_than_ttl(runner, tmp_path):
    marker = tmp_path / "deleted"
    runner.stub("security", _EXPIRE_SECURITY_STUB)
    result = runner.run(
        "expire_key_in_mac MY_API_KEY 1",
        env={"MARKER": marker, "FIND_OUTPUT": _mdat_line("20000101000000")},
    )
    assert result.returncode == 0
    assert marker.exists()


def test_expire_keeps_entry_within_ttl(runner, tmp_path):
    marker = tmp_path / "deleted"
    runner.stub("security", _EXPIRE_SECURITY_STUB)
    # Modified in the past, but the TTL is enormous, so it stays.
    result = runner.run(
        "expire_key_in_mac MY_API_KEY 99999999999",
        env={"MARKER": marker, "FIND_OUTPUT": _mdat_line("20000101000000")},
    )
    assert result.returncode == 0
    assert not marker.exists()


# ---------------------------------------------------------------------------
# get_key_from_1password
# ---------------------------------------------------------------------------

def test_1password_returns_value_when_found(runner):
    runner.stub("op", 'printf "op-secret"; exit 0')
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 0
    assert result.stdout == "op-secret"


def test_1password_returns_1_when_cli_not_installed(runner):
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 1


def test_1password_returns_1_when_item_isnt_an_item(runner):
    runner.stub("op", 'echo "\\"MY_API_KEY\\" isn'"'"'t an item"; exit 1')
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 1


def test_1password_returns_1_when_no_item_matching(runner):
    runner.stub("op", 'echo "no item matching MY_API_KEY"; exit 1')
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 1


def test_1password_returns_1_when_not_found(runner):
    runner.stub("op", 'echo "item not found"; exit 1')
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 1


def test_1password_returns_2_when_signin_required(runner):
    runner.stub("op", 'echo "you are not currently signed in"; exit 1')
    result = runner.run("get_key_from_1password MY_API_KEY")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# get_key_from_aws
# ---------------------------------------------------------------------------

def test_aws_returns_value_when_found(runner):
    runner.stub("aws", 'printf "aws-secret"; exit 0')
    result = runner.run("get_key_from_aws some-profile some/secret/id")
    assert result.returncode == 0
    assert result.stdout == "aws-secret"


def test_aws_returns_1_when_cli_not_installed(runner):
    result = runner.run("get_key_from_aws some-profile some/secret/id")
    assert result.returncode == 1


def test_aws_returns_1_when_secret_not_found(runner):
    runner.stub("aws", 'echo "ResourceNotFoundException: secret missing" >&2; exit 254')
    result = runner.run("get_key_from_aws some-profile some/secret/id")
    assert result.returncode == 1


def test_aws_returns_1_when_profile_not_found(runner):
    runner.stub("aws", 'echo "ProfileNotFound: bad profile" >&2; exit 253')
    result = runner.run("get_key_from_aws bad-profile some/secret/id")
    assert result.returncode == 1


def test_aws_returns_1_when_config_profile_missing(runner):
    runner.stub("aws", 'echo "The config profile could not be found" >&2; exit 253')
    result = runner.run("get_key_from_aws bad-profile some/secret/id")
    assert result.returncode == 1


def test_aws_returns_2_when_credentials_expired(runner):
    runner.stub("aws", 'echo "ExpiredTokenException: token expired" >&2; exit 254')
    result = runner.run("get_key_from_aws some-profile some/secret/id")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# _get_key_from_aws
# ---------------------------------------------------------------------------

_AWS_NOT_CALLED_STUB = """
echo "aws must not be called" >&2
exit 99
"""


def test_get_key_from_aws_returns_1_when_aws_profile_is_unset(runner):
    runner.stub("aws", _AWS_NOT_CALLED_STUB)
    result = runner.run(
        "_get_key_from_aws MY_API_KEY",
        env={"AWS_PREFIX": "engineering/common"},
    )
    assert result.returncode == 1
    assert result.stdout == ""


def test_get_key_from_aws_returns_1_when_aws_prefix_is_unset(runner):
    runner.stub("aws", _AWS_NOT_CALLED_STUB)
    result = runner.run(
        "_get_key_from_aws MY_API_KEY",
        env={"AWS_PROFILE": "eng-common-secrets-devt"},
    )
    assert result.returncode == 1
    assert result.stdout == ""


def test_get_key_from_aws_fetches_and_caches_when_profile_and_prefix_are_set(
    runner, tmp_path
):
    marker = tmp_path / "added"
    aws_args = tmp_path / "aws-args"
    runner.stub(
        "security",
        'if [[ "$1" == add-generic-password ]]; then echo "$@" >> "$MARKER"; fi; exit 0',
    )
    runner.stub(
        "aws",
        """
        printf '%s\\n' "$*" >> "${AWS_ARGS_MARKER}"
        printf 'aws-secret'
        """,
    )
    result = runner.run(
        "_get_key_from_aws MY_API_KEY",
        env={
            "AWS_PROFILE": "my-profile",
            "AWS_PREFIX": "my/prefix",
            "MARKER": marker,
            "AWS_ARGS_MARKER": aws_args,
        },
    )
    assert result.returncode == 0
    assert result.stdout == "aws-secret"
    assert marker.exists()
    cached = marker.read_text()
    assert "MY_API_KEY" in cached
    assert "aws-secret" in cached
    assert aws_args.read_text() == (
        "secretsmanager get-secret-value --profile=my-profile "
        "--secret-id=my/prefix/MY_API_KEY --query=SecretString --output=text\n"
    )


def test_get_key_from_aws_propagates_aws_failure(runner):
    runner.stub("aws", 'echo "ExpiredTokenException: token expired" >&2; exit 254')
    result = runner.run(
        "_get_key_from_aws MY_API_KEY",
        env={
            "AWS_PROFILE": "my-profile",
            "AWS_PREFIX": "my/prefix",
        },
    )
    assert result.returncode == 2
    assert result.stdout == ""


# ---------------------------------------------------------------------------
# coalesce
# ---------------------------------------------------------------------------

def test_coalesce_returns_output_of_first_successful_nonempty_function(runner):
    snippet = """
    f1() { printf 'A'; }
    f2() { printf 'B'; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 0
    assert result.stdout == "A"


def test_coalesce_skips_function_that_succeeds_with_empty_output(runner):
    snippet = """
    f1() { return 0; }
    f2() { printf 'B'; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 0
    assert result.stdout == "B"


def test_coalesce_skips_function_that_fails_even_with_output(runner):
    # f1 produces output but exits non-zero, so it must be skipped and the
    # next successful function's output returned instead.
    snippet = """
    f1() { printf 'A'; return 1; }
    f2() { printf 'B'; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 0
    assert result.stdout == "B"


def test_coalesce_returns_highest_status_when_all_fail(runner):
    snippet = """
    f1() { return 1; }
    f2() { return 2; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 2
    assert result.stdout == ""


def test_coalesce_returns_highest_status_regardless_of_order(runner):
    snippet = """
    f1() { return 2; }
    f2() { return 1; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 2


def test_coalesce_defaults_to_status_1_when_all_fail_with_1(runner):
    snippet = """
    f1() { return 1; }
    f2() { return 1; }
    coalesce f1 f2
    """
    result = runner.run(snippet)
    assert result.returncode == 1


def test_coalesce_passes_shared_args_after_double_dash(runner):
    snippet = """
    echo_arg() { printf '%s' "$1"; }
    coalesce echo_arg -- SHARED_ARG
    """
    result = runner.run(snippet)
    assert result.returncode == 0
    assert result.stdout == "SHARED_ARG"


def test_coalesce_passes_no_args_without_double_dash(runner):
    # Without "--", the function receives no extra arguments, so it produces
    # empty output and is skipped, leaving the default failure status.
    snippet = """
    echo_arg() { printf '%s' "$1"; }
    coalesce echo_arg
    """
    result = runner.run(snippet)
    assert result.returncode == 1
    assert result.stdout == ""


# ---------------------------------------------------------------------------
# set_key
# ---------------------------------------------------------------------------

def test_set_key_exports_value_from_environment_source(runner):
    runner.stub("security", "exit 44")  # nothing cached; expire/find are no-ops
    snippet = """
    set_key MY_API_KEY
    printf 'result=%s' "${MY_API_KEY}"
    """
    result = runner.run(snippet, env={"MY_API_KEY": "env-value"})
    assert result.returncode == 0
    assert result.stdout == "result=env-value"


def test_set_key_emits_nothing_on_stdout_when_expiring_a_stale_entry(runner):
    # `security delete-generic-password` reports the deletion on stdout, and
    # set_key is routinely called inside command substitutions whose stdout is
    # the caller's data channel. When the cache-expiry step deletes a stale
    # entry, that report must land on stderr, never stdout.
    runner.stub(
        "security",
        """
        case "$1" in
          find-generic-password) printf '%s\\n' "${FIND_OUTPUT}"; exit 0 ;;
          delete-generic-password) echo 'password has been deleted.'; exit 0 ;;
        esac
        exit 0
        """,
    )
    snippet = """
    set_key MY_API_KEY
    printf 'result=%s' "${MY_API_KEY}"
    """
    result = runner.run(
        snippet,
        env={
            "MY_API_KEY": "env-value",
            "FIND_OUTPUT": _mdat_line("20000101000000"),
        },
    )
    assert result.returncode == 0
    assert result.stdout == "result=env-value"
    assert "password has been deleted." in result.stderr


def test_set_key_returns_2_and_warns_when_a_source_errors(runner):
    # No env value, no op/aws; Keychain access is denied (128) -> errored.
    runner.stub("security", "exit 128")
    result = runner.run("set_key MY_API_KEY", env={"MY_API_KEY": ""})
    assert result.returncode == 2
    assert "could not be retrieved" in result.stderr


def test_set_key_returns_1_silently_when_nothing_is_configured(runner):
    # No env value, no op/aws installed, Keychain item simply absent (44).
    runner.stub("security", "exit 44")
    result = runner.run("set_key MY_API_KEY", env={"MY_API_KEY": ""})
    assert result.returncode == 1
    assert result.stderr == ""