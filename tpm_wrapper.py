from pathlib import Path
from re import DOTALL, finditer, search
from subprocess import run


class TPM2ExecutionError(Exception):
    pass


def handle_error(cmd):
    perm_error = rb"Failed to open specified TCTI device file /dev/tpmrm\d+: Permission denied"
    auth_error = rb"authorization failure without DA implications"
    if search(perm_error, cmd.stderr):
        raise PermissionError("Permission denied. Please run the command as root.")
    if auth_error in cmd.stderr:
        raise PermissionError("Authorization failure. Please check the TPM2 authorization value.")
    else:
        raise TPM2ExecutionError("Failed to run command '%s', error:\n%s" % (" ".join(cmd.args), cmd.stderr.decode()))


def run_cmd(cmd, return_output=True, stdin=None):
    if stdin:
        cmd = run(cmd, input=stdin, capture_output=True)
    else:
        cmd = run(cmd, capture_output=True)
    if cmd.returncode != 0:
        handle_error(cmd)
    if cmd.stdout and return_output:
        return cmd.stdout
    return cmd


def nvreadpublic():
    return run_cmd(["tpm2_nvreadpublic"])


def nvread(handle):
    return run_cmd(["tpm2_nvread", handle])


def getrandom(num_bytes):
    return run_cmd(["tpm2_getrandom", str(num_bytes)])


def createprimary(hierarchy="owner", parent_auth=None):
    args = ["tpm2_createprimary", "--hierarchy", hierarchy]
    if parent_auth:
        args.extend(["--hierarchy-auth", parent_auth])
    output = run_cmd([*args, "--key-context", "/dev/stdout"])
    rsa = search(rb"rsa: ([a-f0-9]{512})\n", output).group(1)
    key_context = output.split(rsa)[1][1:]

    if len(key_context) != 2072:
        raise ValueError("Primary context length is not 2072 bytes.")

    return key_context, rsa


def evictcontrol(object_context, hierarchy="owner", parent_auth=None):
    if isinstance(object_context, bytes):
        context_data = object_context
        object_context = "-"
    elif not Path(object_context).exists():
        raise FileNotFoundError(f"Object context file '{object_context}' does not exist.")

    args = ["tpm2_evictcontrol", "--hierarchy", hierarchy, "--object-context", object_context]
    if parent_auth:
        args.extend(["--auth", parent_auth])
    if object_context == "-":
        return run_cmd(args, stdin=context_data)
    return run_cmd(args)


def get_handles():
    handles = {}
    if raw_output := nvreadpublic():
        for match in finditer(rb"(0x[0-9a-fA-F]{7}):\n.+?size: (\d+)\n+", raw_output, DOTALL):
            handles[match.group(1).decode()] = int(match.group(2).decode())
    return handles
