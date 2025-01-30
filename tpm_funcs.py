from pathlib import Path
from re import search
from subprocess import run
from tempfile import NamedTemporaryFile

from tpm_types import TPMNVPublic

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


def run_tpm2_cmd(cmd, return_output=True, stdin=None, decode=True):
    if not isinstance(cmd, list):
        cmd = cmd.split()
    if not cmd[0].startswith("tpm2_"):
        cmd[0] = "tpm2_" + cmd[0]
    if stdin:
        cmd = run(cmd, input=stdin, capture_output=True)
    else:
        cmd = run(cmd, capture_output=True)
    if cmd.returncode != 0:
        handle_error(cmd)
    if cmd.stdout and return_output:
        if decode:
            return (cmd.stdout.decode().strip())
        return cmd.stdout
    return cmd


def with_temp_file(func):
    """ Makes a temporary file for writing, as the "output_file" argument, if not provided.
    The output file is then passed to the decorated function.
    """
    def wrapper(*args, **kwargs):
        temp_file = kwargs.get("output_file")
        if not temp_file:
            with NamedTemporaryFile() as t:
                kwargs["output_file"] = Path(t.name)
                return func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    return wrapper



def nvreadpublic():
    return TPMNVPublic.from_output(run_tpm2_cmd("nvreadpublic"))


def nvread(handle):
    return run_tpm2_cmd(["nvread", handle])


def getrandom(num_bytes):
    return run_tpm2_cmd(["getrandom", str(num_bytes)], decode=False)


@with_temp_file
def createprimary(hierarchy="owner", parent_auth=None, output_file: Path=None):
    args = ["createprimary", "--hierarchy", hierarchy, "--key-context", output_file]
    if parent_auth:
        args.extend(["--hierarchy-auth", parent_auth])
    output = run_tpm2_cmd(args)
    for line in output.splitlines():
        if line.startswith("rsa: "):
            rsa = line.split(": ")[1]
            break
    else:
        raise ValueError("RSA key not found in createprimary output: %s" % output)
    key_context = output_file.read_bytes()

    if len(key_context) != 2072:
        raise ValueError("Primary context length is not 2072 bytes.")

    return key_context, rsa


def evictcontrol(object_context, hierarchy="owner", parent_auth=None):
    if isinstance(object_context, bytes):
        context_data = object_context
        with NamedTemporaryFile() as t:
            object_context = Path(t.name)
            object_context.write_bytes(context_data)
            return evictcontrol(object_context, hierarchy, parent_auth)
    elif not Path(object_context).exists():
        raise FileNotFoundError(f"Object context file does not exist: {object_context}")

    args = ["evictcontrol", "--hierarchy", hierarchy, "--object-context", object_context]
    if parent_auth:
        args.extend(["--auth", parent_auth])
    if object_context == "-":
        return run_tpm2_cmd(args, stdin=context_data, decode=False)
    return run_tpm2_cmd(args, decode=False)
