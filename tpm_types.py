from enum import Enum
from textwrap import dedent

from zenlib.types import validatedDataclass


class TPMNVRAMAttributes(Enum):
    """The name of the attribute and associated bit
    TPM Rev 2.0 section 13.3 Table 204: TPMA_NV
    """

    TPMA_NV_PPWRITE = 0
    TPMA_NV_OWNERWRITE = 1
    TPMA_NV_AUTHWRITE = 2
    TPMA_NV_POLICYWRITE = 3
    TPMA_NV_POLICY_DELETE = 10
    TPMA_NV_WRITELOCKED = 11
    TPMA_NV_WRITEALL = 12
    TPMA_NV_WRITEDEFINE = 13
    TPMA_NV_WRITE_STCLEAR = 14
    TPMA_NV_GLOBALLOCK = 15
    TPMA_NV_PPREAD = 16
    TPMA_NV_OWNERREAD = 17
    TPMA_NV_AUTHREAD = 18
    TPMA_NV_POLICYREAD = 19
    TPMA_NV_NO_DA = 25
    TPMA_NV_ORDERLY = 26
    TPMA_NV_CLEAR_STCLEAR = 27
    TPMA_NV_READLOCKED = 28
    TPMA_NV_WRITTEN = 29
    TPMA_NV_PLATFORMCREATE = 30
    TPMA_NV_READ_STCLEAR = 31


class TPMNVRAMHashAlgorithms(Enum):
    """The name of the hash algorithm and associated value
    TPM Rev 2.0 section 6.3 Table 8: TPM_ALG_ID
    """

    TPM_ALG_RSA = 0x0001
    TPM_ALG_SHA1 = 0x0004
    TPM_ALG_HMAC = 0x0005
    TPM_ALG_AES = 0x0006
    TPM_ALG_MGF1 = 0x0007
    TPM_ALG_KEYEDHASH = 0x0008
    TPM_ALG_XOR = 0x000A
    TPM_ALG_SHA256 = 0x000B
    TPM_ALG_SHA384 = 0x000C
    TPM_ALG_SHA512 = 0x000D
    TPM_ALG_NULL = 0x0010
    TPM_ALG_SM3_256 = 0x0012
    TPM_ALG_SM4 = 0x0013
    TPM_ALG_RSASSA = 0x0014
    TPM_ALG_RSAES = 0x0015
    TPM_ALG_RSAPSS = 0x0016
    TPM_ALG_OAEP = 0x0017
    TPM_ALG_ECDSA = 0x0018
    TPM_ALG_ECDH = 0x0019
    TPM_ALG_ECDAA = 0x001A
    TPM_ALG_SM2 = 0x001B
    TPM_ALG_ECSCHNORR = 0x001C
    TPM_ALG_ECMQV = 0x001D
    TPM_ALG_KDF1_SP800_56A = 0x0020
    TPM_ALG_KDF2 = 0x0021
    TPM_ALG_KDF1_SP800_108 = 0x0022
    TPM_ALG_ECC = 0x0023
    TPM_ALG_SYMCIPHER = 0x0025
    TPM_ALG_CAMELLIA = 0x0026
    TPM_ALG_CTR = 0x0040
    TPM_ALG_OFB = 0x0041
    TPM_ALG_CBC = 0x0042
    TPM_ALG_CFB = 0x0043
    TPM_ALG_ECB = 0x0044


@validatedDataclass
class TPMNVPublic:
    """Represents TPM non-volatile public areas"""

    address: int
    name: str
    hash_alg: int
    attributes: int
    size: int

    @staticmethod
    def from_output(output: str):
        """Returns TPMNVPublic objects from tpm2_nvreadpublic output"""
        if isinstance(output, str):
            output = output.splitlines()
        elif not isinstance(output, list):
            raise TypeError("Output must be a string or a list of strings")

        TPMNVPublics = []
        start_address, name, hash_alg, attributes, size = None, None, None, None, None
        mode = None
        for line in output:
            line = line.strip()
            if not start_address:  # The first line should contain the entry index in hex, before the ":" character
                start_address = int(line.split(":")[0], 16)
                continue

            if line.startswith("value:"):
                match mode:
                    case "hash_alg":
                        hash_alg = int(line.split(":")[1].strip(), 16)
                    case "attributes":
                        attributes = int(line.split(":")[1].strip(), 16)
                    case _:
                        raise ValueError("Unexpected value line, mode is not set: %s" % line)
                mode = None
            elif line.startswith("name:"):  # Only the name line should start with "name:"
                name = line.split(":")[1].strip()
                continue
            elif line.startswith("size:"):
                size = int(line.split(":")[1].strip())
                continue
            elif line.startswith("hash algorithm"):
                mode = "hash_alg"
                continue
            elif line.startswith("attributes"):
                mode = "attributes"
                continue

            if not line:  # Empty lines should indicate the end of an entry
                TPMNVPublics.append(TPMNVPublic(start_address, name, hash_alg, attributes, size))
                start_address, name, hash_alg, attributes, size = None, None, None, None, None
                continue
        if len(TPMNVPublics) == 0:
            raise ValueError("No TPMNVPublic objects found in output")
        elif len(TPMNVPublics) == 1:
            return TPMNVPublics[0]
        else:
            return TPMNVPublics

    @property
    def friendly_attributes(self):
        """Returns a list of friendly names of the attributes"""
        return [attr.name for attr in TPMNVRAMAttributes if self.attributes & (1 << attr.value)]

    @property
    def friendly_hash_alg(self):
        """Returns the friendly name of the hash algorithm"""
        for alg in TPMNVRAMHashAlgorithms:
            if alg.value == self.hash_alg:
                return alg.name
        return "Unknown"

    def __post_init__(self, *args, **kwargs):
        if self.size < 0:
            raise ValueError("Size must be positive")

    def has_attr(self, attr: TPMNVRAMAttributes):
        """Returns True if the attribute is set"""
        if not isinstance(attr, TPMNVRAMAttributes):
            attr_name = attr.upper()
            for a in TPMNVRAMAttributes:
                if a.name == attr_name:
                    attr = a
                    break
            else:
                raise ValueError(f"Invalid attribute: {attr}")
        return self.attributes & (1 << attr.value) != 0

    def __str__(self):
        return dedent(
            f"""
        Address: {hex(self.address)}
          Name: {self.name}
          hash algorithm:
            friendly: {self.friendly_hash_alg}
            value: {hex(self.hash_alg)}
          attributes:
            friendly: {"|".join(self.friendly_attributes)}
            value: {hex(self.attributes)}
          size: {self.size}
          """[1:]
        )
