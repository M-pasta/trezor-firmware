from typing import List, Tuple, TYPE_CHECKING
import gc
from storage.device import get_device_secret
from trezor import utils, log
from trezorcrypto import chacha20poly1305
from trezor.crypto import random

if TYPE_CHECKING:
    from apps.common.paths import Slip21Path
    from apps.common.seed import Slip21Node
from storage import cache_codec, cache_common


FIELDS_TO_ENCRYPT = [cache_common.APP_COMMON_SEED]
if not utils.BITCOIN_ONLY:
    FIELDS_TO_ENCRYPT += [
        cache_common.APP_CARDANO_ICARUS_SECRET,
        cache_common.APP_CARDANO_ICARUS_TREZOR_SECRET,
    ]

FIELDS_TO_ENCRYPT_SESSIONLESS = [cache_common.APP_COMMON_SEED_WITHOUT_PASSPHRASE]


def get_seed_encryption_key(session_id: bytes) -> bytes:
    """
    Returns the seed encryption key for a given session ID.
    The key is derived from the device secret and the session ID.
    """
    device_secret = get_device_secret()
    label = b"Seed encryption key"
    path: Slip21Path = [label, session_id]
    key_node = Slip21Node(device_secret)
    key_node.derive_path(path)
    log.info(
        "get_seed_encryption_key",
        f"Derived seed encryption key for session ID: {label.decode()}/{session_id.hex()} : {key_node.key().hex()}",
    )
    return key_node.key()


def chain_seed_values(
    session: cache_codec.DataCache, fileds_to_encrypt: List[int]
) -> bytes:
    """
    Creates a plaintext representation of the session's seed
    and other relevant data for encryption.
    """
    plaintext = bytearray()
    log.info(
        "chain_seed_values", f"Chaining seed values for fields: {fileds_to_encrypt}"
    )
    for field in fileds_to_encrypt:
        value = session.get(field)
        if not value:
            value = b"\x00" * session._get_length(field)
        plaintext += value
    log.info("chain_seed_values", f"Chained text: {bytes(plaintext).hex()}")
    return bytes(plaintext)


def parse_value_chain_to_cache(
    ciphertext: bytes, session: cache_codec.DataCache
) -> None:
    current_length = 0
    for field in FIELDS_TO_ENCRYPT:
        length = session._get_length(field)
        value = ciphertext[current_length : current_length + length]
        session.set(field, value)
        current_length += length
    assert current_length == len(
        ciphertext
    ), "Ciphertext length does not match expected length"


def encrypt_session_seeds(session: cache_codec.DataCache) -> None:
    if isinstance(session, cache_codec.SessionCache):
        sessioless = False
        session_id = session.export_session_id()
    elif isinstance(session, cache_common.SessionlessCache):
        sessioless = True
        session_id = b"\x00" * cache_codec.SESSION_ID_LENGTH
    else:
        raise TypeError("Unsupported session type for encryption")

    log.info(
        "encrypt_session_seeds",
        f"Encrypting session seeds for session ID: {session_id.hex()}",
    )

    encryption_key = get_seed_encryption_key(session_id)
    nonce = random.bytes(12, strong=True)
    log.info("encrypt_session_seeds", f"Generated nonce: {nonce.hex()}")

    cipher = chacha20poly1305(encryption_key, nonce)
    ciphertext = cipher.encrypt(
        chain_seed_values(
            session,
            FIELDS_TO_ENCRYPT if not sessioless else FIELDS_TO_ENCRYPT_SESSIONLESS,
        )
    )
    log.info("encrypt_session_seeds", f"Ciphertext: {ciphertext.hex()}")

    tag = cipher.finish()
    log.info("encrypt_session_seeds", f"Generated tag: {tag.hex()}")
    setattr(session, "encryption_tag", tag)
    setattr(session, "encryption_nonce", nonce)
    parse_value_chain_to_cache(ciphertext, session)

    log.info(
        "encrypt_session_seeds",
        f"New values in session: {[a.hex() for a in session.data]}",
    )


def get_decryption_data(
    session: cache_codec.DataCache,
) -> Tuple[bytes, bytes, bytes, bool]:
    if isinstance(session, cache_codec.SessionCache):
        sessioless = False
        session_id = session.export_session_id()
    elif isinstance(session, cache_common.SessionlessCache):
        sessioless = True
        session_id = b"\x00" * cache_codec.SESSION_ID_LENGTH
    else:
        raise TypeError("Unsupported session type for decryption")

    log.info(
        "get_decryption_data",
        f"Decrypting session seeds for session ID: {session_id.hex()} ({sessioless})",
    )

    try:
        tag: bytes = getattr(session, "encryption_tag")
        nonce: bytes = getattr(session, "encryption_nonce")
        log.info(
            "get_decryption_data",
            f"Retrieved tag: {tag.hex()} and nonce: {nonce.hex()}",
        )

        delattr(session, "encryption_tag")
        delattr(session, "encryption_nonce")
        gc.collect()
    except AttributeError:
        # If the session does not have encryption data, raise an error
        raise ValueError("No encryption data found for the session")
    return session_id, nonce, tag, sessioless


def decrypt_session_seeds(session: cache_codec.DataCache) -> None:
    session_id, nonce, tag, sessionless = get_decryption_data(session)
    encryption_key = get_seed_encryption_key(session_id)
    log.info("decrypt_session_seeds", f"encryption_key: {encryption_key.hex()}")

    cipher = chacha20poly1305(encryption_key, nonce)
    plaintext = cipher.decrypt(
        chain_seed_values(
            session,
            FIELDS_TO_ENCRYPT if not sessionless else FIELDS_TO_ENCRYPT_SESSIONLESS,
        )
    )

    log.info("decrypt_session_seeds", f"Decrypted plaintext: {plaintext.hex()}")

    control_tag = cipher.finish()
    if control_tag != tag:
        raise ValueError("Decryption failed: tag mismatch")

    parse_value_chain_to_cache(plaintext, session)
    log.info(
        "decrypt_session_seeds",
        f"New values in session: {[a.hex() for a in session.data]}",
    )
