import builtins
import gc


from trezor import log
from storage import cache_codec
from storage.cache_common import SESSIONLESS_FLAG, SessionlessCache

# from storage.seed_encryption import decrypt_session_seeds, encrypt_session_seeds

# Cache initialization
_SESSIONLESS_CACHE = SessionlessCache()
_PROTOCOL_CACHE = cache_codec
_PROTOCOL_CACHE.initialize()
_SESSIONLESS_CACHE.clear()

gc.collect()


def clear_all() -> None:
    """
    Clears all data from both the protocol cache and the sessionless cache.
    """
    global autolock_last_touch
    autolock_last_touch = None
    _SESSIONLESS_CACHE.clear()
    _PROTOCOL_CACHE.clear_all()


def get_int_all_sessions(key: int) -> builtins.set[int]:
    """
    Returns set of int values associated with a given key from all relevant sessions.

    If the key has the `SESSIONLESS_FLAG` set, the values are retrieved
    from the sessionless cache. Otherwise, the values are fetched
    from the protocol cache.
    """
    if key & SESSIONLESS_FLAG:
        values = builtins.set()
        encoded = _SESSIONLESS_CACHE.get(key)
        if encoded is not None:
            values.add(int.from_bytes(encoded, "big"))
        return values
    return _PROTOCOL_CACHE.get_int_all_sessions(key)


def get_sessionless_cache() -> SessionlessCache:
    return _SESSIONLESS_CACHE


from typing import List, Tuple, TYPE_CHECKING
import gc

from storage.device import get_device_secret
from trezor import utils, log
from trezorcrypto import chacha20poly1305
from trezor.crypto import random
from binascii import hexlify


if TYPE_CHECKING:
    from apps.common.paths import Slip21Path


from storage import cache_codec, cache_common


FIELDS_TO_ENCRYPT = [cache_common.APP_COMMON_SEED]
if not utils.BITCOIN_ONLY:
    FIELDS_TO_ENCRYPT += [
        cache_common.APP_CARDANO_ICARUS_SECRET,
        cache_common.APP_CARDANO_ICARUS_TREZOR_SECRET,
    ]

FIELDS_TO_ENCRYPT_SESSIONLESS = [cache_common.APP_COMMON_SEED_WITHOUT_PASSPHRASE]


def is_empty(session: cache_codec.DataCache) -> bool:
    """
    Checks if the session is empty, meaning it has no data set for the fields to encrypt.
    """
    if isinstance(session, cache_codec.SessionCache):
        for field in FIELDS_TO_ENCRYPT:
            if session.get(field):
                return False
    elif isinstance(session, cache_common.SessionlessCache):
        for field in FIELDS_TO_ENCRYPT_SESSIONLESS:
            if session.get(field):
                return False
    else:
        raise TypeError("Unsupported session type.")
    return True


def get_seed_encryption_key(session_id: bytes) -> bytes:
    """
    Returns the seed encryption key for a given session ID.
    The key is derived from the device secret and the session ID.
    """
    from apps.common.seed import Slip21Node

    device_secret = get_device_secret()
    label = b"Seed encryption key"
    path: Slip21Path = [label, session_id]
    key_node = Slip21Node(device_secret)
    key_node.derive_path(path)
    log.info(
        "get_seed_encryption_key",
        f"Derived seed encryption key for session ID: {label.decode()}/{hexlify(session_id).decode()} : {hexlify(key_node.key()).decode()}",
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
        # if not value:
        #     value = b"\x00" * session._get_length(field)
        if value:
            plaintext += value
    log.info("chain_seed_values", f"Chained text: {hexlify(bytes(plaintext)).decode()}")
    return bytes(plaintext)


def parse_value_chain_to_cache(
    ciphertext: bytes, session: cache_codec.DataCache
) -> None:
    current_length = 0
    for field in FIELDS_TO_ENCRYPT:
        value = session.get(field)
        if value:
            length = len(value)
            ciphered_value = ciphertext[current_length : current_length + length]
            log.info(
                "parse_value_chain_to_cache",
                f"Extracted value for {field}: {hexlify(ciphered_value).decode()}",
            )
            session.set(field, ciphered_value)
            current_length += length
    assert current_length == len(
        ciphertext
    ), f"Ciphertext length does not match expected length ({current_length} != {len(ciphertext)})"


def encrypt_session_seeds(session: cache_codec.DataCache) -> None:
    if is_empty(session):
        log.info("encrypt_session_seeds", "Session is empty, skipping encryption")
        return
    if isinstance(session, cache_codec.SessionCache):
        session_id = session.export_session_id()
        fields_to_encrypt = FIELDS_TO_ENCRYPT
    elif isinstance(session, cache_common.SessionlessCache):
        session_id = b"\x00" * cache_codec.SESSION_ID_LENGTH
        fields_to_encrypt = FIELDS_TO_ENCRYPT_SESSIONLESS

    else:
        raise TypeError("Unsupported session type for encryption")

    log.info(
        "encrypt_session_seeds",
        f"Encrypting session seeds for session ID: {hexlify(session_id).decode()}",
    )

    encryption_key = get_seed_encryption_key(session_id)
    nonce = random.bytes(12, True)
    log.info("encrypt_session_seeds", f"Generated nonce: {hexlify(nonce).decode()}")

    cipher = chacha20poly1305(encryption_key, nonce)
    ciphertext = cipher.encrypt(chain_seed_values(session, fields_to_encrypt))
    log.info("encrypt_session_seeds", f"Ciphertext: {hexlify(ciphertext).decode()}")

    tag = cipher.finish()
    log.info("encrypt_session_seeds", f"Generated tag: {hexlify(tag).decode()}")
    setattr(session, "encryption_tag", tag)
    setattr(session, "encryption_nonce", nonce)
    parse_value_chain_to_cache(ciphertext, session)

    log.info(
        "encrypt_session_seeds",
        f"New values in session: {[hexlify(a).decode() for a in session.data]}",
    )


def get_decryption_data(
    session: cache_codec.DataCache,
) -> Tuple[bytes, bytes, bytes, List[int]]:
    if isinstance(session, cache_codec.SessionCache):
        sessioless = False
        session_id = session.export_session_id()
        fields_to_encrypt = FIELDS_TO_ENCRYPT
    elif isinstance(session, cache_common.SessionlessCache):
        sessioless = True
        session_id = b"\x00" * cache_codec.SESSION_ID_LENGTH
        fields_to_encrypt = FIELDS_TO_ENCRYPT_SESSIONLESS
    else:
        raise TypeError("Unsupported session type for decryption")

    log.info(
        "get_decryption_data",
        f"Decrypting session seeds for session ID: {hexlify(session_id).decode()} ({sessioless})",
    )

    try:
        tag: bytes = getattr(session, "encryption_tag")
        nonce: bytes = getattr(session, "encryption_nonce")
        log.info(
            "get_decryption_data",
            f"Retrieved tag: {hexlify(tag).decode()} and nonce: {hexlify(nonce).decode()}",
        )

        delattr(session, "encryption_tag")
        delattr(session, "encryption_nonce")
        gc.collect()
    except AttributeError:
        # If the session does not have encryption data, raise an error
        raise ValueError("No encryption data found for the session")
    return session_id, nonce, tag, fields_to_encrypt


def decrypt_session_seeds(session: cache_codec.DataCache) -> None:
    if is_empty(session):
        log.info("encrypt_session_seeds", "Session is empty, skipping encryption")
        return
    session_id, nonce, tag, fields_to_encrypt = get_decryption_data(session)
    decryption_key = get_seed_encryption_key(session_id)
    log.info(
        "decrypt_session_seeds", f"encryption_key: {hexlify(decryption_key).decode()}"
    )

    cipher = chacha20poly1305(decryption_key, nonce)
    plaintext = cipher.decrypt(chain_seed_values(session, fields_to_encrypt))

    log.info(
        "decrypt_session_seeds", f"Decrypted plaintext: {hexlify(plaintext).decode()}"
    )

    control_tag = cipher.finish()
    if control_tag != tag:
        raise ValueError("Decryption failed: tag mismatch")

    parse_value_chain_to_cache(plaintext, session)
    log.info(
        "decrypt_session_seeds",
        f"New values in session: {[hexlify(a).decode() for a in session.data]}",
    )


def encrypt_seeds() -> None:
    """
    Encrypts all seeds in all the sessions as well as the sessionless seeds.
    """

    import sys

    log.info("Print Python version", sys.version)
    log.info("encrypt_seeds", "Encrypting seeds invoked")

    for session in cache_codec._SESSIONS:
        log.info("encrypt_seeds", "Encrypting seeds in a new session")
        encrypt_session_seeds(session)
    log.info("encrypt_seeds", "Encrypting sessionless seeds")
    encrypt_session_seeds(get_sessionless_cache())


def decrypt_seeds() -> None:
    """
    Decrypts all seeds in all the sessions as well as the sessionless seeds.
    """
    log.info("decrypt_seeds", "Decrypting seeds invoked")
    for session in cache_codec._SESSIONS:
        log.info("decrypt_seeds", "Decrypting seeds in a new session")
        decrypt_session_seeds(session)
    log.info("decrypt_seeds", "Decrypting sessionless seeds")
    decrypt_session_seeds(get_sessionless_cache())


# === Homescreen storage ===
# This does not logically belong to the "cache" functionality, but the cache module is
# a convenient place to put this.
# When a Homescreen layout is instantiated, it checks the value of `homescreen_shown`
# to know whether it should render itself or whether the result of a previous instance
# is still on. This way we can avoid unnecessary fadeins/fadeouts when a workflow ends.
HOMESCREEN_ON = object()
LOCKSCREEN_ON = object()
BUSYSCREEN_ON = object()
homescreen_shown: object | None = None

# Timestamp of last autolock activity.
# Here to persist across main loop restart between workflows.
autolock_last_touch: int | None = None
