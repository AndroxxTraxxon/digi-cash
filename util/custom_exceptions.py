class BadSignature(ValueError):
    """ To be raised when the provided token's signature does not validated """
    pass


class ChecksumConflict(ValueError):
    """ To be raised when validating checksums, and they don't match. """
    pass


class TokenFormatMalformed(ValueError):
    """ To be raised when the format file is not properly formed """
    pass


class BadTokenFormat(ValueError):
    """ To be raised when the provided token does not follow the defined token format. """
    pass
