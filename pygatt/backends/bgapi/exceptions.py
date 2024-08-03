from pygatt.exceptions import BLEError


class BGAPIError(BLEError):
    pass


class ExpectedResponseTimeout(BGAPIError):
    def __init__(self, expected_packets, timeout):
        super(ExpectedResponseTimeout, self).__init__(
            "Timed out after %fs waiting for %s" % (timeout or 0, expected_packets)
        )
