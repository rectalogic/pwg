import enum


class TypeEnum(enum.IntEnum):
    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f"{cls.__name__}_{value}"
        obj._value_ = value
        return obj


class IpProto(TypeEnum):
    ANY = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPV4 = 4
    TCP = 6
    UDP = 17
    RDP = 27
    IPV6 = 41
    ESP = 50
    ICMPV6 = 58
    MH = 135
    RAW = 255
