#!/usr/bin/env python

def sha256_padding(prefix, nbytes):
    four_bytes = "0x%02x, 0x%02x, 0x%02x, 0x%02x"
    nbits = nbytes * 8
    pad_bytes = (1 + (nbytes + 8) // 64) * 64
    pad_data = bytearray(pad_bytes)
    pad_data[nbytes] = 0x80

    for p in range(0, 8):
        pad_data[pad_bytes-(1+p)] = (nbits >> 8*p) & 255

    ret = "static uint8_t %s%u[%u] = {\n" % (prefix, nbytes, pad_bytes)
    for p in range(0, pad_bytes-8, 8):
        ret += ("  "+four_bytes+",  "+four_bytes+",\n") % tuple(
            pad_data[p+i] for i in range(8)
        )
        if p % 32 == 24:
            ret += "\n"
    
    ret += "  /* length %u bits, big endian uint84_t */\n" % nbits
    ret += ("  "+four_bytes+",  "+four_bytes+"\n") % tuple(
        pad_data[pad_bytes-i] for i in range(8, 0, -1)
    )


    ret += "};"
    return ret


print sha256_padding('input', 33)
print sha256_padding('input', 65)

