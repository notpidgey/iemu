def verify_hex_string(s: str, append: bool = True, size: int = -1) -> str:
    try:
        val = int(s, 16)
    except ValueError:
        val = 0

    if size < 0:
        out_str = f"{val:x}"
    else:
        out_str = f"{val:0{size * 2}x}"
        if len(out_str) > size * 2:
            out_str = out_str[-size * 2:]

    if append:
        out_str = f"0x{out_str}"

    return out_str