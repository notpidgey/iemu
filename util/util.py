def verify_hex_string(s: str, append: bool = True) -> str:
    str_out = ""
    try:
        # will throw exception if not hex
        int(s, 16)
        str_out = s
    except ValueError:
        str_out = "0"

    if append:
        if str_out.startswith("0x"):
            return str_out
        return f"0x{str_out}"

    return str_out