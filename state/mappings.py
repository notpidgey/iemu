def get_arch_mapping():
    # from binja arch to icicle arch name
    return {'x86_64': 'x86_64', 'x86': 'i686'}


def get_registers_for_mapping(arch):
    if arch == 'x86_64':
        return {
            'RAX': 64, 'RBX': 64, 'RCX': 64, 'RDX': 64, 'RBP': 64, 'RSP': 64, 'RSI': 64, 'RDI': 64,
            'R8': 64, 'R9': 64, 'R10': 64, 'R11': 64, 'R12': 64, 'R13': 64, 'R14': 64, 'R15': 64,
            'RIP': 64, 'RFLAGS': 64
        }
    elif arch == 'x86':
        return {
            'EAX': 32, 'EBX': 32, 'ECX': 32, 'EDX': 32, 'EBP': 32, 'ESP': 32, 'ESI': 32, 'EDI': 32,
            'EIP': 32, 'EFLAGS': 32
        }
    else:
        return {}


def get_register_mapping_override(arch):
    # to make this more formal, each register should have a length
    # and the mappings should have ranges and sizes
    # because we only use this in one case we can just assume they are bits
    mapping = {
        'x86_64': {
            'RFLAGS': {
                0x0001: "CF",  # Carry Flag
                0x0004: "PF",  # Parity Flag
                0x0010: "AF",  # Auxiliary Carry Flag
                0x0040: "ZF",  # Zero Flag
                0x0080: "SF",  # Sign Flag
                0x0100: "TF",  # Trap Flag
                0x0200: "IF",  # Interrupt Enable Flag
                0x0400: "DF",  # Direction Flag
                0x0800: "OF",  # Overflow Flag
                0x4000: "NT",  # Nested Task Flag

                # EFlags
                0x10000: "RF",  # Resume Flag
                0x20000: "VM",  # Virtual-8086 Mode Flag
                0x40000: "AC",  # Alignment Check Flag
                0x80000: "VIF",  # Virtual Interrupt Flag
                0x100000: "VIP",  # Virtual Interrupt Pending
                0x200000: "ID",  # ID Flag
            }
        },
        'x86': {
            'EFLAGS': {
                0x0001: "CF",  # Carry Flag
                0x0004: "PF",  # Parity Flag
                0x0010: "AF",  # Auxiliary Carry Flag
                0x0040: "ZF",  # Zero Flag
                0x0080: "SF",  # Sign Flag
                0x0100: "TF",  # Trap Flag
                0x0200: "IF",  # Interrupt Enable Flag
                0x0400: "DF",  # Direction Flag
                0x0800: "OF",  # Overflow Flag
                0x4000: "NT",  # Nested Task Flag

                # EFlags
                0x10000: "RF",  # Resume Flag
                0x20000: "VM",  # Virtual-8086 Mode Flag
                0x40000: "AC",  # Alignment Check Flag
                0x80000: "VIF",  # Virtual Interrupt Flag
                0x100000: "VIP",  # Virtual Interrupt Pending
                0x200000: "ID",  # ID Flag
            }
        }
    }

    return mapping[arch]


def get_stack_pointer_register(arch):
    if arch == 'x86_64':
        return 'RSP'
    elif arch == 'x86':
        return 'ESP'
    else:
        return ''


def get_arch_instruction_pointer(arch):
    if arch == 'x86_64':
        return 'RIP'
    elif arch == 'x86':
        return 'EIP'
    else:
        return ''

def get_arch_endianness(arch):
    # todo, expose these through the icicle api
    if arch == 'x86_64':
        return 'little'
    elif arch == 'x86':
        return 'little'
    else:
        return ''