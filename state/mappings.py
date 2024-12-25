def get_arch_mapping():
    # from binja arch to icicle arch name
    return {'x86_64': 'x86_64', 'x86': 'x86'}


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