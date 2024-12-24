from binaryninja import *
import icicle

from enum import IntFlag

class PagePermissions(IntFlag):
    NO_ACCESS = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4

class EmulationStatus(Enum):
    Offline = 0
    Initialized = 1
    Running = 2
    Stopped = 3

from typing import Generic, TypeVar, Callable, List

T = TypeVar('T')
from functools import partial

class Observable(Generic[T]):
    def __init__(self, initial_value: T = None):
        self._value: T = initial_value
        self._listeners: List[Callable[[T], None]] = []

    def get(self) -> T:
        return self._value

    def set(self, value: T):
        self._value = value
        self._notify_listeners()

    def add_listener(self, listener: Callable[[T], None]):
        if hasattr(listener, '__self__'):
            listener = partial(listener)
        self._listeners.append(listener)

    def _notify_listeners(self):
        for listener in self._listeners:
            try:
                # log.log_info(f"Calling listener: {listener} with value: {self._value}")
                listener(self._value)
            except Exception as e:
                # log.log_info(f"Error in listener {listener}: {e}")
                pass

class EmulatorState:
    def __init__(self):
        self.vm_inst : Optional[icicle.Icicle] = icicle.Icicle("x86_64", jit=False)
        self.vm_status = Observable[EmulationStatus](EmulationStatus.Offline)

        self.binary_view = Observable[BinaryView](None)

        self.mapped_sections = Observable[List[Tuple[bool, Section]]]([])
        self.mapped_memory = Observable[List[Tuple[bool, Tuple[int, int, PagePermissions]]]]([])

        self.register_state = Observable[Dict[str, int]]({})
        self.target_rip = Observable[int](0)

    def is_memory_overlapping(self, start: int, size: int):
        for (_, (mapped_start, mapped_size, _)) in self.mapped_memory.get():
            if start < mapped_start + mapped_size and start + size > mapped_start:
                return True

        for (_, section) in self.mapped_sections.get():
            if start < section.start + section.length and start + size > section.start:
                return True

        return False

    def set_register(self, reg: str, value: int):
        state = self.register_state.get()
        state[reg] = value
        self.register_state.set(state)

    def get_register(self, reg: str):
        return self.register_state.get().get(reg)

    def set_rip_target(self, value: int):
        self.target_rip.set(value)

    def add_section(self, section: Section, enabled = True):
        sections = self.mapped_sections.get()
        sections.append((enabled, section))
        self.mapped_sections.set(sections)

    def remove_section(self, section: Section):
        sections = self.mapped_sections.get()
        for section_pair in sections:
            if section_pair[1] == section:
                sections.remove(section_pair)
                break

        self.mapped_sections.set(sections)

    def modify_section(self, section : Section, enabled):
        sections = self.mapped_sections.get()
        for index, (s_enabled, s_section) in enumerate(sections):
            if s_section == section:
                sections[index] = (enabled, section)
                break

        self.mapped_sections.set(sections)

    def add_allocation(self, start: int, length: int, permissions: PagePermissions, enabled = True):
        allocations = self.mapped_memory.get()
        allocations.append((enabled, (start, length, permissions)))
        self.mapped_memory.set(allocations)

    def remove_allocation(self, start: int, length: int):
        allocations = self.mapped_memory.get()
        for allocation_pair in allocations:
            if allocation_pair[1][0] == start and allocation_pair[1][1] == length:
                allocations.remove(allocation_pair)
                break

        self.mapped_memory.set(allocations)

    def modify_allocation(self, start: int, length: int, permission : PagePermissions, enabled):
        allocations = self.mapped_memory.get()
        for index, (a_enabled, (a_start, a_length, a_permissions)) in enumerate(allocations):
            if a_start == start and a_length == length:
                allocations[index] = (enabled, (start, length, permission))
                break

        self.mapped_memory.set(allocations)