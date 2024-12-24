from binaryninja import *
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, SidebarWidgetLocation, \
    SidebarContextSensitivity
from PySide6.QtWidgets import QVBoxLayout, QTabWidget, QWidget, QPushButton, QHBoxLayout, QLabel
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtCore import Qt, QRectF

import icicle

from .tabs.context_tab import ContextTab
from iemu.state.emulator_state import EmulatorState, PagePermissions, EmulationStatus
from .tabs.memory_mappings_tab import MemoryMappingsTab
from .tabs.stack_view_tab import StackViewTab
from .tabs.memory_view_tab import MemoryViewTab

instance_id = 0
sidebar_widget_instances = {}


class EmulatorSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        global instance_id
        sidebar_widget_instances[data] = self

        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.prev_highlights = []
        self.emulator_state = EmulatorState()

        self.checkpoint_regs = {}
        self.checkpoint_sections = None
        self.checkpoint_sections_data = {}
        self.checkpoint_memory = None
        self.checkpoint_memory_data = {}

        for reg in [
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
            "RIP", "RFLAGS"
        ]:
            self.emulator_state.set_register(reg, 0)

        tabs = QTabWidget()
        self.context_tab = ContextTab(self, self.emulator_state)
        self.memory_mappings_tab = MemoryMappingsTab(self, self.emulator_state)
        self.stack_view_tab = StackViewTab(self, self.emulator_state)
        self.memory_view_tab = MemoryViewTab(self, self.emulator_state)

        tabs.addTab(self.context_tab, "Context")
        tabs.addTab(self.memory_mappings_tab, "Memory")
        tabs.addTab(self.stack_view_tab, "Stack")
        tabs.addTab(self.memory_view_tab, "Dump")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)
        layout.addWidget(tabs)

        self.status_label = QLabel("Status: Offline")
        layout.addWidget(self.status_label)

        self.control_widget = QWidget()
        control_layout = QHBoxLayout(self.control_widget)
        self.control_widget.setVisible(True)

        initialize_button = QPushButton("Initialize")
        initialize_button.setStyleSheet("background-color: #184d1a; color: white;")
        initialize_button.clicked.connect(self.initialize_button_clicked)
        control_layout.addWidget(initialize_button)

        run_button = QPushButton("Run")
        run_button.setStyleSheet("background-color: #4CAF50; color: white;")
        run_button.clicked.connect(self.run_button_clicked)
        control_layout.addWidget(run_button)

        step_button = QPushButton("Step")
        step_button.setStyleSheet("background-color: #FFC107; color: white;")
        step_button.clicked.connect(self.step_button_clicked)
        control_layout.addWidget(step_button)

        checkpoint_button = QPushButton("Checkpoint")
        checkpoint_button.setStyleSheet("background-color: #f57c73; color: white;")
        checkpoint_button.clicked.connect(self.checkpoint_button_clicked)
        control_layout.addWidget(checkpoint_button)

        restart_button = QPushButton("Load Checkpoint")
        restart_button.setStyleSheet("background-color: #F44336; color: white;")
        restart_button.clicked.connect(self.restart_button_clicked)
        control_layout.addWidget(restart_button)

        clear_button = QPushButton("Clear")
        clear_button.setStyleSheet("background-color: #9E9E9E; color: white;")
        clear_button.clicked.connect(self.clear_button_clicked)
        control_layout.addWidget(clear_button)

        self.emulator_state.register_state.add_listener(self.monitor_rsp_highlight)
        self.emulator_state.vm_status.add_listener(self.update_status_label)

        self.current_allocations = set()
        self.emulator_state.mapped_memory.add_listener(self.monitor_vm_memory)
        self.emulator_state.register_state.add_listener(self.monitor_vm_registers)

        layout.addWidget(self.control_widget)
        self.control_layout = control_layout

        self.setLayout(layout)
        self.emulator_state.binary_view.set(data)

        instance_id += 1

    def initialize_button_clicked(self):
        status = self.emulator_state.vm_status.get()
        if status != EmulationStatus.Offline:
            show_message_box("Error", "Emulator is already initialized.",
                             MessageBoxButtonSet.OKButtonSet, )

        self.emulator_state.vm_inst = icicle.Icicle("x86_64", jit=False)
        log.log_info(f"Initialized VM {self.emulator_state.vm_inst}")

        sections = self.emulator_state.mapped_sections.get()
        memory = self.emulator_state.mapped_memory.get()
        regs = self.emulator_state.register_state.get()

        for section in sections:
            enabled, section = section
            if not enabled:
                continue

            memory_attr = icicle.MemoryProtection.ReadOnly
            match section.semantics:
                case SectionSemantics.DefaultSectionSemantics:
                    memory_attr = icicle.MemoryProtection.ReadOnly
                case SectionSemantics.ExternalSectionSemantics:
                    memory_attr = icicle.MemoryProtection.ExecuteRead
                case SectionSemantics.ReadOnlyCodeSectionSemantics:
                    memory_attr = icicle.MemoryProtection.ExecuteRead
                case SectionSemantics.ReadOnlyDataSectionSemantics:
                    memory_attr = icicle.MemoryProtection.ReadOnly
                case SectionSemantics.ReadWriteDataSectionSemantics:
                    memory_attr = icicle.MemoryProtection.ReadWrite

            self.emulator_state.vm_inst.mem_map(section.start, section.length, memory_attr)
            log.log_info(f"Mapped section region {hex(section.start)} - {hex(section.start + section.length)} {memory_attr}")

            bv = self.emulator_state.binary_view.get()
            self.emulator_state.vm_inst.mem_write(section.start, bv.read(section.start, section.length))
            log.log_info(f"Loaded section region {hex(section.start)} - {hex(section.start + section.length)} {memory_attr}")

        for allocation in memory:
            enabled, (start, length, permissions) = allocation
            if not enabled:
                continue

            self.emulator_state.vm_inst.mem_map(start, length, permissions)
            log.log_info(f"Mapped memory region {hex(start)} - {hex(start + length)} {permissions}")

        for (val, reg) in enumerate(regs):
            self.emulator_state.vm_inst.reg_write(reg, val)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

    def run_button_clicked(self):
        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to run.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        vm = self.emulator_state.vm_inst
        until = self.emulator_state.target_rip.get()
        if until != 0:
            log.log_info(f"Running VM from RIP: {hex(vm.reg_read('RIP'))} to RIP: {hex(until)}")
            status = vm.run_until(until)
        else:
            log.log_info(f"Running VM from RIP: {hex(vm.reg_read('RIP'))}")
            status = vm.run()

        if status == icicle.RunStatus.UnhandledException:
            log.log_info(f"Status Code: {vm.exception_code}")

        log.log_info(f"Run concluded at RIP: {hex(vm.reg_read('RIP'))}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = vm.reg_read(reg)

        self.emulator_state.register_state.set(reg_state)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

    def step_button_clicked(self):
        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to step.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        vm = self.emulator_state.vm_inst
        log.log_info(f"Run started at at RIP: {hex(vm.reg_read('RIP'))}")
        status = vm.step(1)

        if status == icicle.RunStatus.UnhandledException:
            log.log_info(f"Status Code: {vm.exception_code}")

        log.log_info(f"Run concluded at RIP: {hex(vm.reg_read('RIP'))}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = vm.reg_read(reg)

        self.emulator_state.register_state.set(reg_state)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

    def checkpoint_button_clicked(self):
        log.log_info("Checkpoint button clicked")

        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to create checkpoint.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        # we want to save the current state
        # basically we are going to trust that the current state accurately
        # contains the currently mapped memory.
        # so we are going to read it out and safe it

        sections = self.emulator_state.mapped_sections.get()
        memory = self.emulator_state.mapped_memory.get()
        regs = self.emulator_state.register_state.get()

        # copy sections memory
        self.checkpoint_sections = sections.copy()
        for section in sections:
            enabled, section = section
            if not enabled:
                continue

            memory_buffer = self.emulator_state.vm_inst.mem_read(section.start, section.length)
            self.checkpoint_sections_data[section] = memory_buffer

            log.log_info(f"Saved section region {hex(section.start)} - {hex(section.start + section.length)}")

        # copy memory
        self.checkpoint_memory = memory.copy()
        for allocation in memory:
            enabled, (start, length, permissions) = allocation
            if not enabled:
                continue

            memory_buffer = self.emulator_state.vm_inst.mem_read(start, length)
            self.checkpoint_memory_data[(start, length)] = memory_buffer

            log.log_info(f"Saved memory region {hex(start)} - {hex(start + length)}")

        self.checkpoint_regs = regs.copy()
        log.log_info(f"Saved register state {regs}")

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

        log.log_info("Checkpoint created")

    def restart_button_clicked(self):
        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to load checkpoint.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        if self.checkpoint_sections is None or self.checkpoint_memory is None:
            show_message_box("Error", "No checkpoint to load.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        # we want to restore the previous state
        for (reg, value) in self.checkpoint_regs.items():
            self.emulator_state.vm_inst.reg_write(reg, value)
        self.emulator_state.register_state.set(self.checkpoint_regs)

        for (section, buff) in self.checkpoint_sections_data.items():
            self.emulator_state.vm_inst.mem_write(section.start, buff)
            log.log_info(f"Restored section region {hex(section.start)} - {hex(section.start + section.length)}")
        self.emulator_state.mapped_sections.set(self.checkpoint_sections)

        for ((start, length), buff) in self.checkpoint_memory_data.items():
            self.emulator_state.vm_inst.mem_write(start, buff)
            log.log_info(f"Restored memory region {hex(start)} - {hex(start + length)}")
        self.emulator_state.mapped_memory.set(self.checkpoint_memory)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)
        log.log_info("Checkpoint loaded")

    def clear_button_clicked(self):
        self.emulator_state.vm_status.set(EmulationStatus.Running)
        self.emulator_state.vm_inst.reset()

        self.current_allocations = set()
        self.emulator_state.mapped_memory.set([])

        # i want to believe that the unmapping event function would handle
        # the unmaping of the memory regions correctly, but its just safer to create a new vm
        # i dont know what other state is saved in there

        self.emulator_state.vm_inst = icicle.Icicle("x86_64", jit=False)
        log.log_info(f"Initialized VM {self.emulator_state.vm_inst}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = 0

        self.emulator_state.register_state.set(reg_state)
        self.emulator_state.vm_status.set(EmulationStatus.Offline)

    def monitor_vm_memory(self, new_allocations : List[Tuple[bool, Tuple[int, int, PagePermissions]]]):
        # remove any tuple from the list which is not enabled
        new_allocations = [alloc for alloc in new_allocations if alloc[0]]

        # get only the second part of the tuple for each element in the list
        new_allocations = [alloc[1] for alloc in new_allocations]
        new_allocations_set = set(new_allocations)

        allocations_to_add: Set[Tuple[int, int, IntFlag]] = new_allocations_set - self.current_allocations
        for allocation in allocations_to_add:
            (start, length, permissions) = allocation

            if permissions == PagePermissions.READ:
                icicle_permission = icicle.MemoryProtection.ReadOnly
            elif permissions == (PagePermissions.READ | PagePermissions.WRITE):
                icicle_permission = icicle.MemoryProtection.ReadWrite
            elif permissions == PagePermissions.EXECUTE:
                icicle_permission = icicle.MemoryProtection.ExecuteOnly
            elif permissions == (PagePermissions.READ | PagePermissions.EXECUTE):
                icicle_permission = icicle.MemoryProtection.ExecuteRead
            elif permissions == (PagePermissions.READ | PagePermissions.WRITE | PagePermissions.EXECUTE):
                icicle_permission = icicle.MemoryProtection.ExecuteReadWrite
            else:
                icicle_permission = icicle.MemoryProtection.NoAccess

            self.emulator_state.vm_inst.mem_map(start, length, icicle_permission)
            log.log_info(f"Mapped memory region {hex(start)} - {hex(start + length)} {icicle_permission}")

        allocations_to_remove = self.current_allocations - new_allocations_set
        for allocation in allocations_to_remove:
            (start, length, permissions)  = allocation

            self.emulator_state.vm_inst.mem_unmap(start, length)
            log.log_info(f"Unmapped memory region {hex(start)} - {hex(start + length)} {permissions}")

        self.current_allocations = new_allocations_set

    def monitor_vm_registers(self, values):
        vm = self.emulator_state.vm_inst
        for reg in values:
            vm.reg_write(reg, values[reg])

    def update_status_label(self, status):
        self.status_label.setText(f"Status: {status.name}")

    def monitor_rsp_highlight(self, values):
        for prev_highlight in self.prev_highlights:
            prev_highlight[0].set_auto_instr_highlight(prev_highlight[1], prev_highlight[2])
        self.prev_highlights.clear()

        rip = values["RIP"]
        fun = self.emulator_state.binary_view.get().get_functions_containing(rip)

        if fun:
            previous_highlight = fun[0].get_instr_highlight(rip)
            fun[0].set_auto_instr_highlight(rip, highlight.HighlightColor(red=0, green=120, blue=0))

            self.prev_highlights.append((fun[0], rip, previous_highlight))

    def notifyOffsetChanged(self, offset):
        self.offset = offset

    def notifyViewChanged(self, view_frame):
        if view_frame and self.emulator_state.binary_view.get() is None:
            self.emulator_state.binary_view.set(self.data)

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class EmulatorSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "iE")
        p.end()

        SidebarWidgetType.__init__(self, icon, "iEmulator")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return EmulatorSidebarWidget("iEmulator", frame, data)

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.PerViewTypeSidebarContext


def callbackmethod(bv):
    log.log_info("iEmu initialized")

def range_address_handle_run(bv, start, len):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.emulator_state.set_register("RIP", start)
        widget.emulator_state.set_rip_target(start + len)

        widget.run_button_clicked()
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")

def address_handle_run(bv, start):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.emulator_state.set_register("RIP", start)
        widget.run_button_clicked()
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


def update_rip(bv, start):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.emulator_state.set_register("RIP", start)
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


Sidebar.addSidebarWidgetType(EmulatorSidebarWidgetType())
PluginCommand.register_for_address("iEmu: Update RIP", "Update RIP register", update_rip)
PluginCommand.register_for_address("iEmu: Run from", "Update RIP register then run emulator", address_handle_run)
PluginCommand.register_for_range("iEmu: Run Selection", "Update RIP register then run emulator until highlight end",
                                 range_address_handle_run)