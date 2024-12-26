from binaryninja import *
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, SidebarWidgetLocation, \
    SidebarContextSensitivity
from PySide6.QtWidgets import QVBoxLayout, QTabWidget, QWidget, QPushButton, QHBoxLayout, QLabel, QDialog, QLineEdit, \
    QSizePolicy
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtCore import Qt, QRectF

import icicle

from iemu.tabs.context_tab import ContextTab
from iemu.state.mappings import get_arch_mapping, get_registers_for_mapping, get_arch_instruction_pointer, \
    get_stack_pointer_register
from iemu.state.emulator_state import EmulatorState, PagePermissions, EmulationStatus
from iemu.tabs.memory_mappings_tab import MemoryMappingsTab
from iemu.tabs.stack_view_tab import StackViewTab
from iemu.tabs.memory_view_tab import MemoryViewTab

from iemu.util.util import verify_hex_string

instance_id = 0
sidebar_widget_instances = {}


class EmulatorSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data: BinaryView):
        global instance_id
        sidebar_widget_instances[data] = self

        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        if data.arch.name not in get_arch_mapping():
            log.log_error("Unsupported architecture")
            return

        self.prev_highlights = []
        self.emulator_state = EmulatorState()
        self.emulator_state.binary_view.set(data)

        self.checkpoint_regs = {}
        self.checkpoint_sections = None
        self.checkpoint_sections_data = {}
        self.checkpoint_memory = None
        self.checkpoint_memory_data = {}

        for reg in get_registers_for_mapping(data.arch.name):
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
        initialize_button.setStyleSheet("background-color: #357C4C")
        initialize_button.clicked.connect(self.initialize_button_clicked)
        control_layout.addWidget(initialize_button)

        run_button = QPushButton("Run")
        run_button.setStyleSheet("background-color: #77C16C")
        run_button.clicked.connect(self.run_button_clicked)
        control_layout.addWidget(run_button)

        step_button = QPushButton("Step")
        step_button.setStyleSheet("background-color: #F6B26B")
        step_button.clicked.connect(self.step_button_clicked)
        control_layout.addWidget(step_button)

        checkpoint_button = QPushButton("Checkpoint")
        checkpoint_button.setStyleSheet("background-color: #5F93BF")
        checkpoint_button.clicked.connect(self.checkpoint_button_clicked)
        control_layout.addWidget(checkpoint_button)

        restart_button = QPushButton("Load Checkpoint")
        restart_button.setStyleSheet("background-color: #9CC3E0")
        restart_button.clicked.connect(self.restart_button_clicked)
        control_layout.addWidget(restart_button)

        clear_button = QPushButton("Clear")
        clear_button.setStyleSheet("background-color: #A1A1A1")
        clear_button.clicked.connect(self.clear_button_clicked)
        control_layout.addWidget(clear_button)

        self.emulator_state.register_state.add_listener(self.monitor_rip_highlight)
        self.emulator_state.vm_status.add_listener(self.update_status_label)

        self.current_allocations = set()
        self.emulator_state.mapped_memory.add_listener(self.monitor_vm_memory)
        self.emulator_state.register_state.add_listener(self.monitor_vm_registers)

        layout.addWidget(self.control_widget)
        self.control_layout = control_layout

        self.setLayout(layout)
        self.emulator_state.binary_view.set(data)

        self.emulator_state.create_vm_instance()

        instance_id += 1

    def create_args_setup(self, bv: BinaryView, func: Function):
        dialog = QDialog()
        dialog.setWindowTitle("Setup Function Arguments")

        layout = QVBoxLayout()

        font = QFont("Courier")
        font.setPointSize(10)

        fixed_width = 160

        self.current_args = []
        for var in func.parameter_vars.vars:
            variable_layout = QHBoxLayout()

            variable_name = QLabel(f"{var.name}")
            variable_name.setStyleSheet("font-weight: bold;")
            variable_name.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            variable_layout.addWidget(variable_name)

            # initialize the default text value to the hex size of the variable
            if var.source_type == VariableSourceType.StackVariableSourceType:
                stack_offset = var.storage

                reg_offset_label = QLabel(f"+{hex(stack_offset)} [{hex(var.type.width)}]")
                reg_offset_label.setFont(font)
                reg_offset_value = QLineEdit(f"{0:0{var.type.width * 2}x}")
                reg_offset_value.setFixedWidth(fixed_width)

                reg_offset_value.setProperty("target_byte_width", var.type.width)
                reg_offset_value.editingFinished.connect(self.verify_and_update_text)
                self.current_args.append((var, reg_offset_value))

                variable_layout.addWidget(reg_offset_label)
                variable_layout.addWidget(reg_offset_value)

                layout.addLayout(variable_layout)
            elif var.source_type == VariableSourceType.RegisterVariableSourceType:
                register = bv.arch.get_reg_name(var.storage)

                reg_offset_label = QLabel(f"{register} [{hex(var.type.width)}]")
                reg_offset_label.setFont(font)
                reg_offset_value = QLineEdit(
                    verify_hex_string(hex(self.emulator_state.get_register(register.upper())), False, var.type.width))
                reg_offset_value.setFixedWidth(fixed_width)

                reg_offset_value.setProperty("target_byte_width", var.type.width)
                reg_offset_value.editingFinished.connect(self.verify_and_update_text)
                self.current_args.append((var, reg_offset_value))

                variable_layout.addWidget(reg_offset_label)
                variable_layout.addWidget(reg_offset_value)

                layout.addLayout(variable_layout)

            layout.addLayout(variable_layout)

        button_layout = QHBoxLayout()
        set_parameters_button = QPushButton("Set Parameters")
        button_layout.addWidget(set_parameters_button)
        set_parameters_button.clicked.connect(self.set_parameters_clicked)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.exec()

    def set_parameters_clicked(self):
        for (var, value) in self.current_args:
            value_width = var.type.width
            verified_value = int(verify_hex_string(value.text(), False, value_width), 16)

            if var.source_type == VariableSourceType.StackVariableSourceType:
                stack_offset = var.storage
                stack_pointer = get_stack_pointer_register(self.emulator_state.get_arch_name())
                stack_pointer_value = self.emulator_state.vm_read_reg(stack_pointer)

                stack_address = stack_pointer_value + stack_offset
                self.emulator_state.vm_inst.mem_write(stack_address,
                                                      verified_value.to_bytes(value_width, byteorder='big'))
            elif var.source_type == VariableSourceType.RegisterVariableSourceType:
                bv = self.emulator_state.binary_view.get()
                register = bv.arch.get_reg_name(var.storage)

                # TODO: Map Binja reg to Icicle reg, this is just hopeful
                self.emulator_state.set_register(register.upper(), verified_value)

        show_message_box("Success", "Parameters set successfully.", MessageBoxButtonSet.OKButtonSet,
                         MessageBoxIcon.InformationIcon)

    def verify_and_update_text(self):
        sender = self.sender()
        value_width = sender.property("target_byte_width")

        verified_text = verify_hex_string(sender.text(), False, value_width)
        sender.setText(verified_text)

    def initialize_button_clicked(self):
        status = self.emulator_state.vm_status.get()
        if status != EmulationStatus.Offline:
            show_message_box("Error", "Emulator is already initialized.",
                             MessageBoxButtonSet.OKButtonSet, )

        self.emulator_state.create_vm_instance()
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
            log.log_info(
                f"Mapped section region {hex(section.start)} - {hex(section.start + section.length)} {memory_attr}")

            bv = self.emulator_state.binary_view.get()
            self.emulator_state.vm_inst.mem_write(section.start, bv.read(section.start, section.length))
            log.log_info(
                f"Loaded section region {hex(section.start)} - {hex(section.start + section.length)} {memory_attr}")

        for allocation in memory:
            enabled, (start, length, permissions) = allocation
            if not enabled:
                continue

            self.emulator_state.vm_inst.mem_map(start, length, permissions)
            log.log_info(f"Mapped memory region {hex(start)} - {hex(start + length)} {permissions}")

        for (val, reg) in enumerate(regs):
            self.emulator_state.vm_write_reg(reg, val)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

    def run_button_clicked(self):
        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to run.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        ip = get_arch_instruction_pointer(self.emulator_state.get_arch_name())

        vm = self.emulator_state.vm_inst
        until = self.emulator_state.target_rip.get()
        if until != 0:
            log.log_info(f"Running VM from {ip}: {hex(self.emulator_state.vm_read_reg(ip))} to {ip}: {hex(until)}")
            status = vm.run_until(until)
        else:
            log.log_info(f"Running VM from {ip}: {hex(self.emulator_state.vm_read_reg(ip))}")
            status = vm.run()

        if status == icicle.RunStatus.UnhandledException:
            log.log_info(f"Status Code: {vm.exception_code}")

        log.log_info(f"Run concluded at {ip}: {hex(self.emulator_state.vm_read_reg(ip))}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = self.emulator_state.vm_read_reg(reg)

        self.emulator_state.register_state.set(reg_state)

        self.emulator_state.vm_status.set(EmulationStatus.Initialized)

    def step_button_clicked(self):
        if self.emulator_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Error", "Unable to step.",
                             MessageBoxButtonSet.OKButtonSet)
            return

        self.emulator_state.vm_status.set(EmulationStatus.Running)

        ip = get_arch_instruction_pointer(self.emulator_state.get_arch_name())

        vm = self.emulator_state.vm_inst
        log.log_info(f"Run started at at {ip}: {hex(self.emulator_state.vm_read_reg(ip))}")
        status = vm.step(1)

        if status == icicle.RunStatus.UnhandledException:
            log.log_info(f"Status Code: {vm.exception_code}")

        log.log_info(f"Run concluded at {ip}: {hex(self.emulator_state.vm_read_reg(ip))}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = self.emulator_state.vm_read_reg(reg)

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
            self.emulator_state.vm_write_reg(reg, value)
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

        self.emulator_state.create_vm_instance()
        log.log_info(f"Initialized VM {self.emulator_state.vm_inst}")

        reg_state = self.emulator_state.register_state.get()
        for (_, reg) in enumerate(self.emulator_state.register_state.get()):
            reg_state[reg] = 0

        self.emulator_state.register_state.set(reg_state)
        self.emulator_state.vm_status.set(EmulationStatus.Offline)

    def monitor_vm_memory(self, new_allocations: List[Tuple[bool, Tuple[int, int, PagePermissions]]]):
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
            (start, length, permissions) = allocation

            self.emulator_state.vm_inst.mem_unmap(start, length)
            log.log_info(f"Unmapped memory region {hex(start)} - {hex(start + length)} {permissions}")

        self.current_allocations = new_allocations_set

    def monitor_vm_registers(self, values):
        for reg in values:
            self.emulator_state.vm_write_reg(reg, values[reg])

    def update_status_label(self, status):
        self.status_label.setText(f"Status: {status.name}")

    def monitor_rip_highlight(self, values):
        for prev_highlight in self.prev_highlights:
            prev_highlight[0].set_auto_instr_highlight(prev_highlight[1], prev_highlight[2])
        self.prev_highlights.clear()

        arch_rip = get_arch_instruction_pointer(self.emulator_state.get_arch_name())

        rip = values[arch_rip]
        fun = self.emulator_state.binary_view.get().get_functions_containing(rip)

        if fun:
            previous_highlight = fun[0].get_instr_highlight(rip)
            fun[0].set_auto_instr_highlight(rip, highlight.HighlightColor(red=0, green=120, blue=0))

            self.prev_highlights.append((fun[0], rip, previous_highlight))

    def set_rip(self, rip):
        arch_rip = get_arch_instruction_pointer(self.emulator_state.get_arch_name())
        self.emulator_state.set_register(arch_rip, rip)

    def set_target_rip(self, rip):
        self.emulator_state.set_rip_target(rip)

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
        widget.set_rip(start)
        widget.set_target_rip(start + len)

        widget.run_button_clicked()
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


def address_handle_run(bv, start):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.set_rip(start)
        widget.set_target_rip(0)

        widget.run_button_clicked()
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


def update_rip(bv, start):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.set_rip(start)
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


def find_function_constants(bv, func):
    widget = sidebar_widget_instances.get(bv)
    if widget:
        widget.create_args_setup(bv, func)
    else:
        log.log_error("Unable to find iEmulator associated with the current BinaryView")


Sidebar.addSidebarWidgetType(EmulatorSidebarWidgetType())
PluginCommand.register_for_address("iEmu: Update RIP", "Update RIP register", update_rip)
PluginCommand.register_for_address("iEmu: Run from", "Update RIP register then run emulator", address_handle_run)
PluginCommand.register_for_range("iEmu: Run Selection", "Update RIP register then run emulator until highlight end",
                                 range_address_handle_run)

PluginCommand.register_for_function("iEmu: Setup Args", "Setup function argumee",
                                    find_function_constants)
