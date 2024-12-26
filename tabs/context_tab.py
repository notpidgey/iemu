from binaryninja import *

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QGridLayout, QSpacerItem, QSizePolicy
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

from iemu.state.emulator_state import EmulatorState, EmulationStatus

from iemu.state.mappings import get_arch_instruction_pointer, get_registers_for_mapping

class ContextTab(QWidget):
    def __init__(self, parent, state: EmulatorState):
        super().__init__(parent)
        self.register_textboxes = {}
        self.state = state
        self.init_ui()

    def init_ui(self):
        context_layout = QVBoxLayout()
        context_layout.addWidget(QLabel("Name:"))
        self.name_label = QLabel()
        context_layout.addWidget(self.name_label)

        context_layout.addWidget(QLabel("Arch:"))
        self.arch_label = QLabel()
        context_layout.addWidget(self.arch_label)

        self.state.binary_view.add_listener(self.update_binary_view)

        register_layout = QGridLayout()
        run_layout = QGridLayout()

        arch = self.state.get_arch_name()
        mappings = get_registers_for_mapping(arch)
        rip_name = get_arch_instruction_pointer(arch)

        for i, (reg, size) in enumerate(mappings.items()):
            # create an empty hex string given the size of the register
            zero_hex_string = "0x" + "0" * (size // 8 * 2)

            if reg == rip_name:
                rip_label = QLabel(f"{rip_name}: ")
                self.rip_textbox = QLineEdit(zero_hex_string)
                self.rip_textbox.setAlignment(Qt.AlignLeft)
                self.rip_textbox.setFont(QFont("Courier", 10))
                self.rip_textbox.editingFinished.connect(self.validate_register_input)
                run_layout.addWidget(rip_label, 0, 0)
                run_layout.addWidget(self.rip_textbox, 0, 1)

                textbox = self.rip_textbox
            else:
                label = QLabel(f"{reg}: ")
                textbox = QLineEdit(zero_hex_string)
                textbox.setAlignment(Qt.AlignLeft)
                textbox.setFont(QFont("Courier", 10))
                textbox.editingFinished.connect(self.validate_register_input)

                register_layout.addWidget(label, i // 2, (i % 2) * 2)
                register_layout.addWidget(textbox, i // 2, (i % 2) * 2 + 1)

            self.register_textboxes[reg] = textbox

        self.state.register_state.add_listener(self.update_register_textboxes)

        end_rip_label = QLabel(f"{rip_name} Target: ")
        self.end_rip_textbox = QLineEdit(zero_hex_string)
        self.end_rip_textbox.setAlignment(Qt.AlignLeft)
        self.end_rip_textbox.setFont(QFont("Courier", 10))
        self.end_rip_textbox.editingFinished.connect(self.validate_register_input)
        run_layout.addWidget(end_rip_label, 1, 0)
        run_layout.addWidget(self.end_rip_textbox, 1, 1)

        self.state.target_rip.add_listener(self.update_target_rip)

        context_layout.addLayout(register_layout)
        context_layout.addItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Minimum))
        context_layout.addLayout(run_layout)
        context_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.setLayout(context_layout)

    def update_binary_view(self, view):
        self.name_label.setText(str(os.path.basename(view.file.filename)))
        self.arch_label.setText(str(view.arch.name))

    def update_register_textboxes(self, registers):
        arch = self.state.get_arch_name()
        mappings = get_registers_for_mapping(arch)

        for reg, value in registers.items():
            character_counter = int(mappings[reg] / 8 * 2)
            self.register_textboxes[reg].setText(f"0x{value:0{character_counter}x}")

    def update_target_rip(self, target):
        arch = self.state.get_arch_name()
        mappings = get_registers_for_mapping(arch)

        character_counter = int(mappings[get_arch_instruction_pointer(arch)] / 8 * 2)
        self.end_rip_textbox.setText(f"0x{target:0{character_counter}x}")

    def validate_register_input(self):
        if self.state.vm_status.get() == EmulationStatus.Running:
            show_message_box("Warning", "Cannot modify registers while the VM is running.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

        sender = self.sender()
        text = sender.text()

        if not text.startswith("0x"):
            text = "0x" + text

        try:
            value = int(text, 16)
        except ValueError:
            value = 0

        sender.blockSignals(True)
        if sender != self.end_rip_textbox:
            for reg, textbox in self.register_textboxes.items():
                if textbox == sender:
                    self.state.set_register(reg, value)
        else:
            self.state.target_rip.set(value)
        sender.blockSignals(False)