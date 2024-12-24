from binaryninja import *

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QGridLayout, QSpacerItem, QSizePolicy
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

from iemu.state.emulator_state import EmulatorState, EmulationStatus


class ContextTab(QWidget):
    def __init__(self, parent, state: EmulatorState):
        super().__init__(parent)
        self.state = state
        self.init_ui()

    def init_ui(self):
        context_layout = QVBoxLayout()
        context_layout.addWidget(QLabel("Name:"))
        self.name_label = QLabel()
        context_layout.addWidget(self.name_label)

        context_layout.addWidget(QLabel("Platform:"))
        self.platform_label = QLabel()
        context_layout.addWidget(self.platform_label)

        self.state.binary_view.add_listener(self.update_binary_view)

        register_layout = QGridLayout()
        self.register_textboxes = {}

        zero_hex_string = "0x0000000000000000"
        for i, reg in enumerate(self.state.register_state.get()):
            if reg == "RIP":
                continue

            label = QLabel(f"{reg}: ")
            textbox = QLineEdit(zero_hex_string)
            textbox.setAlignment(Qt.AlignLeft)
            textbox.setFont(QFont("Courier", 10))
            textbox.editingFinished.connect(self.validate_register_input)
            self.register_textboxes[reg] = textbox
            register_layout.addWidget(label, i // 2, (i % 2) * 2)
            register_layout.addWidget(textbox, i // 2, (i % 2) * 2 + 1)

        run_layout = QGridLayout()
        rip_label = QLabel("RIP: ")
        self.rip_textbox = QLineEdit(zero_hex_string)
        self.rip_textbox.setAlignment(Qt.AlignLeft)
        self.rip_textbox.setFont(QFont("Courier", 10))
        self.rip_textbox.editingFinished.connect(self.validate_register_input)
        self.register_textboxes["RIP"] = self.rip_textbox
        run_layout.addWidget(rip_label, 0, 0)
        run_layout.addWidget(self.rip_textbox, 0, 1)

        self.state.register_state.add_listener(self.update_register_textboxes)

        end_rip_label = QLabel("End RIP: ")
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
        self.platform_label.setText(str(view.platform))

    def update_register_textboxes(self, registers):
        for reg, value in registers.items():
            self.register_textboxes[reg].setText(f"0x{value:016x}")

    def update_target_rip(self, target):
        self.end_rip_textbox.setText(f"0x{target:016x}")

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