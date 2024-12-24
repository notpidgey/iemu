from binaryninja import *

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, \
    QComboBox, QSizePolicy, QAbstractItemView, QHeaderView, QTableWidgetItem, QApplication
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

import icicle

from iemu.util.util import verify_hex_string
from iemu.state.emulator_state import EmulatorState, PagePermissions, EmulationStatus


class StackViewTab(QWidget):
    def __init__(self, parent, state: EmulatorState):
        super().__init__(parent)

        self.context_state = state
        self.init_ui()

    def init_ui(self):
        stack_view_tab_layout = QVBoxLayout()
        stack_creator_layout = QHBoxLayout()

        self.stack_address_textbox = QLineEdit("0x1000")
        self.stack_length_textbox = QLineEdit("0x1000")
        self.stack_start_textbox = QLineEdit("0x1500")
        self.allocate_stack_button = QPushButton("Allocate stack")
        self.allocate_stack_button.clicked.connect(self.allocate_stack)

        self.stack_address_textbox.editingFinished.connect(self.verify_and_update_text)
        self.stack_length_textbox.editingFinished.connect(self.verify_and_update_text)
        self.stack_start_textbox.editingFinished.connect(self.verify_and_update_text)

        stack_creator_layout.addWidget(QLabel("Address:"))
        stack_creator_layout.addWidget(self.stack_address_textbox)
        stack_creator_layout.addWidget(QLabel("Length:"))
        stack_creator_layout.addWidget(self.stack_length_textbox)
        stack_creator_layout.addWidget(QLabel("RSP:"))
        stack_creator_layout.addWidget(self.stack_start_textbox)
        stack_creator_layout.addWidget(self.allocate_stack_button)

        stack_view_tab_layout.addLayout(stack_creator_layout)

        stack_view_controls_layout = QHBoxLayout()
        self.stack_address_input = QLineEdit("0x1500")
        self.row_count_dropdown = QComboBox()
        self.row_count_dropdown.addItems(["1", "2", "4", "8", "16", "32", "64", "128", "256"])
        self.row_count_dropdown.setCurrentText("8")
        self.view_button = QPushButton("View")
        self.view_button.clicked.connect(self.view_stack)

        stack_view_controls_layout.addWidget(QLabel("View Address:"))
        stack_view_controls_layout.addWidget(self.stack_address_input)
        stack_view_controls_layout.addWidget(QLabel("Number of Rows:"))
        stack_view_controls_layout.addWidget(self.row_count_dropdown)
        stack_view_controls_layout.addWidget(self.view_button)

        self.stack_address_input.editingFinished.connect(self.verify_and_update_text)

        stack_view_tab_layout.addLayout(stack_view_controls_layout)

        self.stack_view_table = QTableWidget()
        self.stack_view_table.setColumnCount(2)
        self.stack_view_table.setHorizontalHeaderLabels(["Address", "Value"])
        self.stack_view_table.horizontalHeader().setStretchLastSection(True)
        self.stack_view_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stack_view_table.verticalHeader().setVisible(False)
        self.stack_view_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.stack_view_table.itemChanged.connect(self.update_stack_value)
        stack_view_tab_layout.addWidget(self.stack_view_table)

        self.setLayout(stack_view_tab_layout)

    def verify_and_update_text(self):
        sender = self.sender()

        verified_text = verify_hex_string(sender.text())
        sender.setText(verified_text)

    def allocate_stack(self):
        if self.context_state.vm_status.get() != EmulationStatus.Initialized:
            show_message_box("Allocation Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        address = int(self.stack_address_textbox.text(), 16)
        length = int(self.stack_length_textbox.text(), 16)
        start = int(self.stack_start_textbox.text(), 16)

        if self.context_state.is_memory_overlapping(address, length):
            show_message_box("Allocation Error", "Memory region overlaps with existing memory.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        self.context_state.add_allocation(address, length, PagePermissions.READ | PagePermissions.WRITE)
        self.context_state.set_register("RSP", start)

        show_message_box("Memory Allocated", "RSP has been updated to starting address",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

    def view_stack(self):
        vm = self.context_state.vm_inst
        if not vm:
            show_message_box("View Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        stack_address = int(self.stack_address_input.text(), 16)
        row_count = int(self.row_count_dropdown.currentText())

        # Temporarily disconnect the itemChanged signal
        self.stack_view_table.itemChanged.disconnect(self.update_stack_value)

        # clear the table
        self.stack_view_table.setRowCount(0)

        for i in range(-row_count, row_count + 1):
            address = stack_address + (i * 8)
            if address < 0:
                continue

            try:
                value = vm.mem_read(address, 8)
                value_hex = ''.join(f'{byte:02x}' for byte in value)
                editable = True
            except icicle.MemoryException:
                value_hex = "ERR: UNMAPPED"
                editable = False

            row_position = self.stack_view_table.rowCount()
            self.stack_view_table.insertRow(row_position)
            address_item = QTableWidgetItem(hex(address))
            value_item = QTableWidgetItem(value_hex)

            address_item.setFlags(address_item.flags() & ~Qt.ItemIsEditable)
            if not editable:
                value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)

            address_item.setTextAlignment(Qt.AlignLeft)
            address_item.setFont(QFont("Courier", 10))
            value_item.setTextAlignment(Qt.AlignLeft)
            value_item.setFont(QFont("Courier", 10))

            self.stack_view_table.setItem(row_position, 0, address_item)
            self.stack_view_table.setItem(row_position, 1, value_item)

        # set the row height to the height of the font
        font_metrics = self.stack_view_table.fontMetrics()
        row_height = font_metrics.height()
        for row in range(self.stack_view_table.rowCount()):
            self.stack_view_table.setRowHeight(row, row_height)

        QApplication.processEvents()
        self.stack_view_table.scrollToItem(
            self.stack_view_table.item(row_count, 0), QAbstractItemView.PositionAtCenter)

        # Reconnect the itemChanged signal
        self.stack_view_table.itemChanged.connect(self.update_stack_value)

    def update_stack_value(self, item):
        if self.context_state.vm_status.get() == EmulationStatus.Offline:
            show_message_box("View Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        row = item.row()
        column = item.column()

        vm = self.context_state.vm_inst
        if column == 1:
            address_item = self.stack_view_table.item(row, 0)
            address = int(address_item.text(), 16)

            new_value_hex = item.text()

            try:
                new_value = int(new_value_hex, 16)
                new_value_hex = f"{new_value:016x}"
            except ValueError:
                original_value = vm.mem_read(address, 8)
                original_value_hex = ''.join(f'{byte:02x}' for byte in original_value)
                item.setText(original_value_hex)
                return

            vm.mem_write(address, new_value.to_bytes(8, byteorder='big'))
            item.setText(new_value_hex)