from typing import Mapping
from binaryninja import *

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QHeaderView, QSpacerItem, QSizePolicy, \
    QCheckBox, QHBoxLayout, QTableWidgetItem, QMenu, QLineEdit, QComboBox, QPushButton
from PySide6.QtCore import Qt

from iemu.state.emulator_state import EmulatorState, EmulationStatus, PagePermissions
from iemu.util.util import verify_hex_string

class MemoryMappingsTab(QWidget):
    def __init__(self, parent, state: EmulatorState):
        super().__init__(parent)

        self.context_state = state
        self.init_ui()

    def init_ui(self):
        memory_mappings_layout = QVBoxLayout()
        memory_mappings_layout.addWidget(QLabel("Sections"))

        self.sections_table = QTableWidget()
        self.sections_table.setColumnCount(5)
        self.sections_table.setHorizontalHeaderLabels(["Load", "Name", "Start", "Length", "Semantics"])
        self.sections_table.horizontalHeader().setStretchLastSection(True)
        self.sections_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.sections_table.setColumnWidth(0, 30)
        self.sections_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        memory_mappings_layout.addWidget(self.sections_table)

        self.context_state.binary_view.add_listener(self.update_binary_view)

        memory_mappings_layout.addWidget(QLabel("Allocations"))

        self.allocations_table = QTableWidget()
        self.allocations_table.setColumnCount(3)
        self.allocations_table.setHorizontalHeaderLabels(["Start", "Length", "Semantics"])
        self.allocations_table.horizontalHeader().setStretchLastSection(True)
        self.allocations_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.allocations_table.setColumnWidth(0, 30)
        self.allocations_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.allocations_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.allocations_table.customContextMenuRequested.connect(self.show_allocation_context_menu)
        memory_mappings_layout.addWidget(self.allocations_table)

        self.context_state.mapped_memory.add_listener(self.update_allocations_table)

        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Address")
        self.length_input = QLineEdit()
        self.length_input.setPlaceholderText("Length")
        self.permissions_input = QComboBox()
        self.permissions_input.addItems(["READ", "WRITE", "EXECUTE", "READ|WRITE", "READ|EXECUTE", "READ|WRITE|EXECUTE"])

        self.allocate_button = QPushButton("Allocate Memory")
        self.allocate_button.clicked.connect(self.allocate_memory)

        self.address_input.editingFinished.connect(self.verify_and_update_text)
        self.length_input.editingFinished.connect(self.verify_and_update_text)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.address_input)
        input_layout.addWidget(self.length_input)
        input_layout.addWidget(self.permissions_input)
        input_layout.addWidget(self.allocate_button)

        memory_mappings_layout.addLayout(input_layout)
        memory_mappings_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(memory_mappings_layout)

    def update_binary_view(self, view):
        sections : Mapping[str, Section] = view.sections

        self.sections_table.clearContents()
        self.sections_table.setRowCount(len(sections))

        for row, (name, section) in enumerate(reversed(list(sections.items()))):
            checkbox = QCheckBox()
            checkbox.setEnabled(True)
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(lambda state, sec=section: self.toggle_section(state, sec))

            container_widget = QWidget()
            layout = QHBoxLayout(container_widget)
            layout.addWidget(checkbox)
            layout.setAlignment(Qt.AlignCenter)
            layout.setContentsMargins(0, 0, 0, 0)

            self.sections_table.setCellWidget(row, 0, container_widget)
            name_item = QTableWidgetItem(section.name)
            name_item.setData(Qt.UserRole, section)

            self.sections_table.setItem(row, 1, QTableWidgetItem(name_item))
            self.sections_table.setItem(row, 2, QTableWidgetItem(hex(section.start)))
            self.sections_table.setItem(row, 3, QTableWidgetItem(hex(section.length)))
            self.sections_table.setItem(row, 4, QTableWidgetItem(section.semantics.name))

            self.context_state.add_section(section)

        self.sections_table.setColumnWidth(0, 30)

    def toggle_section(self, state, section):
        if state == Qt.Unchecked and self.context_state.vm_status.get() != EmulationStatus.Offline:
            # prevent unchecking if the emulator is not offline
            checkbox = self.sender()
            checkbox.blockSignals(True)
            checkbox.setChecked(True)
            checkbox.blockSignals(False)
            return

        self.context_state.modify_section(section, state == Qt.Checked)

    def show_allocation_context_menu(self, position):
        menu = QMenu()
        delete_action = menu.addAction("Delete Allocation")
        action = menu.exec_(self.allocations_table.viewport().mapToGlobal(position))

        if action == delete_action:
            self.delete_selected_allocation()

    def delete_selected_allocation(self):
        selected_items = self.allocations_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        start_item = self.allocations_table.item(row, 0)
        length_item = self.allocations_table.item(row, 1)

        # sketchy i know, not my problem
        if start_item and length_item:
            start = int(start_item.text(), 16)
            length = int(length_item.text(), 16)
            self.delete_allocation(start, length)

    def update_allocations_table(self, allocations):
        self.allocations_table.clearContents()
        self.allocations_table.setRowCount(len(allocations))

        for row, (enabled, (start, length, permissions)) in enumerate(allocations):
            container_widget = QWidget()
            layout = QHBoxLayout(container_widget)
            layout.setAlignment(Qt.AlignCenter)
            layout.setContentsMargins(0, 0, 0, 0)

            self.allocations_table.setItem(row, 0, QTableWidgetItem(hex(start)))
            self.allocations_table.setItem(row, 1, QTableWidgetItem(hex(length)))
            self.allocations_table.setItem(row, 2, QTableWidgetItem(permissions.name))

        self.allocations_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def delete_allocation(self, start, length):
        self.context_state.remove_allocation(start, length)

    def toggle_allocation(self, state, start, length, permissions):
        self.context_state.modify_allocation(start, length, permissions, state == Qt.Checked)

    def verify_and_update_text(self):
        sender = self.sender()

        verified_text = verify_hex_string(sender.text())
        sender.setText(verified_text)

    def allocate_memory(self):
        if self.context_state.vm_status.get() == EmulationStatus.Offline:
            show_message_box("Allocation Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        try:
            start = int(self.address_input.text(), 16)
            length = int(self.length_input.text(), 16)

            if self.context_state.is_memory_overlapping(start, length):
                show_message_box("Allocation Error", "Memory region overlaps with existing memory.",
                                 MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
                return

            permissions = self.permissions_input.currentText()

            if permissions == "READ":
                perm_flag = PagePermissions.READ
            elif permissions == "WRITE":
                perm_flag = PagePermissions.WRITE
            elif permissions == "EXECUTE":
                perm_flag = PagePermissions.EXECUTE
            elif permissions == "READ|WRITE":
                perm_flag = PagePermissions.READ | PagePermissions.WRITE
            elif permissions == "READ|EXECUTE":
                perm_flag = PagePermissions.READ | PagePermissions.EXECUTE
            elif permissions == "READ|WRITE|EXECUTE":
                perm_flag = PagePermissions.READ | PagePermissions.WRITE | PagePermissions.EXECUTE
            else:
                perm_flag = PagePermissions.NO_ACCESS

            self.context_state.add_allocation(start, length, perm_flag)
        except ValueError:
            log.log_info("Invalid input for address or length")