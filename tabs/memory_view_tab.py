from binaryninja import *

import icicle

from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, \
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy, QDialog, QFileDialog
from PySide6.QtGui import QFont, QKeyEvent
from PySide6.QtCore import Qt

import codecs

from iemu.state.emulator_state import EmulationStatus
from iemu.util.util import verify_hex_string
from iemu.state.mappings import get_arch_endianness


class MemoryViewTab(QWidget):
    def __init__(self, parent, emulator_state):
        super().__init__(parent)
        self.context_state = emulator_state
        self.init_ui()

    def init_ui(self):
        memory_view_layout = QVBoxLayout()

        memory_view_controls_layout = QHBoxLayout()
        self.memory_view_address_input = QLineEdit("0x1000")
        self.memory_view_length_input = QLineEdit("0x100")
        self.memory_view_size_dropdown = QComboBox()
        self.memory_view_size_dropdown.addItems(["1", "2", "4", "8"])
        self.memory_view_size_dropdown.setCurrentText("1")
        self.memory_view_total_size_dropdown = QComboBox()
        self.memory_view_total_size_dropdown.addItems(["8", "16"])
        self.memory_view_total_size_dropdown.setCurrentText("8")
        self.memory_view_button = QPushButton("View")
        self.memory_view_button.clicked.connect(self.view_memory)
        self.memory_dump_button = QPushButton("Dump")
        self.memory_dump_button.clicked.connect(self.dump_memory_dialog)

        memory_view_controls_layout.addWidget(QLabel("Address:"))
        memory_view_controls_layout.addWidget(self.memory_view_address_input)
        memory_view_controls_layout.addWidget(QLabel("Length:"))
        memory_view_controls_layout.addWidget(self.memory_view_length_input)
        memory_view_controls_layout.addWidget(QLabel("Size:"))
        memory_view_controls_layout.addWidget(self.memory_view_size_dropdown)
        memory_view_controls_layout.addWidget(QLabel("Bytes:"))
        memory_view_controls_layout.addWidget(self.memory_view_total_size_dropdown)
        memory_view_controls_layout.addWidget(self.memory_view_button)
        memory_view_controls_layout.addWidget(self.memory_dump_button)

        self.memory_view_address_input.editingFinished.connect(self.verify_and_update_text)
        self.memory_view_length_input.editingFinished.connect(self.verify_and_update_text)

        memory_view_layout.addLayout(memory_view_controls_layout)

        self.memory_view_table = QTableWidget()
        self.memory_view_table.setHorizontalHeaderLabels([""])
        self.memory_view_table.horizontalHeader().setStretchLastSection(True)
        self.memory_view_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.memory_view_table.verticalHeader().setVisible(False)
        self.memory_view_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.memory_view_table.cellChanged.connect(self.write_memory)
        self.memory_view_table.installEventFilter(self)
        memory_view_layout.addWidget(self.memory_view_table)

        self.write_string_button = QPushButton("Write String")
        self.write_string_button.clicked.connect(self.show_write_string_dialog)
        memory_view_layout.addWidget(self.write_string_button)

        self.setLayout(memory_view_layout)

    def verify_and_update_text(self):
        sender = self.sender()

        verified_text = verify_hex_string(sender.text())
        sender.setText(verified_text)

    def view_memory(self):
        address = int(self.memory_view_address_input.text(), 16)
        length = int(self.memory_view_length_input.text(), 16)

        cell_bytes = int(self.memory_view_size_dropdown.currentText())
        row_bytes = int(self.memory_view_total_size_dropdown.currentText())

        num_columns = row_bytes // cell_bytes
        self.memory_view_table.setColumnCount(num_columns + 2)
        self.memory_view_table.setHorizontalHeaderLabels(
            ["Address"] + [f"{i * cell_bytes:X}" for i in range(num_columns)] + ["ASCII"])

        self.memory_view_table.setRowCount(0)

        self.memory_view_table.setFrameStyle(0)
        self.memory_view_table.setShowGrid(False)

        # remove grid lines
        self.memory_view_table.setGridStyle(Qt.NoPen)

        # remove ellipsis
        self.memory_view_table.setTextElideMode(Qt.ElideNone)

        # set column resize mode
        self.memory_view_table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.memory_view_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for col in range(1, num_columns + 1):
            self.memory_view_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.memory_view_table.horizontalHeader().setSectionResizeMode(num_columns + 1, QHeaderView.Stretch)

        # this is such a hack i dont even watn to talk about it.
        # temporarily disconnect the cellChanged signal
        self.memory_view_table.blockSignals(True)

        for offset in range(0, length, row_bytes):
            row_position = self.memory_view_table.rowCount()
            self.memory_view_table.insertRow(row_position)

            address_item = QTableWidgetItem(f"{address + offset:08x}")
            address_item.setFlags(address_item.flags() & ~Qt.ItemIsEditable)
            address_item.setTextAlignment(Qt.AlignLeft)

            self.memory_view_table.setItem(row_position, 0, address_item)

            ascii_representation = ""
            for col in range(num_columns):
                cell_address = address + offset + (col * cell_bytes)
                try:
                    value = self.context_state.vm_inst.mem_read(cell_address, cell_bytes)
                    if cell_bytes == 1:
                        value_hex = f"{value[0]:02x}"
                        ascii_representation += chr(value[0]) if 32 <= value[0] <= 126 else "."
                    else:
                        byte_order = get_arch_endianness(self.context_state.get_arch_name())

                        value_int = int.from_bytes(value, byteorder=byte_order)
                        value_hex = f"{value_int:0{cell_bytes * 2}x}"
                        ascii_representation += ''.join(chr(b) if 32 <= b <= 126 else "." for b in value)
                except icicle.MemoryException:
                    value_hex = "?" * (cell_bytes * 2)
                    ascii_representation += "."

                value_item = QTableWidgetItem(value_hex)
                value_item.setTextAlignment(Qt.AlignCenter)
                if value_hex == "?" * (cell_bytes * 2):
                    value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
                self.memory_view_table.setItem(row_position, col + 1, value_item)

            ascii_item = QTableWidgetItem(ascii_representation)
            ascii_item.setFlags(ascii_item.flags() & ~Qt.ItemIsEditable)
            ascii_item.setTextAlignment(Qt.AlignLeft)
            ascii_item.setFont(QFont("Courier", 10))
            self.memory_view_table.setItem(row_position, num_columns + 1, ascii_item)

        self.memory_view_table.blockSignals(False)

        # another hack because i cannot get the grid to be small enough
        # set the row height to the height of the font
        font_metrics = self.memory_view_table.fontMetrics()
        row_height = font_metrics.height()
        for row in range(self.memory_view_table.rowCount()):
            self.memory_view_table.setRowHeight(row, row_height)

    def write_memory(self, row, column):
        if column == 0 or column >= self.memory_view_table.columnCount() - 1:
            return

        address_item = self.memory_view_table.item(row, 0)
        address = int(address_item.text(), 16) + (column - 1) * int(self.memory_view_size_dropdown.currentText())
        new_value_hex = self.memory_view_table.item(row, column).text()

        try:
            size = int(self.memory_view_size_dropdown.currentText())

            # truncate the hex string to the correct size
            byte_order = get_arch_endianness(self.context_state.get_arch_name())

            new_value_hex = new_value_hex[:size * 2]
            new_value = int(new_value_hex, 16)
            new_value_bytes = new_value.to_bytes(size, byteorder=byte_order)
            self.context_state.vm_inst.mem_write(address, new_value_bytes)

            # update the cell with the truncated value
            self.memory_view_table.item(row, column).setText(new_value_hex.zfill(size * 2))

            # update ascii representation
            ascii_item = self.memory_view_table.item(row, self.memory_view_table.columnCount() - 1)
            if ascii_item is not None:
                ascii_representation = list(ascii_item.text())
                for i in range(size):
                    byte_value = new_value_bytes[i]
                    if (column - 1) * size + i < len(ascii_representation):
                        ascii_representation[(column - 1) * size + i] = chr(
                            byte_value) if 32 <= byte_value <= 126 else '.'
                ascii_item.setText(''.join(ascii_representation))

        except ValueError:
            # revert to original value if invalid input
            original_value = self.context_state.vm_inst.mem_read(address, size)
            original_value_hex = ''.join(f'{byte:02x}' for byte in original_value)
            item = self.memory_view_table.item(row, column)
            if item is not None:
                item.setText(original_value_hex)

    def eventFilter(self, source, event):
        if event.type() == QKeyEvent.KeyPress and event.key() == Qt.Key_Return:
            current_row = self.memory_view_table.currentRow()
            current_column = self.memory_view_table.currentColumn()
            num_columns = self.memory_view_table.columnCount() - 2  # exclude address and ascii columns

            if current_column < num_columns:
                self.memory_view_table.setCurrentCell(current_row, current_column + 1)
            elif current_row < self.memory_view_table.rowCount() - 1:
                self.memory_view_table.setCurrentCell(current_row + 1, 1)
            else:
                self.memory_view_table.clearSelection()
            return True

        return super().eventFilter(source, event)

    def show_write_string_dialog(self):
        if self.context_state.vm_status.get() == EmulationStatus.Offline:
            show_message_box("Write Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Write String")
        layout = QVBoxLayout()

        address_layout = QHBoxLayout()
        address_label = QLabel("Address:")
        self.address_input = QLineEdit()
        address_layout.addWidget(address_label)
        address_layout.addWidget(self.address_input)

        self.address_input.editingFinished.connect(self.verify_and_update_text)

        string_layout = QHBoxLayout()
        string_label = QLabel("String:")
        self.string_input = QLineEdit()
        string_layout.addWidget(string_label)
        string_layout.addWidget(self.string_input)

        write_button = QPushButton("Write")
        write_button.clicked.connect(self.write_string_to_memory)

        layout.addLayout(address_layout)
        layout.addLayout(string_layout)
        layout.addWidget(write_button)

        dialog.setLayout(layout)
        dialog.exec()

    def write_string_to_memory(self):
        address_text = self.address_input.text()
        string_text = self.string_input.text()

        try:
            address = int(address_text, 16)
        except ValueError:
            show_message_box("Error", "Invalid address format.", MessageBoxButtonSet.OKButtonSet,
                             MessageBoxIcon.ErrorIcon)
            return

        try:
            string_bytes = codecs.escape_decode(bytes(string_text, "utf-8"))[0]
        except Exception as e:
            show_message_box("Error", f"Failed to decode string: {e}", MessageBoxButtonSet.OKButtonSet,
                             MessageBoxIcon.ErrorIcon)
            return

        try:
            self.context_state.vm_inst.mem_write(address, string_bytes)
            show_message_box("Success", "String written to memory.", MessageBoxButtonSet.OKButtonSet,
                             MessageBoxIcon.InformationIcon)
        except icicle.MemoryException:
            show_message_box("Error", "Failed to write to memory.", MessageBoxButtonSet.OKButtonSet,
                             MessageBoxIcon.ErrorIcon)

    def dump_memory_dialog(self):
        if self.context_state.vm_status.get() == EmulationStatus.Offline:
            show_message_box("Dump Error", "VM is not initialized.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Dump Memory")
        layout = QVBoxLayout()

        address_layout = QHBoxLayout()
        address_label = QLabel("Address:")
        self.dump_address_input = QLineEdit()
        address_layout.addWidget(address_label)
        address_layout.addWidget(self.dump_address_input)
        self.dump_address_input.setText(self.memory_view_address_input.text())

        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.dump_length_input = QLineEdit()
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.dump_length_input)
        self.dump_address_input.setText(self.memory_view_length_input.text())

        self.dump_address_input.editingFinished.connect(self.verify_and_update_text)
        self.dump_length_input.editingFinished.connect(self.verify_and_update_text)

        dump_button = QPushButton("Dump")
        dump_button.clicked.connect(self.dump_memory)

        layout.addLayout(address_layout)
        layout.addLayout(length_layout)
        layout.addWidget(dump_button)

        dialog.setLayout(layout)
        dialog.exec()

    def dump_memory(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            address_text = self.dump_address_input.text()
            length_text = self.dump_length_input.text()

            try:
                address = int(address_text, 16)
                length = int(length_text, 16)
            except ValueError:
                show_message_box("Error", "Invalid address format.", MessageBoxButtonSet.OKButtonSet,
                                 MessageBoxIcon.ErrorIcon)
                return

            try:
                memory_bytes = self.context_state.vm_inst.mem_read(address, length)
                with open(file_path, "wb") as f:
                    f.write(memory_bytes)

                show_message_box("Success", "Memory dumped to file.", MessageBoxButtonSet.OKButtonSet,
                                 MessageBoxIcon.InformationIcon)
            except icicle.MemoryException as e:
                log.log_error(e)
                show_message_box("Error", "Failed to read memory.", MessageBoxButtonSet.OKButtonSet,
                                 MessageBoxIcon.ErrorIcon)

                return
            except Exception as e:
                log.log_error(e)
                show_message_box("Error", "Failed to write to file.", MessageBoxButtonSet.OKButtonSet,
                                 MessageBoxIcon.ErrorIcon)

                return

        show_message_box("Success", "Memory has been dumped to file.", MessageBoxButtonSet.OKButtonSet,
                         MessageBoxIcon.InformationIcon)