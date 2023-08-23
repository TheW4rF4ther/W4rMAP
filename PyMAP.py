import sys
import subprocess
from PyQt5 import QtWidgets
import PyQt5.QtWidgets


class NmapGUI(PyQt5.QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.summary_text = None
        self.result_text = None
        self.scan_button = None
        self.args_checkboxes = None
        self.args_group = None
        self.script_combo = None
        self.script_label = None
        self.args_input = None
        self.args_label = None
        self.browse_button = None
        self.target_file_input = None
        self.target_file_label = None
        self.ip_input = None
        self.ip_label = None
        self.layout = None
        self.central_widget = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('PyMAP - Created by W4rF4ther')
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = PyQt5.QtWidgets.QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = PyQt5.QtWidgets.QHBoxLayout(self.central_widget)

        self.left_layout = PyQt5.QtWidgets.QVBoxLayout()
        self.layout.addLayout(self.left_layout)

        self.setStyleSheet("background-color: #210405; color: white;")

        self.ip_label = PyQt5.QtWidgets.QLabel('IP Addresses (comma-separated):')
        self.ip_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.ip_label)

        self.ip_input = PyQt5.QtWidgets.QLineEdit()
        self.ip_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.ip_input)

        self.target_file_label = PyQt5.QtWidgets.QLabel('Target File:')
        self.target_file_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.target_file_label)

        self.target_file_input = PyQt5.QtWidgets.QLineEdit()
        self.target_file_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.target_file_input)

        self.browse_button = PyQt5.QtWidgets.QPushButton('Browse')
        self.browse_button.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.browse_button)
        self.browse_button.clicked.connect(self.browse_target_file)

        self.args_label = PyQt5.QtWidgets.QLabel('Nmap Command Line Arguments:')
        self.args_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.args_label)

        self.args_input = PyQt5.QtWidgets.QLineEdit()
        self.args_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.args_input)

        self.script_label = PyQt5.QtWidgets.QLabel('Nmap Script:')
        self.script_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.script_label)

        self.script_combo = PyQt5.QtWidgets.QComboBox()
        self.script_combo.addItem('No Script')
        self.populate_script_combo()
        self.left_layout.addWidget(self.script_combo)

        self.args_group = PyQt5.QtWidgets.QWidget()
        self.args_group.setLayout(PyQt5.QtWidgets.QVBoxLayout())
        self.left_layout.addWidget(self.args_group)

        self.args_checkboxes = [
            ('-v', 'Verbose'),
            ('-p-', 'All Ports'),
            ('-sV', 'Service Version'),
            ('-sC', 'Script Scan'),
            ('-T4', 'Aggressive Timing'),
            ('-A', 'All-in-One')
        ]

        for arg, label in self.args_checkboxes:
            checkbox = PyQt5.QtWidgets.QCheckBox(label)
            checkbox.setStyleSheet("color: white; background-color: transparent; border: 2px solid black;")
            self.args_group.layout().addWidget(checkbox)

        self.scan_button = PyQt5.QtWidgets.QPushButton('Run Nmap Scan')
        self.scan_button.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.scan_button)
        self.scan_button.clicked.connect(self.run_nmap_scan)

        self.result_text = PyQt5.QtWidgets.QTextEdit()
        self.result_text.setStyleSheet("background-color: black; color: white;")
        self.layout.addWidget(self.result_text)

    def populate_script_combo(self):
        common_scripts = [
            'http-title',
            'ssl-heartbleed',
            'dns-zone-transfer',
            'ftp-anon',
            'smb-os-discovery',
        ]
        for script in common_scripts:
            self.script_combo.addItem(script)

    def browse_target_file(self):
        options = PyQt5.QtWidgets.QFileDialog.Options()
        options |= PyQt5.QtWidgets.QFileDialog.ReadOnly
        file_path, _ = PyQt5.QtWidgets.QFileDialog.getOpenFileName(self, 'Select Target File', '', 'Text Files (*.txt)',
                                                                   options=options)
        if file_path:
            self.target_file_input.setText(file_path)

    def run_nmap_scan(self):
        ip_addresses = self.ip_input.text().split(',')
        target_file = self.target_file_input.text()
        custom_args = self.args_input.text()

        if not ip_addresses and not target_file:
            self.result_text.setPlainText('Please provide IP addresses or a target file.')
            return

        try:
            command = ['nmap']

            if target_file:
                with open(target_file, 'r') as file:
                    ip_addresses = [line.strip() for line in file if line.strip()]

            if ip_addresses:
                command.extend(ip_addresses)

            if custom_args:
                command.extend(custom_args.split())

            # Use subprocess.PIPE for both stdout and stderr
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                                       universal_newlines=True)

            while True:
                line = process.stdout.readline()
                if not line:
                    break
                self.result_text.append(line.rstrip())
                self.result_text.verticalScrollBar().setValue(
                    self.result_text.verticalScrollBar().maximum())  # Scroll to the bottom
                self.result_text.repaint()  # Update the GUI to show real-time output
                QtWidgets.QApplication.processEvents()  # Process other events to keep the GUI responsive

            process.communicate()  # Wait for the process to finish

            if process.returncode != 0:
                self.result_text.append(f"Process exited with error code: {process.returncode}")

        except Exception as e:
            self.result_text.setPlainText('Error: ' + str(e))


def main():
    app = PyQt5.QtWidgets.QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
