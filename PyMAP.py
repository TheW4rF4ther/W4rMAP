import sys
import subprocess
import re
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QTextEdit, QLineEdit, QLabel, QComboBox, QHBoxLayout, QFileDialog, QCheckBox

class NmapGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('PyMAP - Created by W4rF4ther')
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QHBoxLayout(self.central_widget)

        self.left_layout = QVBoxLayout()
        self.layout.addLayout(self.left_layout)

        self.right_layout = QVBoxLayout()
        self.layout.addLayout(self.right_layout)

        self.setStyleSheet("background-color: #210405; color: white;")

        self.ip_label = QLabel('IP Addresses (comma-separated):')
        self.ip_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.ip_label)

        self.ip_input = QLineEdit()
        self.ip_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.ip_input)

        self.target_file_label = QLabel('Target File:')
        self.target_file_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.target_file_label)

        self.target_file_input = QLineEdit()
        self.target_file_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.target_file_input)

        self.browse_button = QPushButton('Browse')
        self.browse_button.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.browse_button)
        self.browse_button.clicked.connect(self.browse_target_file)

        self.args_label = QLabel('Nmap Command Line Arguments:')
        self.args_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.args_label)

        self.args_input = QLineEdit()
        self.args_input.setStyleSheet("color: white; background-color: black;")
        self.left_layout.addWidget(self.args_input)

        self.script_label = QLabel('Nmap Script:')
        self.script_label.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.script_label)

        self.script_combo = QComboBox()
        self.script_combo.addItem('No Script')
        self.populate_script_combo()
        self.left_layout.addWidget(self.script_combo)

        self.args_group = QWidget()
        self.args_group.setLayout(QVBoxLayout())
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
            checkbox = QCheckBox(label)
            checkbox.setStyleSheet("color: white; background-color: transparent; border: 2px solid black;")
            self.args_group.layout().addWidget(checkbox)

        self.scan_button = QPushButton('Run Nmap Scan')
        self.scan_button.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.scan_button)
        self.scan_button.clicked.connect(self.run_nmap_scan)

        self.result_text = QTextEdit()
        self.result_text.setStyleSheet("background-color: black; color: white;")
        self.right_layout.addWidget(self.result_text)

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
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select Target File', '', 'Text Files (*.txt)', options=options)
        if file_path:
            self.target_file_input.setText(file_path)

    def run_nmap_scan(self):
        ip_addresses = self.ip_input.text().split(',')
        target_file = self.target_file_input.text()
        selected_script = self.script_combo.currentText()

        args = self.args_input.text()

        for arg, label in self.args_checkboxes:
            if self.find_child_widget_by_text(self.args_group, label).isChecked():
                args += f' {arg}'

        if not ip_addresses and not target_file:
            self.result_text.setPlainText('Please provide IP addresses or a target file.')
            return

        try:
            command = ['nmap', *args.split()]

            if selected_script != 'No Script':
                command.extend(['--script', selected_script])

            if target_file:
                with open(target_file, 'r') as file:
                    ip_addresses = [line.strip() for line in file if line.strip()]

            if ip_addresses:
                command.extend(ip_addresses)

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, _ = process.communicate()

            output_lines = output.decode().split('\n')
            colored_output = []

            for line in output_lines:
                line = line.replace('Discovered', '<span style="color: blue;">Discovered</span>')
                line = re.sub(r'PORT', r'<span style="color: #FFA500;">PORT</span>', line)
                line = re.sub(r'STATE', r'<span style="color: #FFA500;">STATE</span>', line)
                line = re.sub(r'(\d+/tcp) (open) (.+)', r'\1 \2 <span style="color: maroon;">\3</span>', line)
                colored_output.append(line)

            self.result_text.setHtml('<br>'.join(colored_output))

        except Exception as e:
            self.result_text.setPlainText('Error: ' + str(e))

    def find_child_widget_by_text(self, parent, text):
        for child in parent.findChildren(QCheckBox):
            if child.text() == text:
                return child
        return None

def main():
    app = QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
