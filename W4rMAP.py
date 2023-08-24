import sys
import subprocess
from PyQt5 import QtWidgets, QtGui, QtCore
import PyQt5.QtWidgets
import PyQt5.QtCore
from PyQt5.QtGui import QPixmap
import base64

class NmapGUI(PyQt5.QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.right_layout = None
        self.right_widget = None
        self.left_layout = None
        self.left_widget = None
        self.splitter = None
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
        self.thread_pool = None  # Thread pool for managing tasks
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('W4rMAP - Created by W4rF4ther')
        self.setGeometry(100, 100, 1000, 600)  # Increased the width for a larger output section

        self.central_widget = PyQt5.QtWidgets.QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = PyQt5.QtWidgets.QHBoxLayout(self.central_widget)

        self.splitter = PyQt5.QtWidgets.QSplitter(self.central_widget)
        self.layout.addWidget(self.splitter)

        self.left_widget = PyQt5.QtWidgets.QWidget()
        self.left_layout = PyQt5.QtWidgets.QVBoxLayout(self.left_widget)
        self.splitter.addWidget(self.left_widget)

        self.right_widget = PyQt5.QtWidgets.QWidget()
        self.right_layout = PyQt5.QtWidgets.QVBoxLayout(self.right_widget)
        self.splitter.addWidget(self.right_widget)

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
            ('-A', 'All-in-One'),
            ('-Pn', 'Skip Host Discovery'),
            ('-O', 'OS Detection'),
            ('-sU', 'UDP Scan')
        ]

        checkbox_layout = None  # To hold the layout for each row of checkboxes
        for i, (arg, label) in enumerate(self.args_checkboxes):
            if i % 2 == 0:  # Start a new row after every 3 checkboxes
                if checkbox_layout:
                    self.args_group.layout().addLayout(checkbox_layout)
                checkbox_layout = PyQt5.QtWidgets.QHBoxLayout()

            checkbox = PyQt5.QtWidgets.QCheckBox(label)
            checkbox.setStyleSheet("color: white; background-color: transparent; border: 2px solid black;")
            checkbox_layout.addWidget(checkbox)

        # Add the last row of checkboxes if needed
        if checkbox_layout:
            self.args_group.layout().addLayout(checkbox_layout)

        self.scan_button = PyQt5.QtWidgets.QPushButton('Run Nmap Scan')
        self.scan_button.setStyleSheet("color: white;")
        self.left_layout.addWidget(self.scan_button)
        self.scan_button.clicked.connect(self.run_nmap_scan)

        self.result_text = PyQt5.QtWidgets.QTextEdit()
        self.result_text.setStyleSheet("background-color: black; color: white;")
        self.right_layout.addWidget(self.result_text)

        self.thread_pool = PyQt5.QtCore.QThreadPool()  # Initialize the thread pool

        logo_base64 = '''
               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
           '''
        logo_data = QtCore.QByteArray.fromBase64(logo_base64.encode())
        pixmap = QtGui.QPixmap()
        pixmap.loadFromData(logo_data)

        new_size = pixmap.size() * 0.50
        pixmap = pixmap.scaled(new_size, QtCore.Qt.KeepAspectRatio)
        logo_label = QtWidgets.QLabel(self)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)
        self.left_layout.addWidget(logo_label)

    def populate_script_combo(self):
        common_scripts = [
            'http-title',
            'ssl-heartbleed',
            'dns-zone-transfer',
            'ftp-anon',
            'smb-os-discovery',
            'banner',
            ''
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

            # Get selected checkboxes and add their corresponding arguments to the command
            selected_args = [arg for arg, label in self.args_checkboxes if any(
                cb.text() == label for cb in self.args_group.findChildren(PyQt5.QtWidgets.QCheckBox) if cb.isChecked())]
            command.extend(selected_args)

            if custom_args:
                command.extend(custom_args.split())

            self.scan_button.setEnabled(False)  # Disable the scan button while the scan is running

            def run_scan_task():
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                           bufsize=1, universal_newlines=True)

                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    PyQt5.QtCore.QMetaObject.invokeMethod(self.result_text, "append", PyQt5.QtCore.Q_ARG(str, line))
                    QtWidgets.QApplication.processEvents()

                process.communicate()
                if process.returncode != 0:
                    error_message = f"Process exited with error code: {process.returncode}"
                    PyQt5.QtCore.QMetaObject.invokeMethod(self.result_text, "append",
                                                          PyQt5.QtCore.Q_ARG(str, error_message))

                self.scan_button.setEnabled(True)

            self.thread_pool.start(run_scan_task)  # Start the scan task in a separate thread

        except Exception as e:
            self.result_text.setPlainText('Error: ' + str(e))

            def run_scan_task():
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                           bufsize=1, universal_newlines=True)

                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    PyQt5.QtCore.QMetaObject.invokeMethod(self.result_text, "append", PyQt5.QtCore.Q_ARG(str, line))
                    QtWidgets.QApplication.processEvents()

                process.communicate()
                if process.returncode != 0:
                    error_message = f"Process exited with error code: {process.returncode}"
                    PyQt5.QtCore.QMetaObject.invokeMethod(self.result_text, "append", PyQt5.QtCore.Q_ARG(str, error_message))

                self.scan_button.setEnabled(True)

            self.thread_pool.start(run_scan_task)  # Start the scan task in a separate thread

        except Exception as e:
            self.result_text.setPlainText('Error: ' + str(e))


def main():
    app = PyQt5.QtWidgets.QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
