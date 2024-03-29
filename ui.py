# Виджеты автоматически сгенерированые QtDesigner

from PyQt5 import QtCore, QtGui, QtWidgets



class MainWindow(QtWidgets.QMainWindow):

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1274, 470)
        self.central_widget = QtWidgets.QWidget(MainWindow)
        self.central_widget.setObjectName("central_widget")
        self.main_layout = QtWidgets.QGridLayout(self.central_widget)
        self.main_layout.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
        self.main_layout.setObjectName("main_layout")
        self.buttons_layout = QtWidgets.QHBoxLayout()
        self.buttons_layout.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)
        self.buttons_layout.setObjectName("buttons_layout")
        self.server_buttons_layout = QtWidgets.QHBoxLayout()
        self.server_buttons_layout.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)
        self.server_buttons_layout.setContentsMargins(0, -1, 0, -1)
        self.server_buttons_layout.setSpacing(6)
        self.server_buttons_layout.setObjectName("server_buttons_layout")
        self.btn_start_server = QtWidgets.QPushButton(self.central_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_start_server.sizePolicy().hasHeightForWidth())
        self.btn_start_server.setSizePolicy(sizePolicy)
        self.btn_start_server.setBaseSize(QtCore.QSize(480, 210))
        self.btn_start_server.setObjectName("btn_start_server")
        self.server_buttons_layout.addWidget(self.btn_start_server)
        self.btn_stop_server = QtWidgets.QPushButton(self.central_widget)
        self.btn_stop_server.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_stop_server.sizePolicy().hasHeightForWidth())
        self.btn_stop_server.setSizePolicy(sizePolicy)
        self.btn_stop_server.setObjectName("btn_stop_server")
        self.server_buttons_layout.addWidget(self.btn_stop_server)
        self.buttons_layout.addLayout(self.server_buttons_layout)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.buttons_layout.addItem(spacerItem)
        self.table_buttons_layout = QtWidgets.QHBoxLayout()
        self.table_buttons_layout.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)
        self.table_buttons_layout.setContentsMargins(0, -1, -1, -1)
        self.table_buttons_layout.setObjectName("table_buttons_layout")
        self.btn_add = QtWidgets.QPushButton(self.central_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_add.sizePolicy().hasHeightForWidth())
        self.btn_add.setSizePolicy(sizePolicy)
        self.btn_add.setObjectName("btn_add")
        self.table_buttons_layout.addWidget(self.btn_add)
        self.btn_remove = QtWidgets.QPushButton(self.central_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_remove.sizePolicy().hasHeightForWidth())
        self.btn_remove.setSizePolicy(sizePolicy)
        self.btn_remove.setObjectName("btn_remove")
        self.table_buttons_layout.addWidget(self.btn_remove)
        self.btn_change = QtWidgets.QPushButton(self.central_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_change.sizePolicy().hasHeightForWidth())
        self.btn_change.setSizePolicy(sizePolicy)
        self.btn_change.setObjectName("btn_change")
        self.table_buttons_layout.addWidget(self.btn_change)
        self.buttons_layout.addLayout(self.table_buttons_layout)
        self.main_layout.addLayout(self.buttons_layout, 2, 1, 1, 1)
        self.line = QtWidgets.QFrame(self.central_widget)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.main_layout.addWidget(self.line, 1, 1, 1, 1)
        self.devices_table = QtWidgets.QTableWidget(self.central_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.devices_table.sizePolicy().hasHeightForWidth())
        self.devices_table.setSizePolicy(sizePolicy)
        self.devices_table.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.devices_table.setFrameShape(QtWidgets.QFrame.Box)
        self.devices_table.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.devices_table.setMidLineWidth(1)
        self.devices_table.setDragDropOverwriteMode(False)
        self.devices_table.setShowGrid(True)
        self.devices_table.setGridStyle(QtCore.Qt.SolidLine)
        self.devices_table.setWordWrap(False)
        self.devices_table.setObjectName("devices_table")
        self.devices_table.setColumnCount(5)
        self.devices_table.setRowCount(1)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.devices_table.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.devices_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        font.setStrikeOut(False)
        font.setKerning(False)
        item.setFont(font)
        self.devices_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.devices_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.devices_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.devices_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.devices_table.setItem(0, 0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
        self.devices_table.setItem(0, 1, item)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setKerning(True)
        item.setFont(font)
        item.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
        self.devices_table.setItem(0, 2, item)
        item = QtWidgets.QTableWidgetItem()
        item.setFlags(QtCore.Qt.ItemIsEnabled)
        self.devices_table.setItem(0, 3, item)
        item = QtWidgets.QTableWidgetItem()
        item.setFlags(QtCore.Qt.ItemIsEnabled)
        self.devices_table.setItem(0, 4, item)
        self.devices_table.horizontalHeader().setVisible(True)
        self.devices_table.horizontalHeader().setCascadingSectionResizes(True)
        self.devices_table.horizontalHeader().setDefaultSectionSize(200)
        self.devices_table.horizontalHeader().setHighlightSections(False)
        self.devices_table.horizontalHeader().setMinimumSectionSize(100)
        self.devices_table.horizontalHeader().setSortIndicatorShown(False)
        self.devices_table.horizontalHeader().setStretchLastSection(False)
        self.devices_table.verticalHeader().setVisible(True)
        self.devices_table.verticalHeader().setCascadingSectionResizes(True)
        self.devices_table.verticalHeader().setStretchLastSection(False)
        self.main_layout.addWidget(self.devices_table, 0, 1, 1, 1)
        MainWindow.setCentralWidget(self.central_widget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1274, 21))
        self.menubar.setDefaultUp(False)
        self.menubar.setObjectName("menubar")
        self.file_menu = QtWidgets.QMenu(self.menubar)
        self.file_menu.setObjectName("file_menu")
        self.settings_menu = QtWidgets.QMenu(self.menubar)
        self.settings_menu.setObjectName("settings_menu")
        self.help_menu = QtWidgets.QMenu(self.menubar)
        self.help_menu.setObjectName("help_menu")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.act_open = QtWidgets.QAction(MainWindow)
        self.act_open.setObjectName("open")
        self.act_save = QtWidgets.QAction(MainWindow)
        self.act_save.setObjectName("save")
        self.act_save_as = QtWidgets.QAction(MainWindow)
        self.act_save_as.setObjectName("save_as")
        self.exit = QtWidgets.QAction(MainWindow)
        self.exit.setMenuRole(QtWidgets.QAction.QuitRole)
        self.exit.setObjectName("exit")
        self.act_about = QtWidgets.QAction(MainWindow)
        self.act_about.setObjectName("about")
        self.act_manual = QtWidgets.QAction(MainWindow)
        self.act_manual.setObjectName("manual")
        self.act_conn_settings = QtWidgets.QAction(MainWindow)
        self.act_conn_settings.setObjectName("dataTrans")
        self.file_menu.addAction(self.act_open)
        self.file_menu.addSeparator()
        self.file_menu.addAction(self.act_save)
        self.file_menu.addAction(self.act_save_as)
        self.file_menu.addSeparator()
        self.file_menu.addAction(self.exit)
        self.settings_menu.addAction(self.act_conn_settings)
        self.help_menu.addAction(self.act_about)
        self.help_menu.addAction(self.act_manual)
        self.menubar.addAction(self.file_menu.menuAction())
        self.menubar.addAction(self.settings_menu.menuAction())
        self.menubar.addAction(self.help_menu.menuAction())

        self.retranslateUi(MainWindow)
        self.exit.triggered.connect(MainWindow.close)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        MainWindow.setTabOrder(self.btn_start_server, self.btn_change)
        MainWindow.setTabOrder(self.btn_change, self.devices_table)
        MainWindow.setTabOrder(self.devices_table, self.btn_stop_server)
        MainWindow.setTabOrder(self.btn_stop_server, self.btn_add)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Сервер сбора данных Тензо-М"))
        self.btn_start_server.setText(_translate("MainWindow", "Запуск сервера"))
        self.btn_stop_server.setText(_translate("MainWindow", "Остановка сервера"))
        self.btn_add.setText(_translate("MainWindow", "Добавить"))
        self.btn_remove.setText(_translate("MainWindow", "Удалить"))
        self.btn_change.setText(_translate("MainWindow", "Изменить"))
        item = self.devices_table.verticalHeaderItem(0)
        item.setText(_translate("MainWindow", "1"))
        item = self.devices_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Название"))
        item = self.devices_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Адрес весового контроллера"))
        item = self.devices_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Тип массы"))
        item = self.devices_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Значение массы"))
        item = self.devices_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Статус"))
        __sortingEnabled = self.devices_table.isSortingEnabled()
        self.devices_table.setSortingEnabled(False)
        item = self.devices_table.item(0, 0)
        item.setText(_translate("MainWindow", "Танк 24"))
        item = self.devices_table.item(0, 1)
        item.setText(_translate("MainWindow", "1"))
        item = self.devices_table.item(0, 2)
        item.setText(_translate("MainWindow", "Нетто"))
        item = self.devices_table.item(0, 3)
        item.setText(_translate("MainWindow", "0.0"))
        item = self.devices_table.item(0, 4)
        item.setText(_translate("MainWindow", "нет"))
        self.devices_table.setSortingEnabled(__sortingEnabled)
        self.file_menu.setTitle(_translate("MainWindow", "Файл"))
        self.settings_menu.setTitle(_translate("MainWindow", "Настройки"))
        self.help_menu.setTitle(_translate("MainWindow", "Справка"))
        self.act_open.setText(_translate("MainWindow", "Открыть"))
        self.act_save.setText(_translate("MainWindow", "Сохранить"))
        self.act_save_as.setText(_translate("MainWindow", "Сохранить как"))
        self.exit.setText(_translate("MainWindow", "Выход"))
        self.act_about.setText(_translate("MainWindow", "О программе"))
        self.act_manual.setText(_translate("MainWindow", "Руководство"))
        self.act_conn_settings.setText(_translate("MainWindow", "Передача данных"))


class DeviceDialog(QtWidgets.QDialog):

    def setupUi(self, Add_change_device):
        Add_change_device.setObjectName("Add_change_device")
        Add_change_device.setWindowModality(QtCore.Qt.WindowModal)
        Add_change_device.resize(262, 162)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Add_change_device.sizePolicy().hasHeightForWidth())
        Add_change_device.setSizePolicy(sizePolicy)
        Add_change_device.setMinimumSize(QtCore.QSize(262, 162))
        Add_change_device.setMaximumSize(QtCore.QSize(262, 162))
        font = QtGui.QFont()
        font.setPointSize(12)
        Add_change_device.setFont(font)
        Add_change_device.setModal(True)
        self.main_layout = QtWidgets.QGridLayout(Add_change_device)
        self.main_layout.setHorizontalSpacing(10)
        self.main_layout.setObjectName("main_layout")
        self.lbl_mass_type = QtWidgets.QLabel(Add_change_device)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lbl_mass_type.sizePolicy().hasHeightForWidth())
        self.lbl_mass_type.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lbl_mass_type.setFont(font)
        self.lbl_mass_type.setObjectName("lbl_mass_type")
        self.main_layout.addWidget(self.lbl_mass_type, 2, 0, 1, 2)
        self.lbl_device_addr = QtWidgets.QLabel(Add_change_device)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lbl_device_addr.setFont(font)
        self.lbl_device_addr.setObjectName("lbl_device_addr")
        self.main_layout.addWidget(self.lbl_device_addr, 1, 0, 1, 1)
        self.cmx_mass_type = QtWidgets.QComboBox(Add_change_device)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_mass_type.setFont(font)
        self.cmx_mass_type.setObjectName("cmx_mass_type")
        self.cmx_mass_type.addItem("")
        self.cmx_mass_type.addItem("")
        self.main_layout.addWidget(self.cmx_mass_type, 2, 3, 1, 1)
        self.spx_device_addr = QtWidgets.QSpinBox(Add_change_device)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.spx_device_addr.setFont(font)
        self.spx_device_addr.setMinimum(1)
        self.spx_device_addr.setMaximum(127)
        self.spx_device_addr.setObjectName("spx_device_addr")
        self.main_layout.addWidget(self.spx_device_addr, 1, 3, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("server_buttons_layout")
        self.btn_ok = QtWidgets.QPushButton(Add_change_device)
        self.btn_ok.setMaximumSize(QtCore.QSize(75, 23))
        self.btn_ok.setObjectName("btn_ok")
        self.horizontalLayout.addWidget(self.btn_ok)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.btn_cancel = QtWidgets.QPushButton(Add_change_device)
        self.btn_cancel.setMaximumSize(QtCore.QSize(75, 23))
        self.btn_cancel.setObjectName("btn_cancel")
        self.horizontalLayout.addWidget(self.btn_cancel)
        self.main_layout.addLayout(self.horizontalLayout, 4, 0, 1, 4)
        self.lne_device_name = QtWidgets.QLineEdit(Add_change_device)
        self.lne_device_name.setMaxLength(20)
        self.lne_device_name.setObjectName("lne_device_name")
        self.main_layout.addWidget(self.lne_device_name, 0, 3, 1, 1)
        self.lbl_dev_name = QtWidgets.QLabel(Add_change_device)
        self.lbl_dev_name.setObjectName("lbl_dev_name")
        self.main_layout.addWidget(self.lbl_dev_name, 0, 0, 1, 1)

        self.retranslateUi(Add_change_device)
        self.btn_cancel.clicked.connect(Add_change_device.close)
        QtCore.QMetaObject.connectSlotsByName(Add_change_device)

    def retranslateUi(self, Add_change_device):
        _translate = QtCore.QCoreApplication.translate
        if self.add_mode:
            Add_change_device.setWindowTitle(_translate("Add_change_device", "Добавить устройство"))
        else:
            Add_change_device.setWindowTitle(_translate("Add_change_device", "Изменить устройство"))
        self.lbl_mass_type.setText(_translate("Add_change_device", "Тип массы:"))
        self.lbl_device_addr.setText(_translate("Add_change_device", "Адрес:"))
        self.cmx_mass_type.setItemText(0, _translate("Add_change_device", "Нетто"))
        self.cmx_mass_type.setItemText(1, _translate("Add_change_device", "Брутто"))
        self.btn_ok.setText(_translate("Add_change_device", "OK"))
        self.btn_cancel.setText(_translate("Add_change_device", "Отмена"))
        self.lbl_dev_name.setText(_translate("Add_change_device", "Название"))

class SettingsDialog(QtWidgets.QDialog):

    def setupUi(self, Dialog):
        self.int_validator = QtGui.QIntValidator()
        self.float_validator = QtGui.QDoubleValidator()
        self.float_validator.setNotation(QtGui.QDoubleValidator.StandardNotation)
        Dialog.setObjectName("Dialog")
        Dialog.setWindowModality(QtCore.Qt.WindowModal)
        Dialog.resize(340, 445)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Dialog.sizePolicy().hasHeightForWidth())
        Dialog.setSizePolicy(sizePolicy)
        Dialog.setMinimumSize(QtCore.QSize(340, 445))
        Dialog.setMaximumSize(QtCore.QSize(340, 445))
        Dialog.setSizeGripEnabled(False)
        Dialog.setModal(True)
        self.main_layout = QtWidgets.QGridLayout(Dialog)
        self.main_layout.setVerticalSpacing(0)
        self.main_layout.setObjectName("main_layout")
        self.tcp_settings_layout = QtWidgets.QFormLayout()
        self.tcp_settings_layout.setHorizontalSpacing(130)
        self.tcp_settings_layout.setObjectName("tcp_settings_layout")
        self.lbl_ip_addr = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_ip_addr.setFont(font)
        self.lbl_ip_addr.setObjectName("lbl_ip_addr")
        self.tcp_settings_layout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.lbl_ip_addr)
        self.lne_ip_addr = QtWidgets.QLineEdit(Dialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lne_ip_addr.sizePolicy().hasHeightForWidth())
        self.lne_ip_addr.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lne_ip_addr.setFont(font)
        self.lne_ip_addr.setInputMask("000.000.000.000")
        self.lne_ip_addr.setValidator(self.int_validator)
        self.lne_ip_addr.setInputMethodHints(QtCore.Qt.ImhFormattedNumbersOnly)
        self.lne_ip_addr.setMaxLength(15)
        self.lne_ip_addr.setObjectName("lne_ip_addr")
        self.tcp_settings_layout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.lne_ip_addr)
        self.lbl_ip_port = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_ip_port.setFont(font)
        self.lbl_ip_port.setObjectName("lbl_ip_port")
        self.tcp_settings_layout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.lbl_ip_port)
        self.lne_ip_port = QtWidgets.QLineEdit(Dialog)
        self.lne_ip_port.setValidator(self.int_validator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lne_ip_port.sizePolicy().hasHeightForWidth())
        self.lne_ip_port.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lne_ip_port.setFont(font)
        self.lne_ip_port.setInputMethodHints(QtCore.Qt.ImhDigitsOnly)
        self.lne_ip_port.setMaxLength(5)
        self.lne_ip_port.setObjectName("lne_ip_port")
        self.tcp_settings_layout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.lne_ip_port)
        self.main_layout.addLayout(self.tcp_settings_layout, 8, 0, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.main_layout.addItem(spacerItem, 4, 0, 1, 1)
        self.serial_settings_layout = QtWidgets.QFormLayout()
        self.serial_settings_layout.setHorizontalSpacing(50)
        self.serial_settings_layout.setObjectName("serial_settings_layout")
        self.lbl_serial_port = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_serial_port.setFont(font)
        self.lbl_serial_port.setObjectName("lbl_mass_type")
        self.serial_settings_layout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.lbl_serial_port)
        self.lbl_data_bits = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_data_bits.setFont(font)
        self.lbl_data_bits.setObjectName("lbl_data_bits")
        self.serial_settings_layout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.lbl_data_bits)
        self.lbl_baudrate = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_baudrate.setFont(font)
        self.lbl_baudrate.setObjectName("lbl_dev_name")
        self.serial_settings_layout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.lbl_baudrate)
        self.lbl_stop_bits = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_stop_bits.setFont(font)
        self.lbl_stop_bits.setObjectName("lbl_stop_bits")
        self.serial_settings_layout.setWidget(3, QtWidgets.QFormLayout.LabelRole, self.lbl_stop_bits)
        self.cmx_com_port = QtWidgets.QComboBox(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_com_port.setFont(font)
        self.cmx_com_port.setObjectName("cmx_com_port")
        self.serial_settings_layout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.cmx_com_port)
        self.cmx_data_bits = QtWidgets.QComboBox(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_data_bits.setFont(font)
        self.cmx_data_bits.setObjectName("cmx_data_bits")
        self.cmx_data_bits.addItem("")
        self.cmx_data_bits.addItem("")
        self.cmx_data_bits.addItem("")
        self.cmx_data_bits.addItem("")
        self.cmx_data_bits.addItem("")
        self.serial_settings_layout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.cmx_data_bits)
        self.cmx_baud_rate = QtWidgets.QComboBox(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_baud_rate.setFont(font)
        self.cmx_baud_rate.setObjectName("cmx_baud_rate")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.cmx_baud_rate.addItem("")
        self.serial_settings_layout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.cmx_baud_rate)
        self.cmx_stop_bits = QtWidgets.QComboBox(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_stop_bits.setFont(font)
        self.cmx_stop_bits.setObjectName("cmx_stop_bits")
        self.cmx_stop_bits.addItem("")
        self.cmx_stop_bits.addItem("")
        self.cmx_stop_bits.addItem("")
        self.serial_settings_layout.setWidget(3, QtWidgets.QFormLayout.FieldRole, self.cmx_stop_bits)
        self.cmx_parity = QtWidgets.QComboBox(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.cmx_parity.setFont(font)
        self.cmx_parity.setObjectName("cmx_parity")
        self.cmx_parity.addItem("")
        self.cmx_parity.addItem("")
        self.cmx_parity.addItem("")
        self.cmx_parity.addItem("")
        self.cmx_parity.addItem("")
        self.serial_settings_layout.setWidget(4, QtWidgets.QFormLayout.FieldRole, self.cmx_parity)
        self.lbl_parity = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_parity.setFont(font)
        self.lbl_parity.setObjectName("lbl_parity")
        self.serial_settings_layout.setWidget(4, QtWidgets.QFormLayout.LabelRole, self.lbl_parity)
        self.lbl_timeout = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_timeout.setFont(font)
        self.lbl_timeout.setObjectName("lbl_timeout")
        self.serial_settings_layout.setWidget(5, QtWidgets.QFormLayout.LabelRole, self.lbl_timeout)
        self.lne_timeout = QtWidgets.QLineEdit(Dialog)
        self.lne_timeout.setValidator(self.float_validator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lne_timeout.sizePolicy().hasHeightForWidth())
        self.lne_timeout.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lne_timeout.setFont(font)
        self.lne_timeout.setMaxLength(5)
        self.lne_timeout.setObjectName("lne_timeout")
        self.serial_settings_layout.setWidget(5, QtWidgets.QFormLayout.FieldRole, self.lne_timeout)

        self.lbl_autostart = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.lbl_autostart.setFont(font)
        self.lbl_autostart.setObjectName("lbl_autostart")
        self.serial_settings_layout.setWidget(6, QtWidgets.QFormLayout.LabelRole, self.lbl_autostart)


        self.chb_autostart = QtWidgets.QCheckBox(Dialog)
        self.chb_autostart.setSizePolicy(sizePolicy)
        self.chb_autostart.setMinimumSize(QtCore.QSize(80, 30))
        self.chb_autostart.setFont(font)
        self.chb_autostart.setTabletTracking(False)
        self.chb_autostart.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.chb_autostart.setText("")
        self.chb_autostart.setIconSize(QtCore.QSize(30, 30))
        self.chb_autostart.setObjectName("chb_autostart")
        self.chb_autostart.setStyleSheet("QCheckBox::indicator"
                               "{"
                               "width :20px;"
                               "height : 20px;"
                               "}")
        self.serial_settings_layout.setWidget(6, QtWidgets.QFormLayout.FieldRole, self.chb_autostart)

        self.main_layout.addLayout(self.serial_settings_layout, 1, 0, 1, 1)
        self.lbl_header_ip = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("Droid Sans Fallback")
        font.setPointSize(14)
        font.setItalic(True)
        self.lbl_header_ip.setFont(font)
        self.lbl_header_ip.setObjectName("lbl_header_ip")
        self.main_layout.addWidget(self.lbl_header_ip, 5, 0, 1, 1)
        self.line_2 = QtWidgets.QFrame(Dialog)
        self.line_2.setMidLineWidth(1)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.main_layout.addWidget(self.line_2, 6, 0, 1, 1)
        self.header_layout = QtWidgets.QVBoxLayout()
        self.header_layout.setObjectName("header_layout")
        self.lbl_header_serial = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("Droid Sans Fallback")
        font.setPointSize(14)
        font.setItalic(True)
        self.lbl_header_serial.setFont(font)
        self.lbl_header_serial.setObjectName("lbl_device_addr")
        self.header_layout.addWidget(self.lbl_header_serial)
        self.line = QtWidgets.QFrame(Dialog)
        self.line.setMidLineWidth(1)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.header_layout.addWidget(self.line)
        self.main_layout.addLayout(self.header_layout, 0, 0, 1, 1)
        self.buttons_layout = QtWidgets.QHBoxLayout()
        self.buttons_layout.setObjectName("buttons_layout")
        self.btn_ok = QtWidgets.QPushButton(Dialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_ok.sizePolicy().hasHeightForWidth())
        self.btn_ok.setSizePolicy(sizePolicy)
        self.btn_ok.setMinimumSize(QtCore.QSize(75, 23))
        self.btn_ok.setMaximumSize(QtCore.QSize(75, 23))
        self.btn_ok.setObjectName("btn_ok")
        self.buttons_layout.addWidget(self.btn_ok)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.buttons_layout.addItem(spacerItem1)
        self.btn_cancel = QtWidgets.QPushButton(Dialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_cancel.sizePolicy().hasHeightForWidth())
        self.btn_cancel.setSizePolicy(sizePolicy)
        self.btn_cancel.setMinimumSize(QtCore.QSize(75, 23))
        self.btn_cancel.setMaximumSize(QtCore.QSize(75, 23))
        self.btn_cancel.setObjectName("btn_cancel")
        self.buttons_layout.addWidget(self.btn_cancel)
        self.main_layout.addLayout(self.buttons_layout, 10, 0, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.main_layout.addItem(spacerItem2, 9, 0, 1, 1)

        self.retranslateUi(Dialog)
        self.btn_cancel.clicked.connect(Dialog.close)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Настройки"))
        self.lbl_ip_addr.setText(_translate("Dialog", "Адрес:"))
        self.lbl_ip_port.setText(_translate("Dialog", "Порт:"))
        self.lbl_serial_port.setText(_translate("Dialog", "Порт:"))
        self.lbl_data_bits.setText(_translate("Dialog", "Биты данных:"))
        self.lbl_baudrate.setText(_translate("Dialog", "Скорость (бит/с):"))
        self.lbl_stop_bits.setText(_translate("Dialog", "Стоповые биты:"))
        self.cmx_data_bits.setItemText(0, _translate("Dialog", "4"))
        self.cmx_data_bits.setItemText(1, _translate("Dialog", "5"))
        self.cmx_data_bits.setItemText(2, _translate("Dialog", "6"))
        self.cmx_data_bits.setItemText(3, _translate("Dialog", "7"))
        self.cmx_data_bits.setItemText(4, _translate("Dialog", "8"))
        self.cmx_baud_rate.setItemText(0, _translate("Dialog", "1200"))
        self.cmx_baud_rate.setItemText(1, _translate("Dialog", "1800"))
        self.cmx_baud_rate.setItemText(2, _translate("Dialog", "2400"))
        self.cmx_baud_rate.setItemText(3, _translate("Dialog", "4800"))
        self.cmx_baud_rate.setItemText(4, _translate("Dialog", "7200"))
        self.cmx_baud_rate.setItemText(5, _translate("Dialog", "9600"))
        self.cmx_baud_rate.setItemText(6, _translate("Dialog", "14400"))
        self.cmx_baud_rate.setItemText(7, _translate("Dialog", "19200"))
        self.cmx_baud_rate.setItemText(8, _translate("Dialog", "38400"))
        self.cmx_baud_rate.setItemText(9, _translate("Dialog", "57600"))
        self.cmx_baud_rate.setItemText(10, _translate("Dialog", "115200"))
        self.cmx_baud_rate.setItemText(11, _translate("Dialog", "128000"))
        self.cmx_stop_bits.setItemText(0, _translate("Dialog", "1"))
        self.cmx_stop_bits.setItemText(1, _translate("Dialog", "1.5"))
        self.cmx_stop_bits.setItemText(2, _translate("Dialog", "2"))
        self.cmx_parity.setItemText(0, _translate("Dialog", "Нет"))
        self.cmx_parity.setItemText(1, _translate("Dialog", "Even"))
        self.cmx_parity.setItemText(2, _translate("Dialog", "Odd"))
        self.cmx_parity.setItemText(3, _translate("Dialog", "Mark"))
        self.cmx_parity.setItemText(4, _translate("Dialog", "Space"))
        self.lbl_parity.setText(_translate("Dialog", "Четность:"))
        self.lbl_timeout.setText(_translate("Dialog", "Таймаут, сек:"))
        self.lbl_header_ip.setText(_translate("Dialog", "TCP сервер"))
        self.lbl_header_serial.setText(_translate("Dialog", "Последовательный порт"))
        self.lbl_autostart.setText(_translate("Dialog", "Автозапуск"))
        self.btn_ok.setText(_translate("Dialog", "ОК"))
        self.btn_cancel.setText(_translate("Dialog", "Отмена"))

