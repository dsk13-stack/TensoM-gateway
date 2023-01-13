import json
import socket
import struct
import sys
import threading
import time
import serial
import logging

from PyQt5 import QtCore, QtGui, QtWidgets
from serial.tools import list_ports

import ui


DEFAULT_SETTINGS = ("COM1", "8", "9600", "1", "Нет", "1.0", "127.0.0.1", "2000", "False")
DEFAULT_SETTINGS_PATH = "settings.json"


logging.basicConfig(filename="app_log.log", filemode="w",
                    format="[%(asctime)s: %(levelname)s] %(message)s", level=logging.DEBUG)
logger = logging.getLogger(__name__)


def crc8(data: hex, poly: hex, crc: hex = 0) -> hex:
    data = data ^ crc
    for _ in range(8):
        if data & 0x80:
            data = (data << 1) ^ poly
        else:
            data = data << 1
    return data & 0xFF


def hex_to_binary(hex_number: str, num_digits: int = 8) -> str:
    return str(bin(int(hex_number, 16)))[2:].zfill(num_digits)


def get_weight(raw_data: bytearray) -> float:
    """
    Извлечение значения и знака массы из байтового сообщения прибора
    :param raw_data: сообщение от прибора в байтовом формате
    :return: значение измеренной массы
    """
    properties = list(int(bit) for bit in (hex_to_binary(str(raw_data[6:7].hex()), 8)))
    properties.reverse()
    weight = int(str((raw_data[5:6] + raw_data[4:5] + raw_data[3:4]).hex()))
    weight = weight / ((10 ** properties[0]) * (100 ** properties[1]) * (1000 ** properties[2]))
    return weight * (-1) if properties[7] else weight


class TcpServer:

    def __init__(self, ip: str, port: int):
        self.address = None
        self.connection = None
        self.sock = None
        self.ip = None
        self.port = None
        self.set_address(ip, port)

    def set_address(self, ip: str, port: int):
        socket.inet_aton(ip)
        socket.inet_pton(socket.AF_INET, ip)
        hostname = socket.getfqdn()
        *_, host_addresses = socket.gethostbyname_ex(hostname)
        host_addresses.append("127.0.0.1")
        if ip in host_addresses:
            self.ip = ip
            self.port = port  
        else:
            raise ValueError("Invalid IP")
 
    def connect(self) -> str:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(None)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(1)
        self.connection, self.address = self.sock.accept()
        return str(self.address)

    def send(self, data):
        self.connection.send(data)

    def receive(self, data_len):
        return self.connection.recv(data_len)

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()
        if self.sock is not None:
            self.sock.close()


class UiMainWindow(ui.MainWindow):
    """Главное окно приложения

    Главное окно приложения, виджеты сгенерированы QtDesigner и
    импрортируются из файла ui.
    Основная логика приложения также реализована в этом классе.

    """

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connect_actions()
        self.modify_widgets()  
        self.connection_enabled = False
        self.new_data_received = False
        self.config_file_path = DEFAULT_SETTINGS_PATH
        self.communication_settings = list(DEFAULT_SETTINGS)    
        self.server = TcpServer(
            self.communication_settings[6], int(self.communication_settings[7]))
        self.serial_thread = threading.Thread(
            target=self.serial_stream, args=(self.devices_table,), daemon=True)
        self.serial_thread.start()
        self.sock_thread = threading.Thread(
            target=self.sock_stream, args=(self.devices_table,), daemon=True)
        self.sock_thread.start()
        self.system_settings = self.open_config_file(self.config_file_path)
        if self.system_settings is not None:
            self.update_setting(self.system_settings)
            self.update_table(self.system_settings, self.devices_table)
            if self.communication_settings[8] == "True":
                self.start_connection()

    def connect_actions(self):
        self.act_open.triggered.connect(
            lambda: self.open_dialog(self.devices_table))
        self.act_save_as.triggered.connect(
            lambda: self.save_as_file_dialog(self.devices_table))
        self.act_save.triggered.connect(
            lambda: self.save_action(self.devices_table))
        self.btn_add.clicked.connect(
            lambda: self.add_dialog(self.devices_table))
        self.btn_change.clicked.connect(
            lambda: self.change_dialog(self.devices_table))
        self.btn_remove.clicked.connect(
            lambda: self.remove_row(self.devices_table))
        self.act_conn_settings.triggered.connect(self.settings_dialog)
        self.btn_start_server.clicked.connect(self.start_connection)
        self.btn_stop_server.clicked.connect(self.stop_connection)
        self.btn_stop_server.setEnabled(False)
        self.act_about.triggered.connect(self.about_dialog)

    def start_connection(self):
        self.act_conn_settings.setEnabled(False)
        self.btn_add.setEnabled(False)
        self.btn_remove.setEnabled(False)
        self.btn_change.setEnabled(False)
        self.act_open.setEnabled(False)
        self.act_save.setEnabled(False)
        self.act_save_as.setEnabled(False)
        self.btn_start_server.setEnabled(False)
        self.btn_stop_server.setEnabled(True)
        self.connection_enabled = True
        self.statusBar().showMessage("Сервер запущен")

    def stop_connection(self):
        self.act_conn_settings.setEnabled(True)
        self.btn_add.setEnabled(True)
        self.btn_remove.setEnabled(True)
        self.btn_change.setEnabled(True)
        self.act_open.setEnabled(True)
        self.act_save.setEnabled(True)
        self.act_save_as.setEnabled(True)
        self.btn_start_server.setEnabled(True)
        self.btn_stop_server.setEnabled(False)
        self.connection_enabled = False
        try:
            self.server.disconnect()
        except OSError:
            logger.exception("Ошибка закрытия соединения")
        self.statusBar().showMessage("Сервер остановлен")

    def modify_widgets(self):
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        self.devices_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

    def serial_stream(self, table: QtWidgets.QTableWidget):
        """RS485, протокол Тензо-М
        Циклическое чтение данных из устройств
        по последовательному интерфейсу.
        Читает и записывает данные в таблицу,
        устанавливает флаг self.new_data_received для TCP-сервера что данные обновлены.
        """
        ADDR_COLUMN = 1
        MASS_TYPE_COLUMN = 2
        DATA_COLUMN = 3
        STATUS_COLUMN = 4

        com_port_open = False
        serial_connection = None
        while True:
            if self.connection_enabled:
                try:
                    # Открытие COM-порта если он еще не был открыт
                    if not com_port_open:
                        port = self.communication_settings[0]
                        data_bits = int(self.communication_settings[1])
                        baud_rate = int(self.communication_settings[2])
                        parity = {"Нет": "N",
                                  "Even": "E",
                                  "Odd": "O",
                                  "Mark": "M",
                                  "Space": "S"}

                        stop_bits = int(self.communication_settings[3])
                        timeout = float(self.communication_settings[5])
                        serial_connection = serial.Serial(port, baud_rate, data_bits,
                                                          parity[self.communication_settings[4]],
                                                          stop_bits,
                                                          timeout=timeout)
                        com_port_open = True

                    row_count = table.rowCount()
                    for i in range(row_count):
                        message = []
                        addr = int(table.item(i, ADDR_COLUMN).text())
                        message.append(addr)
                        mass_type = table.item(i, MASS_TYPE_COLUMN).text()
                        message.append(
                            0xc2) if mass_type == "Нетто" else message.append(0xc3)
                        crc = 0
                        for j in message:
                            crc = crc8(data=j, poly=0x69, crc=crc)
                        packet = bytearray()
                        packet.append(0xFF)
                        packet.append(message[0])
                        packet.append(message[1])
                        packet.append(crc)
                        packet.append(0xFF)
                        packet.append(0xFF)
                        serial_connection.write(packet)
                        read_buffer = serial_connection.read_until(
                            expected=b"\xff\xff")

                        # Повторный запрос данных в случае ошибки
                        if read_buffer == b"" or len(read_buffer) < 9 or read_buffer[2] == b"EE":
                            logger.warning(
                                "Повторное чтение данных устройства с адресом {addr}".format(addr=addr))
                            serial_connection.write(packet)
                            read_buffer = serial_connection.read_until(
                                expected=b"\xff\xff")

                            if read_buffer == b"":
                                logger.warning(
                                    "Устройство с адресом {addr} недоступно".format(addr=addr))
                                self.change_cell(
                                    table, i, DATA_COLUMN, "-32768.0")
                                self.change_cell(
                                    table, i, STATUS_COLUMN, "Прибор недоступен", QtGui.QColor(255, 0, 0))
                            elif len(read_buffer) < 9 or read_buffer[2] == b"EE":
                                logger.warning(
                                    "Устройство с адресом {addr} в ошибке".format(addr=addr))
                                self.change_cell(
                                    table, i, DATA_COLUMN, "-32768.0")
                                self.change_cell(
                                    table, i, STATUS_COLUMN, "Ошибка прибора", QtGui.QColor(255, 0, 0))
                            else:
                                self.change_cell(table, i, DATA_COLUMN, str(
                                    get_weight(read_buffer)))
                                self.change_cell(table, i, STATUS_COLUMN, "Ok")
                        else:
                            self.change_cell(table, i, DATA_COLUMN, str(
                                get_weight(read_buffer)))
                            self.change_cell(table, i, STATUS_COLUMN, "Ok")
                        table.reset()
                    self.new_data_received = True

                except serial.serialutil.SerialException:
                    logger.exception("Ошибка COM-порта")
                    self.error_dialog("Ошибка COM-порта",
                                      "Последовательный порт " +
                                      self.communication_settings[0] +
                                      " недоступен или параметры неккоректны")
                    time.sleep(0.5)
                    self.stop_connection()
            else:
                if com_port_open:
                    serial_connection.close()
                com_port_open = False
                time.sleep(1)

    def sock_stream(self, table: QtWidgets.QTableWidget):
        """Сервер TCP
        Пассивный сервер. При завершении опроса устройств
        отправляет данные подключенному клиенту из таблицы.
        Флаг self.new_data_received использован для отправки свежих данных
        в случае задержки опроса устройств.
        В случае ошибки перезапускает соединение
        """
        while True:
            if self.connection_enabled:
                if self.new_data_received:
                    data = []
                    row_count = table.rowCount()
                    for i in range(row_count):
                        item = table.item(i, 3).text()
                        data.append((float(item)))
                    sending_data = struct.pack(("!" + "f" * row_count), *data)
                    try:
                        self.server.send(sending_data)
                    except (AttributeError, ConnectionAbortedError, ConnectionError, OSError):
                        logger.exception("Ошибка отправки данных")
                        try:
                            self.statusBar().showMessage("Ожидание клиента")
                            partner = self.server.connect()
                            self.statusBar().showMessage("Подключен клиент " + str(partner))
                        except (AttributeError, ConnectionAbortedError, ConnectionError, OSError):
                            logger.exception("Повторное создание подключения")
                    self.new_data_received = False
            else:
                time.sleep(1)

    def device_num_control(self, table: QtWidgets.QTableWidget):
        if table.rowCount() <= 0:
            self.btn_start_server.setEnabled(False)
        else:
            self.btn_start_server.setEnabled(True)

    def add_row(self, table: QtWidgets.QTableWidget, data: list):
        table.insertRow(table.rowCount())
        row_count = table.rowCount()
        column_count = table.columnCount()
        for j in range(column_count):
            item = QtWidgets.QTableWidgetItem()
            item.setText(data[j])
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            table.setItem(row_count - 1, j, item)
        self.device_num_control(table)

    def remove_row(self, table: QtWidgets.QTableWidget):
        if table.rowCount() > 0:
            selected_row = table.currentRow()
            table.removeRow(selected_row)
        self.device_num_control(table)

    @staticmethod
    def change_cell(table: QtWidgets.QTableWidget, row: int = 0, column: int = 0, text: str = "",
                    color: QtGui.QColor = QtGui.QColor(255, 255, 255)):
        item = QtWidgets.QTableWidgetItem()
        item.setText(text)
        item.setFlags(QtCore.Qt.ItemIsEnabled)
        item.setBackground(color)
        table.setItem(row, column, item)

    @staticmethod
    def error_dialog(title: str, message: str):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setText(message)
        msg.setWindowTitle(title)
        msg.exec()

    @staticmethod
    def get_device_data(table: QtWidgets.QTableWidget) -> list:
        device_data = []
        row_count = table.rowCount()
        column_count = table.columnCount()
        for i in range(row_count):
            for j in range(column_count):
                item = table.item(i, j).text()
                device_data.append(item)
        return device_data

    def save_config(self, data: list, path: str):
        try:
            with open(path, "w") as file:
                json.dump(data, file)
        except Exception:
            logger.exception("Ошибка сохранения файла")
            self.error_dialog("Ошибка сохранения файла",
                              "Невозможно сохранить файл в\n {path}".format(path=self.config_file_path))

    def save_action(self, table: QtWidgets.QTableWidget):
        config = []
        config.extend(self.communication_settings)
        config.extend(self.get_device_data(table))
        self.save_config(config, self.config_file_path)
        self.statusBar().showMessage("Сохранено " + str(self.config_file_path))

    def open_config_file(self, path: str) -> list:
        """Чтение конфигурации из файла
        В случае успешного открытия возвращает list
        в противном случае None
        """
        try:
            with open(path, "r") as file:
                config = json.load(file)
            return config
        except Exception:
            logger.exception("Ошибка открытия файла")
            self.error_dialog("Ошибка открытия файла",
                              "Неподдерживаемый тип файла, или файл поврежден")
            return None

    def update_table(self, config: list, table: QtWidgets.QTableWidget):
        row_count = table.rowCount()
        column_count = table.columnCount()
        for i in range(row_count, -1, -1):
            table.removeRow(i)
        row_count = 0
        table.insertRow(row_count)
        j = 0
        while config:
            if j > column_count - 1:
                j = 0
                row_count += 1
                table.insertRow(row_count)
            item = QtWidgets.QTableWidgetItem()
            item.setText(str(config.pop(0)))
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            table.setItem(row_count, j, item)
            j += 1

    def update_setting(self, config: list):
        for i in range(len(self.communication_settings)):
            self.communication_settings[i] = config.pop(0)

    def update_server_settings(self):
        """Обновление параметров TCP-сервера
        В случае ошибки инициализирует сервер
        на localhost порт 2000
        """
        try:
            self.server.set_address(
                self.communication_settings[6], int(self.communication_settings[7]))
        except ValueError:
            logger.exception("Ошибка настроек сервера {addr}, {port}".format(addr=self.communication_settings[6],
                                                                             port=self.communication_settings[7]))
            self.error_dialog(
                "Ошибка TCP-сервера",
                "Введены неверные параметры сервера")
            self.communication_settings[6] = "127.0.0.1"
            self.communication_settings[7] = "2000"

    def open_dialog(self, table: QtWidgets.QTableWidget):
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Открыть файл", "", "All Files (*);;json (*.json)", options=options)
        if file_path:
            config = self.open_config_file(file_path)
            if config is not None:
                try:
                    self.update_setting(config)
                    self.update_table(config, table)
                    self.statusBar().showMessage("Открыт файл " + str(self.config_file_path))
                    self.update_server_settings()
                except Exception:
                    logger.exception("Ошибка открытия файла конфигурации")
                    self.error_dialog("Ошибка открытия файла конфигурации",
                                      "Невозможно загрузить конфигурацию из\n {path}".format(path=self.config_file_path))
                    self.communication_settings = list[DEFAULT_SETTINGS]
                    self.update_server_settings()

    def save_as_file_dialog(self, table: QtWidgets.QTableWidget):
        config = []
        config.extend(self.communication_settings)
        config.extend(self.get_device_data(table))
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Сохранить как", "", "json(*.json)", options=options)
        if file_path:
            self.config_file_path = file_path
            self.save_config(config, self.config_file_path)
            self.statusBar().showMessage("Сохранено " + str(self.config_file_path))

    def settings_dialog(self):
        settings = SettingsDialog(self)
        if self.communication_settings:
            settings.set_settings(self.communication_settings)
        settings.exec_()
        if settings.get_settings_list() is not None:
            self.communication_settings = settings.get_settings_list()
            self.update_server_settings()

    def add_dialog(self, table: QtWidgets.QTableWidget):
        add_device = DeviceDialog(self, add_mode=True)
        add_device.exec_()
        device_data = add_device.get_settings_list()
        if device_data is not None:
            self.add_row(table, device_data)

    def change_dialog(self, table: QtWidgets.QTableWidget):
        settings = []
        selected_row = table.currentRow()
        if selected_row < 0:
            selected_row = 0
        column_count = table.columnCount()
        for i in range(column_count):
            item = table.item(selected_row, i).text()
            settings.append(item)
        add_device = DeviceDialog(self, add_mode=False)
        add_device.set_settings(settings)
        add_device.exec_()
        settings = add_device.get_settings_list()
        if settings is not None:
            for i in range(column_count):
                item = QtWidgets.QTableWidgetItem()
                item.setText(settings[i])
                item.setFlags(QtCore.Qt.ItemIsEnabled)
                table.setItem(selected_row, i, item)

    def about_dialog(self):
        QtWidgets.QMessageBox.about(self, "О программе", "Шлюз Тензо-М(RS485)-TCP/IP\n"
                                                         "============\n"
                                                         "Сбор данных с весовых контроллеровпо протоколу Тензо-М.\n"
                                                         "Создание TCP-сервера для дальнейшей передачи собранных данных\n"
                                                         "Версия: 1.0.1.0\n"
                                                         "Автор: Кузьменко Дмитрий\n"
                                                         "Дата: 06/2022")

    def closeEvent(self, event):
        """
        Переопределенный метод события закрытия главного окна.
        При закрытии создает диалоговое окно для подтверждения
        """
        quit_dialog = QtWidgets.QMessageBox()
        quit_dialog.setWindowTitle("Выход")
        quit_dialog.setIcon(QtWidgets.QMessageBox.Question)
        quit_dialog.setText("Вы уверены, что хотите выйти?")

        btn_yes = quit_dialog.addButton("Да", QtWidgets.QMessageBox.YesRole)
        btn_no = quit_dialog.addButton("Нет", QtWidgets.QMessageBox.NoRole)
        quit_dialog.setDefaultButton(btn_yes)
        quit_dialog.exec_()

        if quit_dialog.clickedButton() == btn_yes:
            self.stop_connection()
            logger.info("Приложение завершено")
            event.accept()
        else:
            event.ignore()


class DeviceDialog(ui.DeviceDialog):
    """Диалог изменения/добавления устройства
    Атрибут add_mode, определяет название окна.
    Виджеты сгенерированы QtDesigner и
    импрортируются из файла ui.
    """

    def __init__(self, parent, add_mode: bool):
        super().__init__(parent)
        self.add_mode = add_mode
        self.setupUi(self)
        self.connect_actions()
        self.settings_accepted = False

    def connect_actions(self):
        self.btn_ok.clicked.connect(self.accept_settings)

    def get_settings_list(self) -> list:
        """Передать настройки устройства
        Метод собирает данные из виджетов и
        возвращает list при подтверждении настроек
        в противном случае возвращает None
        :return:list или None
        """
        settings = [str(self.lne_device_name.text()), str(self.spx_device_addr.value()),
                    str(self.cmx_mass_type.currentText()), "0.0", "Нет"]
        return settings if self.settings_accepted else None

    def set_settings(self, settings_list: list):
        """Установить настройки устройства
        Метод устанавливает данные в виджеты
        из переданного списка в режиме изменения настроек устройства
        """
        self.lne_device_name.setText(str(settings_list[0]))
        self.spx_device_addr.setValue(int(settings_list[1]))
        self.cmx_mass_type.setCurrentText(settings_list[2])

    def accept_settings(self):
        self.settings_accepted = True
        self.close()


class SettingsDialog(ui.SettingsDialog):
    """Диалог настройки параметров соединения
    Виджеты сгенерированы QtDesigner и
    импрортируются из файла ui.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.setupUi(self)
        self.widgets_modify()
        self.connect_actions()
        self.settings_accepted = False

    def available_ports(self):
        try:
            ports = list_ports.comports()
            for port in ports:
                self.cmx_com_port.addItem(str(port[0]))
        except Exception:
            self.cmx_com_port.addItem("")
            logger.exception("Ошибка создания списка доступных com-портов")

    def connect_actions(self):
        self.btn_ok.clicked.connect(self.accept_settings)

    def widgets_modify(self):
        self.available_ports()

    def get_settings_list(self) -> list:
        """Передать настройки соединения
        Метод собирает данные из виджетов и
        возвращает list при подтверждении настроек
        в противном случае возвращает None
        :return:list или None
        """
        settings = [
            str(self.cmx_com_port.currentText()),
            str(self.cmx_data_bits.currentText()),
            str(self.cmx_baud_rate.currentText()),
            str(self.cmx_stop_bits.currentText()),
            str(self.cmx_parity.currentText()),
            str(self.lne_timeout.text()).replace(",", "."),
            str(self.lne_ip_addr.text()),
            str(self.lne_ip_port.text()),
            str(self.chb_autostart.isChecked())]
        return settings if self.settings_accepted else None

    def set_settings(self, settings_list: list):
        """Установить настройки соединения
        Метод устанавливает текущие настройки в виджеты
        из переданного списка
        """
        self.cmx_com_port.setCurrentText(settings_list[0])
        self.cmx_data_bits.setCurrentText(settings_list[1])
        self.cmx_baud_rate.setCurrentText(settings_list[2])
        self.cmx_stop_bits.setCurrentText(settings_list[3])
        self.cmx_parity.setCurrentText(settings_list[4])
        self.lne_timeout.setText(settings_list[5].replace(".", ","))
        self.lne_ip_addr.setText(settings_list[6])
        self.lne_ip_port.setText(settings_list[7])
        self.chb_autostart.setChecked(True if settings_list[8] == "True" else False)

    def accept_settings(self):
        self.settings_accepted = True
        self.close()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    application = UiMainWindow()
    logger.info("Приложение запущено")
    application.show()
    sys.exit(app.exec())
