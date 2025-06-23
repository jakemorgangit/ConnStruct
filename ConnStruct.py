import sys
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QPushButton, QTabWidget, QLabel,
    QSplitter, QMenu, QAction, QInputDialog, QLineEdit,
    QFormLayout, QComboBox, QMessageBox, QGroupBox, QScrollArea,
    QAbstractItemView, QDialog, QDialogButtonBox, QFileDialog, QTreeWidgetItemIterator,
    QColorDialog # Added for color picker
)
from PyQt5.QtCore import Qt, QUrl, QMimeData, QTimer, QPoint
from PyQt5.QtGui import QIcon, QPixmap, QFont, QPainter, QPolygon, QBrush, QPen, QColor # Added QColor
from PyQt5.QtWebEngineWidgets import QWebEngineView

import socket
import time
import subprocess
import logging
import multiprocessing

CONNECTIONS_FILE = "connections.json"
SETTINGS_FILE = "settings.json"
APP_NAME = "ConnStruct"
APP_VERSION = "1.4.1" # Incremented
APP_AUTHOR = "Jake Morgan"
APP_WEBSITE = "https://dba.wales"
WEBSSH_HOST = "localhost"
SSH_ICON, RDP_ICON, FOLDER_ICON, APP_ICON, STAR_ICON = None, None, None, None, None
DEFAULT_PORTS = {"ssh": "22", "rdp": "3389"}
RDP_RESOLUTIONS = ["Default", "Fullscreen", "1920x1080", "1600x900", "1366x768", "1280x1024", "1280x720", "1024x768", "800x600"]


def get_application_path():
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'): application_path = sys._MEIPASS
    elif getattr(sys, 'frozen', False): application_path = os.path.dirname(sys.executable)
    elif __file__: application_path = os.path.dirname(os.path.abspath(__file__))
    else: application_path = os.getcwd()
    return application_path

log_file_path = os.path.join(get_application_path(), f"{APP_NAME.lower()}.log")
logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
                    filemode='w')

def get_icon(name, color_hex=None):
    if color_hex and (name == "ssh" or name == "rdp"):
        pixmap = QPixmap(16, 16)
        try:
            pixmap.fill(QColor(color_hex))
        except Exception as e:
            logging.warning(f"Invalid icon color hex '{color_hex}', using default for {name}: {e}")
            default_color = Qt.blue if name == "ssh" else Qt.darkGreen
            pixmap.fill(default_color)
        return QIcon(pixmap)
    if name=="ssh":pix=QPixmap(16,16);pix.fill(Qt.blue);return QIcon(pix)
    if name=="rdp":pix=QPixmap(16,16);pix.fill(Qt.darkGreen);return QIcon(pix)
    if name=="folder":pix=QPixmap(16,16);pix.fill(Qt.yellow);return QIcon(pix)
    if name=="app_icon":
        # IMPORTANT: For PyInstaller, if 'folder_shell_icon.ico' is a loose file,
        # ensure it's added to 'datas' in your .spec file:
        # datas=[('webssh', 'webssh'), ('folder_shell_icon.ico', '.')]
        # And ensure get_application_path() is used to locate it.
        icon_path = os.path.join(get_application_path(), "folder_shell_icon.ico")
        if os.path.exists(icon_path):
            loaded_icon = QIcon(icon_path)
            if not loaded_icon.isNull():
                logging.info(f"Loaded app icon from: {icon_path}")
                return loaded_icon
            else:
                logging.warning(f"App icon at {icon_path} is null/invalid.")
        else:
            logging.warning(f"App icon not found at {icon_path}.")
        # Fallback placeholder if ICO loading fails or file not found
        pix=QPixmap(32,32);pix.fill(Qt.darkCyan);return QIcon(pix)
    if name=="star":
        pix=QPixmap(16,16);pix.fill(Qt.transparent);p=QPainter(pix);p.setRenderHint(QPainter.Antialiasing)
        pen=QPen(Qt.yellow);pen.setWidth(1);p.setPen(pen);p.setBrush(QBrush(Qt.yellow))
        pts=[QPoint(8,1),QPoint(10,6),QPoint(15,6),QPoint(11,10),QPoint(13,15),QPoint(8,12),QPoint(3,15),QPoint(5,10),QPoint(1,6),QPoint(6,6)]
        p.drawPolygon(QPolygon(pts));p.end();return QIcon(pix)
    return QIcon()

def initialize_icons():
    global SSH_ICON,RDP_ICON,FOLDER_ICON,APP_ICON,STAR_ICON
    SSH_ICON,RDP_ICON,FOLDER_ICON,STAR_ICON=get_icon("ssh"),get_icon("rdp"),get_icon("folder"),get_icon("star")
    APP_ICON = get_icon("app_icon") # Load app icon separately

def find_free_port():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('localhost',0));p=s.getsockname()[1];s.close();logging.debug(f"Found free port: {p}");return p

class CryptoHelper:
    def __init__(self):self.key=None
    def generate_salt(self,sz=16):return os.urandom(sz)
    def hash_master_password(self,p,s):return PBKDF2HMAC(hashes.SHA256(),32,s,100000,default_backend()).derive(p.encode())
    def verify_master_password(self,h,s,p):
        try:PBKDF2HMAC(hashes.SHA256(),32,s,100000,default_backend()).verify(p.encode(),h);return True
        except Exception as e:logging.error(f"Pwd verify fail: {e}",exc_info=True);return False
    def derive_fernet_key(self,p,s):self.key=base64.urlsafe_b64encode(PBKDF2HMAC(hashes.SHA256(),32,s,100000,default_backend()).derive(p.encode()))
    def encrypt(self,d):
        if not self.key:logging.error("Enc key not set.");raise ValueError("Key not set")
        return Fernet(self.key).encrypt(d.encode()).decode()if d else""
    def decrypt(self,t):
        if not self.key:logging.error("Dec key not set.");raise ValueError("Key not set")
        try:return Fernet(self.key).decrypt(t.encode()).decode()if t else""
        except InvalidToken:logging.warning("InvalidToken dec.");QMessageBox.warning(None,"Decryption Error","Pwd/passphrase corrupt.");return""
        except Exception as e:logging.error(f"General dec err: {e}",exc_info=True);QMessageBox.warning(None,"Decryption Error","Pwd/passphrase corrupt.");return""

def load_initial_settings():
    try:
        with open(SETTINGS_FILE,"r")as f:sd=json.load(f)
        if 'master_salt_b64'in sd:sd['master_salt']=base64.b64decode(sd.pop('master_salt_b64'))
        if 'master_hash_b64'in sd:sd['master_hash']=base64.b64decode(sd.pop('master_hash_b64'))
        logging.info("Settings loaded.");return sd
    except FileNotFoundError:logging.info(f"{SETTINGS_FILE} not found.");return{}
    except json.JSONDecodeError:logging.error(f"Corrupt {SETTINGS_FILE}.");QMessageBox.critical(None,"Settings Error",f"Corrupt {SETTINGS_FILE}.");return{}
    except Exception as e:logging.error(f"Load settings: {e}.",exc_info=True);QMessageBox.critical(None,"Settings Error",f"Load settings: {e}.");return{}

def save_initial_settings(d):
    try:
        sd=d.copy()
        if'master_salt'in sd and isinstance(sd['master_salt'],bytes):sd['master_salt_b64']=base64.b64encode(sd['master_salt']).decode();del sd['master_salt']
        if'master_hash'in sd and isinstance(sd['master_hash'],bytes):sd['master_hash_b64']=base64.b64encode(sd['master_hash']).decode();del sd['master_hash']
        with open(SETTINGS_FILE,"w")as f:json.dump(sd,f,indent=2)
        logging.info("Settings saved.")
    except Exception as e:logging.error(f"Save settings: {e}",exc_info=True);QMessageBox.critical(None,"Settings Save Error",f"Save settings: {e}")

class MasterPasswordDialog(QDialog):
    def __init__(self, parent=None, is_setting_up=False):
        super().__init__(parent)
        self.is_setting_up = is_setting_up; self.setWindowTitle("Master Password"); self.setModal(True)
        layout = QVBoxLayout(self)
        self.info_label = QLabel("Set up master password." if self.is_setting_up else "Enter master password.")
        layout.addWidget(self.info_label); self.password_edit = QLineEdit(); self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Master Password:")); layout.addWidget(self.password_edit)
        if self.is_setting_up:
            self.confirm_password_edit = QLineEdit(); self.confirm_password_edit.setEchoMode(QLineEdit.Password)
            layout.addWidget(QLabel("Confirm Master Password:")); layout.addWidget(self.confirm_password_edit)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept); self.button_box.rejected.connect(self.reject); layout.addWidget(self.button_box)
    def get_password(self):
        pw1 = self.password_edit.text()
        if self.is_setting_up:
            pw2 = self.confirm_password_edit.text()
            if not pw1: QMessageBox.warning(self, "Error", "Password empty."); return None
            if pw1 != pw2: QMessageBox.warning(self, "Error", "Passwords mismatch."); return None
        elif not pw1: QMessageBox.warning(self, "Error", "Password empty."); return None
        return pw1

class ConnectionTreeWidget(QTreeWidget):
    def __init__(self, manager, parent=None):
        super().__init__(parent)
        self.manager = manager; self.setDragEnabled(True); self.setAcceptDrops(True)
        self.setDropIndicatorShown(True); self.setDragDropMode(QAbstractItemView.InternalMove)
    def mimeTypes(self): return ['application/x-qtreewidgetitemlist']
    def mimeData(self, items):
        mime_data = QMimeData()
        if items:
            item = items[0]
            if item.text(0) == "Favorites" or (item.parent() and item.parent().text(0) == "Favorites"): return mime_data
            idx = item.data(0, Qt.UserRole)
            if idx is not None and 0 <= idx < len(self.manager.connections) and self.manager.connections[idx].get("type") != "folder":
                mime_data.setText(str(idx))
        return mime_data
    def dropMimeData(self, parent_item, action, data, row, col):
        if not data.hasText(): return False
        if parent_item and (parent_item.text(0) == "Favorites" or (parent_item.parent() and parent_item.parent().text(0) == "Favorites")): return False
        try: src_idx = int(data.text())
        except ValueError: return False
        if not (0 <= src_idx < len(self.manager.connections)): return False
        conn_to_move = self.manager.connections[src_idx]; target_fldr = "Default"
        if parent_item:
            p_idx = parent_item.data(0, Qt.UserRole)
            if p_idx is not None and 0 <= p_idx < len(self.manager.connections):
                p_data = self.manager.connections[p_idx]
                target_fldr = p_data["name"] if p_data.get("type") == "folder" else p_data.get("folder", "Default")
        conn_to_move["folder"] = target_fldr
        self.manager.save_connections_data(); self.manager.refresh_connection_list()
        item_sel = self.manager.find_item_by_index(src_idx)
        if item_sel: self.manager.explorer.setCurrentItem(item_sel)
        return True

class EditPane(QWidget):
    def __init__(self):
        super().__init__();layout=QVBoxLayout(self);scroll=QScrollArea();scroll.setWidgetResizable(True)
        self.inner=QWidget();self.inner_layout=QVBoxLayout(self.inner)
        self.display_box=QGroupBox("Display");self.connection_box=QGroupBox("Connection")
        self.ssh_options_box=QGroupBox("SSH Key Options"); self.rdp_options_box=QGroupBox("RDP Display Options"); self.misc_box=QGroupBox("Miscellaneous")
        self.display_form=QFormLayout();self.connection_form=QFormLayout();self.ssh_options_form=QFormLayout();self.rdp_options_form=QFormLayout();self.misc_form=QFormLayout()
        self.name_edit=QLineEdit();self.folder_combo=QComboBox()
        self.icon_color_label=QLabel("Icon Colour:");self.icon_color_swatch=QLabel();self.icon_color_swatch.setFixedSize(20,20);self.icon_color_swatch.setAutoFillBackground(True)
        self.icon_color_button=QPushButton("Choose...")
        self.host_edit=QLineEdit();self.protocol_combo=QComboBox();self.protocol_combo.addItems(["ssh","rdp"]);self.port_edit=QLineEdit()
        self.username_edit=QLineEdit();self.password_edit_field=QLineEdit();self.password_edit_field.setEchoMode(QLineEdit.Password);self.notes_edit=QLineEdit()
        self.ssh_key_path_edit=QLineEdit();self.ssh_key_path_edit.setPlaceholderText("Optional path to SSH private key")
        self.ssh_key_browse_btn=QPushButton("Browse...");self.ssh_key_clear_btn=QPushButton("Clear")
        self.ssh_key_passphrase_edit = QLineEdit();self.ssh_key_passphrase_edit.setPlaceholderText("Optional passphrase");self.ssh_key_passphrase_edit.setEchoMode(QLineEdit.PasswordEchoOnEdit)
        self.rdp_resolution_combo = QComboBox(); self.rdp_resolution_combo.addItems(RDP_RESOLUTIONS)

        self.display_form.addRow("Name:",self.name_edit);self.display_form.addRow("Folder:",self.folder_combo)
        icon_color_layout=QHBoxLayout();icon_color_layout.addWidget(self.icon_color_swatch);icon_color_layout.addWidget(self.icon_color_button);icon_color_layout.addStretch()
        self.display_form.addRow(self.icon_color_label,icon_color_layout)
        self.connection_form.addRow("Hostname/IP:",self.host_edit);self.connection_form.addRow("Protocol:",self.protocol_combo);self.connection_form.addRow("Port:",self.port_edit)
        self.connection_form.addRow("Username:",self.username_edit);self.connection_form.addRow("Password:",self.password_edit_field)
        ssh_key_path_layout=QHBoxLayout();ssh_key_path_layout.addWidget(self.ssh_key_path_edit);ssh_key_path_layout.addWidget(self.ssh_key_browse_btn);ssh_key_path_layout.addWidget(self.ssh_key_clear_btn)
        self.ssh_options_form.addRow("Key File:",ssh_key_path_layout);self.ssh_options_form.addRow("Key Passphrase:", self.ssh_key_passphrase_edit)
        self.rdp_options_form.addRow("Resolution:", self.rdp_resolution_combo)
        self.misc_form.addRow("Notes:",self.notes_edit)
        for b,f in [(self.display_box,self.display_form),(self.connection_box,self.connection_form),(self.ssh_options_box,self.ssh_options_form),(self.rdp_options_box,self.rdp_options_form),(self.misc_box,self.misc_form)]:b.setLayout(f);self.inner_layout.addWidget(b)
        self.inner_layout.addStretch(1);scroll.setWidget(self.inner);layout.addWidget(scroll)
        for w in [self.name_edit,self.host_edit,self.port_edit,self.username_edit,self.password_edit_field,self.folder_combo,self.protocol_combo,self.notes_edit,self.ssh_key_path_edit, self.ssh_key_passphrase_edit, self.rdp_resolution_combo]:
            if isinstance(w,QLineEdit):w.textChanged.connect(self.on_value_changed)
            elif isinstance(w,QComboBox):w.currentTextChanged.connect(self.on_value_changed) # Covers rdp_resolution_combo too
        self.protocol_combo.currentTextChanged.connect(self.on_protocol_changed);self.ssh_key_browse_btn.clicked.connect(self.browse_for_ssh_key);self.ssh_key_clear_btn.clicked.connect(self.clear_ssh_key)
        self.icon_color_button.clicked.connect(self.choose_icon_color)
        self.current_item_index=None;self.manager=None;self._block_signals=False;self._current_icon_color=None;self.on_protocol_changed(self.protocol_combo.currentText())

    def bind(self,manager):self.manager=manager
    def choose_icon_color(self):
        initial_c = QColor(self._current_icon_color) if self._current_icon_color and QColor.isValidColor(self._current_icon_color) else Qt.black
        color = QColorDialog.getColor(initial_c, self, "Choose Icon Colour")
        if color.isValid(): self._current_icon_color = color.name(); self.update_icon_color_swatch(self._current_icon_color); self.on_value_changed()
    def update_icon_color_swatch(self,hex_color):
        self._current_icon_color = hex_color
        self.icon_color_swatch.setStyleSheet(f"background-color: {hex_color if hex_color else 'transparent'}; border: 1px solid grey;")

    def on_protocol_changed(self,protocol_text):
        is_ssh=protocol_text=="ssh"; self.ssh_options_box.setVisible(is_ssh)
        is_rdp=protocol_text=="rdp"; self.rdp_options_box.setVisible(is_rdp)
        is_conn = is_ssh or is_rdp; self.icon_color_label.setVisible(is_conn); self.icon_color_swatch.setVisible(is_conn); self.icon_color_button.setVisible(is_conn)
        if not is_conn: self.update_icon_color_swatch(None)
        self._block_signals=True
        curr_p=self.port_edit.text();def_p=DEFAULT_PORTS.get(protocol_text,"");is_prev_def=any(pr!=protocol_text and curr_p==dp for pr,dp in DEFAULT_PORTS.items())
        if not curr_p or is_prev_def:self.port_edit.setText(def_p)
        self._block_signals=False
        if not is_ssh:
            if self.ssh_key_path_edit.text():self._block_signals=True;self.ssh_key_path_edit.clear();self._block_signals=False
            if self.ssh_key_passphrase_edit.text():self._block_signals=True;self.ssh_key_passphrase_edit.clear();self._block_signals=False
        if not is_rdp and self.rdp_resolution_combo.currentIndex()!=0:self._block_signals=True;self.rdp_resolution_combo.setCurrentText("Default");self._block_signals=False

    def browse_for_ssh_key(self):k,_=QFileDialog.getOpenFileName(self,"SSH Key",os.path.expanduser("~/.ssh"),"All(*);;Keys(id*)");k and self.ssh_key_path_edit.setText(k)
    def clear_ssh_key(self):self.ssh_key_path_edit.clear(); self.ssh_key_passphrase_edit.clear()
    def load_connection_data(self,cd,idx):
        self._block_signals=True;self.current_item_index=idx
        self.name_edit.setText(cd.get("name",""));self.host_edit.setText(cd.get("host",""));self.username_edit.setText(cd.get("username",""))
        self.password_edit_field.setText(cd.get("password_decrypted",""));self.notes_edit.setText(cd.get("notes",""))
        self.ssh_key_path_edit.setText(cd.get("ssh_key_path",""));self.ssh_key_passphrase_edit.setText(cd.get("ssh_key_passphrase_decrypted",""))
        self.rdp_resolution_combo.setCurrentText(cd.get("rdp_resolution","Default"));self.update_icon_color_swatch(cd.get("icon_color"))
        pt=cd.get("type","ssh");self.port_edit.setText(str(cd.get("port",DEFAULT_PORTS.get(pt,""))))
        fldrs=self.manager.get_folder_names();self.folder_combo.clear();self.folder_combo.addItems(fldrs);self.folder_combo.setCurrentText(cd.get("folder","Default"))
        self.protocol_combo.setCurrentText(pt);self.on_protocol_changed(pt);self._block_signals=False;self.update_visibility(True)
    def clear_and_hide(self):
        self._block_signals=True;[w.clear()for w in[self.name_edit,self.host_edit,self.port_edit,self.username_edit,self.password_edit_field,self.notes_edit,self.ssh_key_path_edit,self.ssh_key_passphrase_edit]]
        self.folder_combo.clear();self.protocol_combo.setCurrentIndex(0);self.rdp_resolution_combo.setCurrentText("Default");self.update_icon_color_swatch(None)
        self.current_item_index=None;self._block_signals=False;self.on_protocol_changed(self.protocol_combo.currentText());self.update_visibility(False)
    def update_visibility(self,show):
        for b in[self.display_box,self.connection_box,self.misc_box]:b.setVisible(show)
        if show:self.on_protocol_changed(self.protocol_combo.currentText())
        else:self.ssh_options_box.setVisible(False);self.rdp_options_box.setVisible(False);self.icon_color_label.setVisible(False);self.icon_color_swatch.setVisible(False);self.icon_color_button.setVisible(False)
    def on_value_changed(self,_=None):
        if self._block_signals or self.manager is None or self.current_item_index is None or not(0<=self.current_item_index<len(self.manager.connections)):return
        conn=self.manager.connections[self.current_item_index]
        conn.update({"name":self.name_edit.text(),"host":self.host_edit.text(),"port":self.port_edit.text(),"username":self.username_edit.text(),
                     "password_to_encrypt":self.password_edit_field.text(),"folder":self.folder_combo.currentText(),"type":self.protocol_combo.currentText(),
                     "notes":self.notes_edit.text(), "icon_color": self._current_icon_color})
        ct=self.protocol_combo.currentText()
        if ct=="ssh":conn["ssh_key_path"]=self.ssh_key_path_edit.text();conn["ssh_key_passphrase_to_encrypt"]=self.ssh_key_passphrase_edit.text();conn.pop("rdp_resolution",None)
        elif ct=="rdp":conn["rdp_resolution"]=self.rdp_resolution_combo.currentText();conn.pop("ssh_key_path",None);conn.pop("ssh_key_passphrase_to_encrypt",None);conn.pop("ssh_key_passphrase_encrypted",None)
        else:[conn.pop(k,None)for k in["ssh_key_path","ssh_key_passphrase_to_encrypt","ssh_key_passphrase_encrypted","rdp_resolution","icon_color"]]
        self.manager.save_connections_data();self.manager.refresh_connection_list()
        ci=self.manager.explorer.currentItem();isf=ci.data(0,Qt.UserRole+1)==True if ci else False;its=self.manager.find_item_by_index(self.current_item_index,is_fav_link=isf);its and self.manager.explorer.setCurrentItem(its)

# --- ConnectionManager and other classes below... ---
class ConnectionManager(QMainWindow):
    def __init__(self,crypto_helper,settings_data):
        super().__init__();self.crypto_helper=crypto_helper;self.settings=settings_data
        self.setWindowTitle(APP_NAME);self.setWindowIcon(APP_ICON);self.setGeometry(100,100,1200,800)
        self.all_connections_data=self.load_all_data()
        self.connections=self.all_connections_data.get("connections",[])
        self.favorites_indices=self.all_connections_data.get("favorites_indices",[])
        self.active_webssh_processes = {}
        self.webssh_ports = {}
        container=QWidget();main_layout=QHBoxLayout(container);self.setCentralWidget(container)
        splitter=QSplitter(Qt.Horizontal);main_layout.addWidget(splitter)
        left_pane=QWidget();left_layout=QVBoxLayout(left_pane);left_layout.setContentsMargins(0,0,0,0)
        self.search_box=QLineEdit();self.search_box.setPlaceholderText("Search (name, host, notes, port)...")
        self.search_box.textChanged.connect(self.filter_connections)
        search_clear_btn=QPushButton("✕");search_clear_btn.setFixedWidth(30);search_clear_btn.clicked.connect(self.search_box.clear)
        search_hl=QHBoxLayout();search_hl.addWidget(self.search_box);search_hl.addWidget(search_clear_btn);left_layout.addLayout(search_hl)
        explorer_group=QGroupBox("Connections");explorer_layout=QVBoxLayout(explorer_group)
        self.explorer=ConnectionTreeWidget(self);self.explorer.setHeaderHidden(True)
        self.explorer.itemClicked.connect(self.handle_item_click);self.explorer.itemDoubleClicked.connect(self.launch_connection_from_item)
        self.explorer.setContextMenuPolicy(Qt.CustomContextMenu);self.explorer.customContextMenuRequested.connect(self.show_context_menu)
        explorer_layout.addWidget(self.explorer);self.add_btn=QPushButton(QIcon.fromTheme("list-add"),"Add");self.add_folder_btn=QPushButton(FOLDER_ICON,"Folder")
        self.add_btn.clicked.connect(self.add_connection);self.add_folder_btn.clicked.connect(self.create_folder_action)
        btn_hl=QHBoxLayout();btn_hl.addWidget(self.add_btn);btn_hl.addWidget(self.add_folder_btn);explorer_layout.addLayout(btn_hl);left_layout.addWidget(explorer_group)
        self.edit_pane=EditPane();self.edit_pane.bind(self)
        self.edit_pane.update_visibility(False)
        left_layout.addWidget(self.edit_pane);left_layout.setStretchFactor(explorer_group,2);left_layout.setStretchFactor(self.edit_pane,1)
        self.tabs=QTabWidget();self.tabs.setTabsClosable(True);self.tabs.tabCloseRequested.connect(self.confirm_close_tab)
        splitter.addWidget(left_pane);splitter.addWidget(self.tabs);splitter.setStretchFactor(0,1);splitter.setStretchFactor(1,2);splitter.setSizes([400,800])
        self.create_menus();self.apply_theme(self.settings.get('theme','light'));self.refresh_connection_list()

    def find_item_by_index(self,target_idx,is_fav_link=False):
        if target_idx is None:return None
        iterator = QTreeWidgetItemIterator(self.explorer)
        while iterator.value():
            item = iterator.value();item_data_idx = item.data(0, Qt.UserRole);item_is_fav_link = item.data(0, Qt.UserRole + 1) == True
            if is_fav_link:
                if item_is_fav_link and item_data_idx == target_idx and item.parent() and item.parent().text(0) == "Favorites": return item
            else:
                if not item_is_fav_link and item.text(0) != "Favorites" and item_data_idx == target_idx: return item
            iterator += 1
        return None

    def filter_connections(self,text):self.refresh_connection_list()

    def load_all_data(self):
        if not self.crypto_helper.key: return {"connections": [], "favorites_indices": []}
        try:
            with open(CONNECTIONS_FILE, "r") as f: raw_data_from_file = json.load(f)
            connections_list = []; favorites_list = []
            if isinstance(raw_data_from_file, list):
                connections_list = raw_data_from_file; favorites_list = []
                logging.info(f"Migrating old '{CONNECTIONS_FILE}' format to new structure.")
            elif isinstance(raw_data_from_file, dict):
                connections_list = raw_data_from_file.get("connections", [])
                favorites_list = raw_data_from_file.get("favorites_indices", [])
            else:
                QMessageBox.warning(self, "Load Warning", f"Unexpected data format in {CONNECTIONS_FILE}. Starting fresh.")
                logging.warning(f"Unexpected data format in {CONNECTIONS_FILE}.")
                return {"connections": [], "favorites_indices": []}
            decr_conns = []
            for conn in connections_list:
                if isinstance(conn, dict):
                    conn["password_decrypted"] = self.crypto_helper.decrypt(conn.get("password_encrypted", ""))
                    conn["ssh_key_passphrase_decrypted"] = self.crypto_helper.decrypt(conn.get("ssh_key_passphrase_encrypted", ""))
                    decr_conns.append(conn)
                else: logging.warning(f"Skipping invalid connection data item: {conn}")
            logging.info(f"Loaded {len(decr_conns)} connections and {len(favorites_list)} favorite indices.")
            return {"connections": decr_conns, "favorites_indices": favorites_list}
        except FileNotFoundError: logging.info(f"{CONNECTIONS_FILE} not found."); return {"connections": [], "favorites_indices": []}
        except json.JSONDecodeError: logging.error(f"Corrupt {CONNECTIONS_FILE}."); QMessageBox.critical(self,"Load Error",f"Corrupt {CONNECTIONS_FILE}. Check or delete."); return {"connections":[],"favorites_indices":[]}
        except Exception as e: logging.error(f"Loading data error: {e}", exc_info=True); QMessageBox.critical(self,"Load Error",f"Loading data: {e}"); return {"connections":[],"favorites_indices":[]}

    def save_connections_data(self):
        if not self.crypto_helper.key:QMessageBox.warning(self,"Save Error","Master key unavailable.");return
        conns_to_save=[]
        for c_orig in self.connections:
            c=c_orig.copy()
            pw_to_encrypt_val = c.pop("password_to_encrypt", c.get("password_decrypted", ""))
            c["password_encrypted"] = self.crypto_helper.encrypt(pw_to_encrypt_val) if pw_to_encrypt_val else ""
            ssh_key_pass_to_encrypt = c.pop("ssh_key_passphrase_to_encrypt", c.get("ssh_key_passphrase_decrypted", ""))
            if ssh_key_pass_to_encrypt: c["ssh_key_passphrase_encrypted"] = self.crypto_helper.encrypt(ssh_key_pass_to_encrypt)
            elif "ssh_key_passphrase_encrypted" in c: c["ssh_key_passphrase_encrypted"] = ""
            if "password_decrypted" in c: del c["password_decrypted"]
            if "ssh_key_passphrase_decrypted" in c: del c["ssh_key_passphrase_decrypted"]
            conns_to_save.append(c)
        full_data={"connections":conns_to_save,"favorites_indices":self.favorites_indices}
        try:
            with open(CONNECTIONS_FILE,"w") as f:
                json.dump(full_data,f,indent=2)
            logging.info("Connections data saved.")
        except Exception as e:
            logging.error(f"Saving connections data error: {e}", exc_info=True)
            QMessageBox.critical(self,"Save Error",f"Saving data: {e}")

    def get_folder_names(self):return sorted(list({c["name"]for c in self.connections if c.get("type")=="folder"}|{"Default"}))

    def refresh_connection_list(self,sel_orig_idx=None,sel_fav_link_orig_idx=None):
        current_selection=self.explorer.currentItem();current_sel_orig_idx=current_selection.data(0,Qt.UserRole)if current_selection else None;current_sel_is_fav=current_selection.data(0,Qt.UserRole+1)==True if current_selection else False
        self.explorer.clear();search_term=self.search_box.text().lower()
        fav_fldr_item=QTreeWidgetItem(["Favorites"]);fav_fldr_item.setIcon(0,STAR_ICON);fav_fldr_item.setFlags(fav_fldr_item.flags()&~Qt.ItemIsDragEnabled&~Qt.ItemIsDropEnabled&~Qt.ItemIsEditable)
        self.explorer.addTopLevelItem(fav_fldr_item);font_obj=fav_fldr_item.font(0);font_obj.setBold(True);fav_fldr_item.setFont(0,font_obj);item_to_reselect=None
        for original_idx in self.favorites_indices:
            if 0<=original_idx<len(self.connections):
                conn_data=self.connections[original_idx];
                if conn_data.get("type")=="folder":continue
                matches_search=not search_term or search_term in conn_data.get("name","").lower()or search_term in conn_data.get("host","").lower()or search_term in conn_data.get("notes","").lower()or search_term in str(conn_data.get("port",""))
                if not matches_search:continue
                favorite_text=conn_data.get("name","Fav")+(f" ({conn_data.get('host')})"if conn_data.get('host')else"");favorite_item=QTreeWidgetItem([favorite_text])
                conn_type = conn_data.get("type", "ssh"); icon_color = conn_data.get("icon_color")
                favorite_item.setIcon(0, get_icon(conn_type, icon_color) if conn_type in ["ssh", "rdp"] else (SSH_ICON if conn_type=="ssh" else RDP_ICON) )
                favorite_item.setData(0,Qt.UserRole,original_idx);favorite_item.setData(0,Qt.UserRole+1,True);fav_fldr_item.addChild(favorite_item)
                if(sel_fav_link_orig_idx==original_idx)or(current_sel_is_fav and current_sel_orig_idx==original_idx):item_to_reselect=favorite_item
        folder_items_map={};
        for i,conn_data in enumerate(self.connections):
            is_folder=conn_data.get("type")=="folder"
            matches_search=not search_term or search_term in conn_data.get("name","").lower()or(not is_folder and(search_term in conn_data.get("host","").lower()or search_term in str(conn_data.get("port",""))or search_term in conn_data.get("notes","").lower()))
            if is_folder:
                children_match=any(not search_term or search_term in child.get("name","").lower()or search_term in child.get("host","").lower()or search_term in str(child.get("port",""))or search_term in child.get("notes","").lower()for child in self.connections if child.get("folder")==conn_data["name"])
                if search_term and not matches_search and not children_match:continue
                folder_item=QTreeWidgetItem([conn_data["name"]]);folder_item.setIcon(0,FOLDER_ICON);folder_item.setData(0,Qt.UserRole,i);folder_item.setFlags(folder_item.flags()&~Qt.ItemIsEditable|Qt.ItemIsDropEnabled);self.explorer.addTopLevelItem(folder_item);folder_items_map[conn_data["name"]]=folder_item
                if(sel_orig_idx==i)or(not current_sel_is_fav and current_sel_orig_idx==i and not item_to_reselect):item_to_reselect=folder_item
            elif matches_search:
                port_value=conn_data.get('port',DEFAULT_PORTS.get(conn_data.get('type','')));port_display=f":{port_value}"if port_value and str(port_value)!=DEFAULT_PORTS.get(conn_data.get('type',''),'')else""
                item_text=conn_data.get("name","Un")+(f" ({conn_data.get('host')}{port_display})"if conn_data.get('host')else"");tree_item=QTreeWidgetItem([item_text])
                tree_item.setData(0,Qt.UserRole,i);tree_item.setFlags(tree_item.flags()|Qt.ItemIsDragEnabled)
                conn_type = conn_data.get("type", "ssh"); icon_color = conn_data.get("icon_color")
                tree_item.setIcon(0, get_icon(conn_type, icon_color) if conn_type in ["ssh", "rdp"] else (SSH_ICON if conn_type=="ssh" else RDP_ICON) )
                parent_folder_name=conn_data.get("folder","Default");parent_item_widget=folder_items_map.get(parent_folder_name)
                if parent_item_widget:parent_item_widget.addChild(tree_item)
                elif parent_folder_name=="Default":self.explorer.addTopLevelItem(tree_item)
                if(sel_orig_idx==i)or(not current_sel_is_fav and current_sel_orig_idx==i and not item_to_reselect):item_to_reselect=tree_item
        self.explorer.expandAll();should_hide_favs = bool(search_term and fav_fldr_item.childCount()==0); fav_fldr_item.setHidden(should_hide_favs)
        if item_to_reselect: self.explorer.setCurrentItem(item_to_reselect)

    def handle_item_click(self,item,col=0):
        original_idx=item.data(0,Qt.UserRole)
        if item.text(0)=="Favorites":self.edit_pane.clear_and_hide();return
        if original_idx is not None and 0<=original_idx<len(self.connections):
            conn_data=self.connections[original_idx]
            if conn_data.get("type")=="folder":self.edit_pane.clear_and_hide()
            else:self.edit_pane.load_connection_data(conn_data,original_idx)
        else:self.edit_pane.clear_and_hide()

    def show_context_menu(self,pos):
        item=self.explorer.itemAt(pos);menu=QMenu()
        if not item:menu.addAction(FOLDER_ICON,"New Folder",self.create_folder_action);menu.addAction(QIcon.fromTheme("list-add"),"Add Connection",self.add_connection)
        else:
            original_idx=item.data(0,Qt.UserRole);is_favorite_link=item.data(0,Qt.UserRole+1)==True;is_favorites_folder=item.text(0)=="Favorites"
            if is_favorites_folder:menu.addAction("Clear All Favorites",self.clear_all_favorites)
            elif original_idx is not None and 0<=original_idx<len(self.connections):
                conn_data=self.connections[original_idx]
                if conn_data.get("type")!="folder":menu.addAction(QIcon.fromTheme("media-playback-start"),"Launch",lambda:self.launch_connection_from_item(item));(menu.addAction(STAR_ICON,"Remove from Favorites",lambda:self.toggle_favorite(original_idx,False))if is_favorite_link or original_idx in self.favorites_indices else menu.addAction(STAR_ICON,"Add to Favorites",lambda:self.toggle_favorite(original_idx,True)));menu.addSeparator()
                if not is_favorite_link:(menu.addAction("Rename Folder",lambda:self.rename_folder_action(item,original_idx))if conn_data.get("type")=="folder"else None);menu.addAction(QIcon.fromTheme("edit-delete"),"Delete Original Item",lambda:self.delete_item_action(item,original_idx))
                elif is_favorite_link:menu.addAction(STAR_ICON,"Remove from Favorites",lambda:self.toggle_favorite(original_idx,False))
            if not is_favorites_folder:menu.addSeparator();menu.addAction(FOLDER_ICON,"New Folder",self.create_folder_action);menu.addAction(QIcon.fromTheme("list-add"),"Add Connection",self.add_connection)
        menu.exec_(self.explorer.viewport().mapToGlobal(pos))

    def toggle_favorite(self,original_idx,add):
        (self.favorites_indices.append(original_idx)if add and original_idx not in self.favorites_indices else(self.favorites_indices.remove(original_idx)if not add and original_idx in self.favorites_indices else None));self.save_connections_data();self.refresh_connection_list(sel_fav_link_orig_idx=original_idx if add else None,sel_orig_idx=original_idx if not add else None)

    def clear_all_favorites(self):
        (self.favorites_indices.clear(),self.save_connections_data(),self.refresh_connection_list())if QMessageBox.question(self,"Confirm","Clear all favorites?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes else None

    def create_menus(self):
        menubar=self.menuBar();file_menu=menubar.addMenu("&File");view_menu=menubar.addMenu("&View");help_menu=menubar.addMenu("&Help")
        exit_action=QAction("E&xit",self);exit_action.triggered.connect(self.close);file_menu.addAction(exit_action)
        self.theme_menu=view_menu.addMenu("Theme");light_action=QAction("Light",self,checkable=True);light_action.triggered.connect(lambda:self.switch_theme("light"))
        dark_action=QAction("Dark",self,checkable=True);dark_action.triggered.connect(lambda:self.switch_theme("dark"));self.theme_menu.addActions([light_action,dark_action]);(dark_action if self.settings.get("theme")=="dark"else light_action).setChecked(True)
        about_action=QAction(f"About {APP_NAME}",self);about_action.triggered.connect(self.show_about_dialog);help_menu.addAction(about_action)

    def show_about_dialog(self):
        about_text = f"""
        <h2>{APP_NAME}</h2>
        <p>SSH & RDP sessions made manageable</p>
        <p>Version: {APP_VERSION}</p>
        <p>A powerful and intuitive utility for managing structured remote connections.
Organise, edit, and launch SSH and RDP sessions in a unified tabbed interface.
Includes folder-based grouping, embedded terminal support, password and key authentication, and session persistence — all wrapped in a clean, tree-style explorer.</p>
        <p>© 2025 {APP_AUTHOR}</p>
        <p>Visit: <a href='{APP_WEBSITE}'>{APP_WEBSITE}</a></p>
        """ # Removed SSH instances line
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(f"About {APP_NAME}")
        if APP_ICON and not APP_ICON.isNull(): # Use APP_ICON if valid
            msg_box.setIconPixmap(APP_ICON.pixmap(64, 64))
        else: # Fallback if APP_ICON isn't loaded or is null
            msg_box.setIcon(QMessageBox.Information)
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(about_text)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    def switch_theme(self,theme_name):self.settings['theme']=theme_name;self.save_current_settings();self.apply_theme(theme_name);[a.setChecked(a.text().lower().startswith(theme_name))for a in self.theme_menu.actions()]
    def apply_theme(self,theme_name):
        stylesheet="";
        if theme_name=="dark":
            try:import qdarkstyle;stylesheet=qdarkstyle.load_stylesheet_pyqt5()
            except ImportError:stylesheet="QMainWindow,QDialog,QWidget{background-color:#333;color:#EEE}QGroupBox{border:1px solid #555;margin-top:1ex}QGroupBox::title{subcontrol-origin:margin;subcontrol-position:top left;padding:0 3px;background-color:#444;color:#EEE}QLineEdit,QComboBox,QTreeWidget,QTabWidget::pane,QScrollArea{background-color:#444;color:#EEE;border:1px solid #555;padding:2px}QPushButton{background-color:#555;color:#EEE;border:1px solid #666;padding:5px}QPushButton:hover{background-color:#666}QPushButton:pressed{background-color:#4E4E4E}QTabBar::tab{background:#555;color:#EEE;padding:5px;border-top-left-radius:4px;border-top-right-radius:4px}QTabBar::tab:selected{background:#444}QMenu{background-color:#333;color:#EEE;border:1px solid #555}QMenu::item:selected{background-color:#555}QSplitter::handle{background-color:#555}QScrollArea{border:none}"
        self.setStyleSheet(stylesheet)
    def save_current_settings(self):save_initial_settings(self.settings)
    def rename_folder_action(self,item,folder_idx):
        if not(0<=folder_idx<len(self.connections)):return
        old_name=self.connections[folder_idx]["name"];new_name,ok=QInputDialog.getText(self,"Rename Folder","New name:",QLineEdit.Normal,old_name)
        if ok and new_name.strip()and new_name!=old_name:
            new_name=new_name.strip();
            if any(c.get("name")==new_name and c.get("type")=="folder"for i,c in enumerate(self.connections)if i!=folder_idx):QMessageBox.warning(self,"Error",f"Folder '{new_name}' exists.");return
            self.connections[folder_idx]["name"]=new_name;[c.update({"folder":new_name})for c in self.connections if c.get("folder")==old_name]
            self.save_connections_data();self.refresh_connection_list(sel_orig_idx=folder_idx)
            if self.edit_pane.current_item_index is not None and self.connections[self.edit_pane.current_item_index].get("folder")==new_name:self.edit_pane.load_connection_data(self.connections[self.edit_pane.current_item_index],self.edit_pane.current_item_index)
    def delete_item_action(self,item,item_idx):
        if not(0<=item_idx<len(self.connections)):return
        conn_data=self.connections[item_idx];item_name=conn_data.get("name","item");item_type="folder"if conn_data.get("type")=="folder"else"connection"
        if QMessageBox.question(self,"Confirm Delete",f"Delete original {item_type} '{item_name}'?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
            if item_type=="folder"and[c for c in self.connections if c.get("folder")==item_name]:
                reply=QMessageBox.question(self,"Folder Contents",f"Move contents of '{item_name}' to 'Default'?",QMessageBox.Yes|QMessageBox.No|QMessageBox.Cancel)
                if reply==QMessageBox.Cancel:return
                if reply==QMessageBox.Yes:[c.update({"folder":"Default"})for c in self.connections if c.get("folder")==item_name]
                elif reply==QMessageBox.No:QMessageBox.information(self,"Info",f"Folder '{item_name}' not deleted.");return
            if item_idx in self.favorites_indices:self.favorites_indices.remove(item_idx)
            self.favorites_indices=[i if i<item_idx else i-1 for i in self.favorites_indices if i!=item_idx];del self.connections[item_idx]
            self.save_connections_data();self.refresh_connection_list();self.edit_pane.clear_and_hide()
    def create_folder_action(self):
        name,ok=QInputDialog.getText(self,"New Folder","Folder name:")
        if ok and name.strip()and not any(c.get("name")==name.strip()and c.get("type")=="folder"for c in self.connections):self.connections.append({"name":name.strip(),"type":"folder"});self.save_connections_data();self.refresh_connection_list(sel_orig_idx=len(self.connections)-1)
        elif ok and name.strip():QMessageBox.warning(self,"Error",f"Folder '{name.strip()}' exists.")
    def add_connection(self):
        new_idx=len(self.connections);folder_name="Default";current_item=self.explorer.currentItem()
        if current_item:
            original_idx=current_item.data(0,Qt.UserRole);folder_name=(self.connections[original_idx]["name"]if self.connections[original_idx].get("type")=="folder"else self.connections[original_idx].get("folder","Default"))if original_idx is not None and 0<=original_idx<len(self.connections)else "Default"
        self.connections.append({"name":"New Conn","folder":folder_name,"type":"ssh","port":DEFAULT_PORTS["ssh"]});self.save_connections_data();self.refresh_connection_list(sel_orig_idx=new_idx)
        newly_selected_item=self.find_item_by_index(new_idx);newly_selected_item and(self.explorer.setCurrentItem(newly_selected_item),self.handle_item_click(newly_selected_item))
    def launch_connection_from_item(self,item,col=0):
        original_idx=item.data(0,Qt.UserRole)
        if original_idx is not None and 0<=original_idx<len(self.connections):
            connection_data=self.connections[original_idx]
            if connection_data.get("type")=="folder":item.setExpanded(not item.isExpanded())
            elif connection_data.get("type")=="ssh":self.launch_ssh_tab(connection_data)
            elif connection_data.get("type")=="rdp":self.launch_rdp_tab(connection_data)

    def launch_ssh_tab(self, conn_data):
        host = conn_data.get("host"); ssh_port = str(conn_data.get("port", DEFAULT_PORTS["ssh"]))
        username = conn_data.get("username"); password_decrypted = conn_data.get("password_decrypted", "")
        ssh_key_path = conn_data.get("ssh_key_path", ""); ssh_key_passphrase = conn_data.get("ssh_key_passphrase_decrypted", "")
        if not host or not username: QMessageBox.warning(self, "Missing Info", "Host or username missing for SSH."); return
        wssh_instance_port = find_free_port()
        if not wssh_instance_port: QMessageBox.critical(self, "Port Error", "Could not find a free port for webssh instance."); return
        base_path = get_application_path()
        webssh_dir = os.path.join(base_path, "webssh")
        webssh_run_script = os.path.join(webssh_dir, "run.py")
        if not os.path.exists(webssh_run_script):
            QMessageBox.critical(self, "WebSSH Error", f"webssh script not found: {webssh_run_script}\nBase path: {base_path}"); logging.error(f"webssh script not found: {webssh_run_script} (Base path: {base_path})"); return
        python_executable_to_use = sys.executable
        if getattr(sys, 'frozen', False):
            bundled_python_path = os.path.join(base_path, "python.exe") 
            if os.path.exists(bundled_python_path): python_executable_to_use = bundled_python_path
            else: python_executable_to_use = "python"; logging.warning(f"Frozen, bundled python not found. Trying '{python_executable_to_use}' from PATH.")
        command = [python_executable_to_use, webssh_run_script, f"--port={wssh_instance_port}", "--logging=info", "--policy=warning"]
        process = None
        try:
            logging.info(f"Launching dedicated webssh: {' '.join(command)} from cwd: {webssh_dir}")
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       creationflags=creation_flags, text=True, bufsize=1, cwd=webssh_dir)
            max_wait, poll_int, started = 7, 0.3, False
            for _ in range(int(max_wait / poll_int)):
                if process.poll() is not None: break 
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(poll_int / 2)
                try:
                    if s.connect_ex((WEBSSH_HOST, wssh_instance_port)) == 0: started = True; logging.info(f"Webssh on port {wssh_instance_port} listening."); break
                except socket.error: pass
                finally: s.close()
                time.sleep(poll_int)
            if not started or process.poll() is not None:
                 out = process.stdout.read() if process.stdout and not process.stdout.closed else "N/A (stdout)"
                 err = process.stderr.read() if process.stderr and not process.stderr.closed else "N/A (stderr)"
                 logging.error(f"Webssh start fail port {wssh_instance_port}. Code: {process.poll()}\nSTDOUT:\n{out[:1000]}\nSTDERR:\n{err[:1000]}")
                 QMessageBox.critical(self, "WebSSH Error", f"Failed to start webssh on port {wssh_instance_port}. See log at {log_file_path} for details."); process and process.poll() is None and process.terminate(); return
        except Exception as e: logging.error(f"Webssh launch exception: {e}", exc_info=True); QMessageBox.critical(self, "WebSSH Launch Error", f"General error launching webssh: {e}"); return
        
        term_view = QWebEngineView(); term_url = QUrl(f"http://{WEBSSH_HOST}:{wssh_instance_port}/")
        self.active_webssh_processes[term_view] = process; self.webssh_ports[term_view] = wssh_instance_port

        def on_load_finished(ok):
            if not ok: logging.warning(f"Failed to load webssh page from port {wssh_instance_port}"); QMessageBox.warning(self, "WebSSH Load Error", f"Page load failed for port {wssh_instance_port}."); self.cleanup_webssh_instance(term_view); return
            opts = {"hostname": host, "port": ssh_port, "username": username}
            if ssh_key_path:
                try:
                    with open(ssh_key_path, 'r') as kf: opts["privatekey"] = kf.read()
                    if ssh_key_passphrase: opts["passphrase"] = ssh_key_passphrase
                except Exception as e: logging.error(f"Key read error '{ssh_key_path}': {e}", exc_info=True); QMessageBox.warning(self, "Key Error", f"Read SSH key '{ssh_key_path}': {e}"); self.cleanup_webssh_instance(term_view); return
            elif password_decrypted: opts["password"] = password_decrypted
            
            opts_json_string = json.dumps(opts)
            raw_js_template = """
                var style=document.createElement('style');style.type='text/css';
                style.innerHTML=`body{background-color:#222!important}form,.connect-form,#connect,div[role="form"],h1,button[type="submit"],.form-group,.x-panel-body{display:none!important;visibility:hidden!important}`;
                (document.head||document.body).appendChild(style);console.log('ConnStruct: CSS Injected.');
                
                var connectAttempts=0; 
                var maxConnectAttempts=20; 
                var opts_data = __OPTS_JSON_PLACEHOLDER__; 

                function connect() { 
                    connectAttempts++; 
                    if(typeof wssh !== 'undefined' && typeof wssh.connect === 'function') {
                        console.log('ConnStruct: wssh found. Connecting with opts:', opts_data);
                        wssh.connect(opts_data);
                        
                        var obs = new MutationObserver((m,o)=>{
                            if(document.body.innerText.toLowerCase().match(/chan closed|connection closed|logout|session closed|authentication failed/))
                                !window.location.hash.includes('closedByApp')&&(window.location.hash='connStructSessionClosed',o.disconnect(),window.connStructTtydMonInt&&clearInterval(window.connStructTtydMonInt))
                        });
                        if(document.body) obs.observe(document.body,{childList:true,subtree:true,characterData:true});
                        else console.warn('ConnStruct: document.body not ready for observer.');

                        window.connStructTtydMonInt=setInterval(()=>{
                            if(document.body&&document.body.innerText.toLowerCase().match(/chan closed|connection closed|logout|session closed|authentication failed/))
                                !window.location.hash.includes('closedByApp')&&(window.location.hash='connStructSessionClosed',clearInterval(window.connStructTtydMonInt))
                        },1500);
                    } else if (connectAttempts < maxConnectAttempts) { 
                        console.log('ConnStruct: wssh not ready, attempt:'+connectAttempts);
                        setTimeout(connect,500);
                    } else { 
                        console.error('ConnStruct: wssh.connect not defined after '+maxConnectAttempts+' attempts.');
                        style.innerHTML=''; 
                        alert('ConnStruct: Failed to init SSH session.');
                    }
                }
                connect();
            """
            js_to_run = raw_js_template.replace("__OPTS_JSON_PLACEHOLDER__", opts_json_string)
            
            logging.debug(f"Injecting JS for wssh.connect on port {wssh_instance_port} with JS (first 200 chars): {js_to_run[:200]}...")
            term_view.page().runJavaScript(js_to_run)

        def on_url_changed(new_url):
            if new_url.fragment() == "connStructSessionClosed": logging.debug(f"SessionClosed fragment for {term_view}"); self.cleanup_webssh_instance(term_view)

        term_view.loadFinished.connect(on_load_finished); term_view.urlChanged.connect(on_url_changed)
        tab_index = self.tabs.addTab(term_view, f"SSH: {conn_data.get('name', host)}"); self.tabs.setCurrentIndex(tab_index)
        term_view.setUrl(term_url)

    def cleanup_webssh_instance(self, term_widget):
        if term_widget in self.active_webssh_processes:
            process = self.active_webssh_processes.pop(term_widget)
            port = self.webssh_ports.pop(term_widget, "Unknown")
            logging.info(f"Terminating webssh (PID: {process.pid}, Port: {port}).")
            try: process.terminate(); process.wait(timeout=1)
            except subprocess.TimeoutExpired: logging.warning(f"Killing webssh PID {process.pid}."); process.kill()
            except Exception as e: logging.error(f"Terminating webssh PID {process.pid}: {e}", exc_info=True)
        tab_index = self.tabs.indexOf(term_widget)
        if tab_index != -1: self.tabs.removeTab(tab_index)
        if hasattr(term_widget,'force_close_timer_confirm')and term_widget.force_close_timer_confirm.isActive():
            term_widget.force_close_timer_confirm.stop(); delattr(term_widget, 'force_close_timer_confirm')
        term_widget.deleteLater()

    def confirm_close_tab(self,index):
        widget = self.tabs.widget(index)
        if widget in self.active_webssh_processes:
            if QMessageBox.question(self,"Exit SSH","Close SSH session?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
                widget.page().runJavaScript("try{(document.querySelector('terminal-container')||document.querySelector('.xterm-helper-textarea')||document.body).focus(); document.execCommand('insertText',false,'exit\\n'); window.location.hash='closedByApp';}catch(e){console.error('JS exit err:',e)}")
                if not hasattr(widget,'force_close_timer_confirm'):
                    widget.force_close_timer_confirm=QTimer(widget);widget.force_close_timer_confirm.setSingleShot(True)
                    cw=widget;widget.force_close_timer_confirm.timeout.connect(lambda:self.cleanup_webssh_instance(cw));widget.force_close_timer_confirm.start(2000)
        else: self.tabs.removeTab(index); widget and widget.deleteLater()

    def launch_rdp_tab(self,conn_data):
        h,p_str=conn_data.get("host"),str(conn_data.get("port",DEFAULT_PORTS["rdp"]))
        rdp_resolution = conn_data.get("rdp_resolution", "Default")
        if not h:QMessageBox.warning(self,"Missing Info","Hostname missing for RDP.");return
        addr_conn=h;
        if p_str and p_str!=DEFAULT_PORTS["rdp"]:addr_conn=f"{h}:{p_str}"
        info_label=QLabel(f"Launching RDP for: {addr_conn}\nResolution: {rdp_resolution}\n\nClose this tab manually.");info_label.setAlignment(Qt.AlignCenter)
        tab_index=self.tabs.addTab(info_label,f"RDP: {conn_data.get('name',h)}");self.tabs.setCurrentIndex(tab_index)
        try:
            command_list=["mstsc.exe",f"/v:{addr_conn}"] # Default to mstsc
            if rdp_resolution == "Fullscreen": command_list.append("/f")
            elif rdp_resolution != "Default":
                try: w, ht = map(int, rdp_resolution.split('x')); command_list.extend([f"/w:{w}", f"/h:{ht}"])
                except ValueError: logging.warning(f"Invalid RDP res: {rdp_resolution}")
            
            if sys.platform=="darwin":command_list=["open",f"rdp://{addr_conn}"] # Mac RDP client might not support w/h via open
            elif sys.platform !="win32": # Linux
                found_client = False
                for client_try_cmd_list in [["xfreerdp",f"/v:{addr_conn}"],["rdesktop",addr_conn]]: # xfreerdp might take /w /h
                    try:subprocess.check_call(["which",client_try_cmd_list[0]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);command_list=client_try_cmd_list; found_client=True; break
                    except:continue
                if not found_client:QMessageBox.warning(self,"RDP Error","No RDP client found (xfreerdp, rdesktop).");self.tabs.removeTab(tab_index);return
            
            logging.info(f"Launching RDP with command: {' '.join(command_list)}")
            subprocess.Popen(command_list)
        except Exception as e: logging.error(f"RDP Launch Error: {e}", exc_info=True); QMessageBox.critical(self,"RDP Launch Error",f"{e}");self.tabs.removeTab(tab_index)

    def closeEvent(self,event):
        logging.info(f"{APP_NAME} closing. Terminating active webssh instances.")
        self.save_current_settings()
        for term_widget in list(self.active_webssh_processes.keys()):
            self.cleanup_webssh_instance(term_widget)
        super().closeEvent(event)

# --- Main Application Logic ---
def main_app_logic():
    base_path = get_application_path()
    logging.info(f"Application base path at startup: {base_path}")
    webssh_check_script = os.path.join(base_path, "webssh", "run.py")
    if not os.path.exists(webssh_check_script):
         logging.error(f"Core component 'webssh/run.py' not found at: {webssh_check_script} using base_path: {base_path}")
         QMessageBox.critical(None, f"{APP_NAME} Error", f"Core component 'webssh/run.py' not found at expected location:\n{webssh_check_script}\n\nThe application might not function correctly for SSH sessions. Please ensure the 'webssh' directory is present alongside the application or in the extracted PyInstaller directory.")

    crypto=CryptoHelper();settings=load_initial_settings();master_ok=False
    if 'master_hash' in settings and 'master_salt' in settings:
        for attempt_num in range(3):
            dialog=MasterPasswordDialog(is_setting_up=False)
            if dialog.exec_()==QDialog.Accepted:
                password_entered=dialog.get_password()
                if password_entered and crypto.verify_master_password(settings['master_hash'],settings['master_salt'],password_entered):
                    crypto.derive_fernet_key(password_entered,settings['master_salt']);master_ok=True;break
                else:QMessageBox.warning(None,"Login Failed",f"Incorrect. {2-attempt_num} attempts left.")
            else:logging.info("Master password entry cancelled by user.");sys.exit("Pwd entry cancelled.")
        if not master_ok:logging.error("Too many incorrect master password attempts.");sys.exit("Too many incorrect pwd attempts.")
    else:
        logging.info("No master password found, initiating setup.")
        dialog=MasterPasswordDialog(is_setting_up=True)
        if dialog.exec_()==QDialog.Accepted:
            password_entered=dialog.get_password()
            if password_entered:
                salt_val=crypto.generate_salt();settings.update({'master_salt':salt_val,'master_hash':crypto.hash_master_password(password_entered,salt_val),'theme':'light'});save_initial_settings(settings);crypto.derive_fernet_key(password_entered,salt_val);master_ok=True
                logging.info("Master password setup successful.")
            else:logging.error("Pwd setup failed (empty or mismatch).");sys.exit("Pwd setup failed.")
        else:logging.info("Master password setup cancelled by user.");sys.exit("Pwd setup cancelled.")
    if not master_ok:logging.critical("Master pwd not verified/set.");sys.exit("Master pwd not verified/set.")
    
    logging.info(f"{APP_NAME} starting UI...")
    window=ConnectionManager(crypto,settings);window.show();sys.exit(QApplication.instance().exec_())

if __name__ == '__main__':
    if sys.platform.startswith('win'):
        multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_AUTHOR) 
    initialize_icons()
    logging.info(f"--- {APP_NAME} v{APP_VERSION} Session Started ---")
    logging.info(f"Log file: {log_file_path}")
    main_app_logic()
