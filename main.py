import winreg
import pymysql
import socket
import psutil
import sys
import re
import json
import base64
import ctypes
import webbrowser

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHeaderView,
    QFrame, QMessageBox, QStatusBar, QSizePolicy, QCheckBox
)
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin(fix_data=None):
    try:
        if sys.platform == 'win32':
            args = sys.argv[0]
            if fix_data:
                encoded = base64.b64encode(json.dumps(fix_data).encode()).decode()
                args = f'"{sys.argv[0]}" --apply-fix {encoded}'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    except Exception:
        return False
    return True


try:
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='',
        db='system_checker',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
except Exception as e:
    print(f"Error connecting to database: {e}")
    sys.exit(1)

pending_fix = None
if len(sys.argv) > 2 and sys.argv[1] == '--apply-fix':
    try:
        decoded = base64.b64decode(sys.argv[2]).decode()
        pending_fix = json.loads(decoded)
    except Exception:
        pass

system_name = socket.gethostname()

root_map = {
    'HKEY_LOCAL_MACHINE':  winreg.HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER':   winreg.HKEY_CURRENT_USER,
    'HKEY_CLASSES_ROOT':   winreg.HKEY_CLASSES_ROOT,
    'HKEY_USERS':          winreg.HKEY_USERS,
    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
}

LOW_SEVERITY_CATEGORIES = {'network', 'software'}

def version_tuple(v):
    parts = re.split(r'[^\d]+', v)
    return tuple(int(p) for p in parts if p.isdigit())


def compare_versions(curr, exp, op):
    ct = version_tuple(curr)
    et = version_tuple(exp)
    if op == 'eq': return ct == et
    if op == 'ne': return ct != et
    if op == 'gt': return ct > et
    if op == 'lt': return ct < et
    if op == 'ge': return ct >= et
    if op == 'le': return ct <= et
    return False
    
def get_port_process(port):
    for conn in psutil.net_connections(kind='tcp'):
        if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN' and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                return conn.pid, proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return conn.pid, 'Access Denied'
    return None, 'Unknown'

def apply_registry_value(reg_path, reg_value_name, expected_value):
    try:
        parts = reg_path.split('\\')
        root_str = parts[0]
        if root_str not in root_map:
            raise ValueError(f"Unknown registry root: {root_str}")
        root_key = root_map[root_str]
        subkey = '\\'.join(parts[1:])
        try:
            key = winreg.OpenKey(root_key, subkey, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            key = winreg.CreateKey(root_key, subkey)
        try:
            int_value = int(expected_value)
            winreg.SetValueEx(key, reg_value_name, 0, winreg.REG_DWORD, int_value)
        except ValueError:
            winreg.SetValueEx(key, reg_value_name, 0, winreg.REG_SZ, expected_value)
        winreg.CloseKey(key)
        return True, "Success"
    except Exception as e:
        return False, str(e)


def read_registry_value(reg_path, reg_value_name):
    try:
        parts = reg_path.split('\\')
        root_str = parts[0]
        if root_str not in root_map:
            raise ValueError(f"Unknown registry root: {root_str}")
        root_key = root_map[root_str]
        subkey = '\\'.join(parts[1:])
        key = winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ)
        try:
            value, _ = winreg.QueryValueEx(key, reg_value_name)
            return str(value)
        except FileNotFoundError:
            return None
        finally:
            winreg.CloseKey(key)
    except Exception:
        return None

with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM expected_checks")
    checks = cursor.fetchall()

expected_ports = set()
for check in checks:
    if check['check_type'] == 'port' and check['expected_value']:
        try:
            expected_ports.add(int(check['expected_value']))
        except ValueError:
            pass

results = []

for check in checks:
    check_type     = check['check_type']
    check_name     = check['check_name']
    expected_value = check['expected_value']
    condition      = check['condition']
    note           = check['note']
    category       = check['category']
    reg_path       = check.get('reg_path')
    reg_value_name = check.get('reg_value_name')
    current_value  = None
    status         = 'UNKNOWN'
    link_port      = None

    db_severity = check.get('severity')
    if db_severity is not None:
        severity = int(db_severity)
    elif (category or '').lower() in LOW_SEVERITY_CATEGORIES:
        severity = 2
    else:
        severity = 1

    try:
        if check_type == 'registry':
            if reg_path and reg_value_name:
                parts = reg_path.split('\\')
                root_str = parts[0]
                if root_str not in root_map:
                    raise ValueError(f"Unknown registry root: {root_str}")
                root_key = root_map[root_str]
                subkey = '\\'.join(parts[1:])
                key = winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ)
                try:
                    value, _ = winreg.QueryValueEx(key, reg_value_name)
                    current_value = str(value)
                except FileNotFoundError:
                    current_value = None
                finally:
                    winreg.CloseKey(key)

        elif check_type == 'port':
            if expected_value:
                port = int(expected_value)
                link_port = port
                pid, proc_name = get_port_process(port)
                is_open = pid is not None
                current_value = str(port) if is_open else None
                process_info = f"{proc_name} (PID {pid})" if is_open else "—"
                prefix = f"[PORT LINK] [{process_info}]"
                note = f"{prefix} - {note}" if note else prefix

        elif check_type == 'software':
            software_partial = check_name.lower()
            matching_with_version = None
            matching_names = False
            for uninstall_base in [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            ]:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_base, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_path = f"{uninstall_base}\\{subkey_name}"
                            subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_READ)
                            try:
                                dn, _ = winreg.QueryValueEx(subkey, 'DisplayName')
                                dn_lower = str(dn).lower()
                                if software_partial in dn_lower:
                                    matching_names = True
                                    try:
                                        dv, _ = winreg.QueryValueEx(subkey, 'DisplayVersion')
                                        dv_str = str(dv)
                                        if matching_with_version is None or version_tuple(dv_str) > version_tuple(matching_with_version):
                                            matching_with_version = dv_str
                                    except FileNotFoundError:
                                        pass
                            except FileNotFoundError:
                                pass
                            winreg.CloseKey(subkey)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
            if matching_with_version is not None:
                current_value = matching_with_version
            elif matching_names:
                current_value = 'installed'
            else:
                current_value = None
        else:
            status = 'ERROR'
            current_value = f"Unsupported check_type: {check_type}"

        allow_not_exist = note and 'or not exist' in note.lower()

        if condition == 'equals':
            status = 'GOOD' if current_value == expected_value or (allow_not_exist and current_value is None) else 'BAD'
        elif condition == 'not_exists':
            status = 'GOOD' if current_value is None else 'BAD'
        elif condition == 'exists':
            status = 'GOOD' if current_value is not None else 'BAD'
        elif condition == 'contains':
            status = 'GOOD' if current_value and expected_value in current_value else 'BAD'
        elif condition == 'regex':
            status = 'GOOD' if current_value and re.match(expected_value, current_value) else 'BAD'
        elif condition in ['gt', 'lt', 'ge', 'le', 'eq', 'ne']:
            if current_value is None or current_value == 'installed':
                status = 'BAD'
            else:
                status = 'GOOD' if compare_versions(current_value, expected_value, condition) else 'BAD'
        elif allow_not_exist and current_value is None:
            status = 'GOOD'
        elif current_value is None:
            status = 'BAD'

    except Exception as e:
        status = 'ERROR'
        current_value = str(e)
        
    if check_type == 'port' and status == 'GOOD':
        continue
    results.append({
        'check_name':     check_name,
        'category':       category,
        'current_value':  current_value,
        'expected':       f"{condition} {expected_value}",
        'status':         status,
        'note':           note,
        'link_port':      link_port,
        'check_type':     check_type,
        'reg_path':       reg_path,
        'reg_value_name': reg_value_name,
        'expected_value': expected_value,
        'condition':      condition,
        'severity':       severity,
    })

listening_ports = [
    conn.laddr.port
    for conn in psutil.net_connections(kind='tcp')
    if conn.laddr and conn.status == 'LISTEN' and conn.laddr.port <= 1024
]
unexpected_ports = [p for p in listening_ports if p not in expected_ports]

for port in unexpected_ports:
    pid, proc_name = get_port_process(port)
    process_info = f"{proc_name}" if pid else "Unknown"
    results.append({
        'check_name':     f'Open Port {port}',
        'category':       'Network',
        'current_value':  str(port),
        'expected':       'closed',
        'status':         'WARNING',
        'note':           f'[PORT LINK] [{process_info}] - Unexpected open port (not listed in DB)',
        'link_port':      port,
        'check_type':     'port',
        'reg_path':       None,
        'reg_value_name': None,
        'expected_value': None,
        'condition':      None,
        'severity':       2,
    })

connection.close()

COL_NAME     = 0
COL_CATEGORY = 1
COL_CURRENT  = 2   #advanced mode
COL_EXPECTED = 3   # advanced mode
COL_STATUS   = 4
COL_NOTE     = 5
COL_ACTION   = 6

ADVANCED_COLS = (COL_CURRENT, COL_EXPECTED)

class CircularProgress(QWidget):

    def __init__(self, label_text="Compliant", ring_width=15, font_size=36, sub_font_size=11, parent=None):
        super().__init__(parent)
        self.good = self.bad = self.warning = self.total = 0
        self.label_text   = label_text
        self.ring_width   = ring_width
        self.font_size    = font_size
        self.sub_font_size = sub_font_size
        self.setMinimumSize(200, 200)

    def set_progress(self, good, bad, warning, total):
        self.good    = good
        self.bad     = bad
        self.warning = warning
        self.total   = total
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h   = self.width(), self.height()
        side   = min(w, h)
        cx, cy = w / 2, h / 2
        radius = side / 2 - 22
        rect   = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)

        painter.setPen(QPen(QColor(220, 220, 220), self.ring_width))
        painter.drawArc(rect, 0, 360 * 16)

        if self.total == 0:
            return

        start     = 90 * 16
        good_a    = int((self.good    / self.total) * 360 * 16)
        bad_a     = int((self.bad     / self.total) * 360 * 16)
        warning_a = int((self.warning / self.total) * 360 * 16)

        rw = self.ring_width
        painter.setPen(QPen(QColor(76, 175, 80),  rw, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, start, -good_a)

        painter.setPen(QPen(QColor(244, 67, 54),  rw, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, start - good_a, -bad_a)

        painter.setPen(QPen(QColor(255, 152, 0),  rw, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, start - good_a - bad_a, -warning_a)

        pct = int((self.good / self.total) * 100) if self.total > 0 else 0
        painter.setPen(QColor(30, 30, 30))
        painter.setFont(QFont('Arial', self.font_size, QFont.Weight.Bold))
        
        pct_rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2 - self.sub_font_size * 1.8)
        painter.drawText(pct_rect, Qt.AlignmentFlag.AlignCenter, f"{pct}%")

        painter.setFont(QFont('Arial', self.sub_font_size))
        label_rect = QRectF(cx - radius, cy + self.font_size * 0.55, radius * 2, self.sub_font_size * 2.4)
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, self.label_text)


class SystemCheckerWindow(QMainWindow):

    def __init__(self, results_data):
        super().__init__()
        self.results      = results_data
        self.advanced_mode = False

        self.setWindowTitle(f"System Checker Results — {system_name}")
        self.setGeometry(100, 100, 1340, 780)

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        top_bar = self._build_top_bar()
        root_layout.addWidget(top_bar)

        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setSpacing(20)
        content_layout.setContentsMargins(20, 12, 20, 20)
        content_layout.addWidget(self._build_left_panel(), stretch=1)
        content_layout.addWidget(self._build_right_panel(), stretch=3)
        root_layout.addWidget(content)

        sb = QStatusBar()
        sb.showMessage(f"Admin Mode: {'Yes' if is_admin() else 'No'}   |   Host: {system_name}")
        self.setStatusBar(sb)

        self._populate_table()
        self._update_circles()

    def _build_top_bar(self):
        bar = QFrame()
        bar.setStyleSheet("QFrame { background-color: #1e1e2e; }")
        bar.setFixedHeight(44)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)

        title = QLabel(f"System Checker  —  {system_name}")
        title.setFont(QFont('Arial', 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #cdd6f4;")
        layout.addWidget(title)
        layout.addStretch()

        self.advanced_cb = QCheckBox("Advanced User")
        self.advanced_cb.setStyleSheet("""
            QCheckBox { color: #cdd6f4; font-size: 12px; spacing: 6px; }
            QCheckBox::indicator { width: 16px; height: 16px; }
            QCheckBox::indicator:unchecked { border: 2px solid #6c7086; border-radius: 3px; background: #313244; }
            QCheckBox::indicator:checked   { border: 2px solid #89b4fa; border-radius: 3px; background: #89b4fa; }
        """)
        self.advanced_cb.stateChanged.connect(self._toggle_advanced)
        layout.addWidget(self.advanced_cb)
        return bar

    def _toggle_advanced(self, state):
        self.advanced_mode = (state == Qt.CheckState.Checked.value)
        for col in ADVANCED_COLS:
            self.table.setColumnHidden(col, not self.advanced_mode)

    def _build_left_panel(self):
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.StyledPanel)
        panel.setStyleSheet("QFrame { background-color: #f5f5f5; border-radius: 10px; }")
        panel.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(panel)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(14)
        layout.setContentsMargins(14, 16, 14, 16)

        title = QLabel("System Status")
        title.setFont(QFont('Arial', 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sev1_lbl = QLabel("Severity 1  (Critical)")
        sev1_lbl.setFont(QFont('Arial', 15, QFont.Weight.Bold))
        sev1_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sev1_lbl.setStyleSheet("color: #c62828;")
        layout.addWidget(sev1_lbl)

        self.circle_sev1 = CircularProgress(
            label_text="Compliant", ring_width=20, font_size=38, sub_font_size=12
        )
        self.circle_sev1.setMinimumSize(240, 240)
        layout.addWidget(self.circle_sev1, alignment=Qt.AlignmentFlag.AlignCenter)

        self.sev1_good_lbl    = self._make_summary_lbl("✓", "Good",    "#4CAF50", size=12)
        self.sev1_bad_lbl     = self._make_summary_lbl("✗", "Bad",     "#F44336", size=12)
        self.sev1_warning_lbl = self._make_summary_lbl("⚠", "Warning", "#FF9800", size=12)
        for w in (self.sev1_good_lbl, self.sev1_bad_lbl, self.sev1_warning_lbl):
            layout.addWidget(w)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #ccc;")
        layout.addWidget(line)

        all_lbl = QLabel("All Checks")
        all_lbl.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        all_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        all_lbl.setStyleSheet("color: #1565c0;")
        layout.addWidget(all_lbl)

        self.circle_all = CircularProgress(
            label_text="Compliant", ring_width=13, font_size=26, sub_font_size=10
        )
        self.circle_all.setMinimumSize(160, 160)
        self.circle_all.setMaximumSize(180, 180)
        layout.addWidget(self.circle_all, alignment=Qt.AlignmentFlag.AlignCenter)

        self.all_good_lbl    = self._make_summary_lbl("✓", "Good",    "#4CAF50", size=10)
        self.all_bad_lbl     = self._make_summary_lbl("✗", "Bad",     "#F44336", size=10)
        self.all_warning_lbl = self._make_summary_lbl("⚠", "Warning", "#FF9800", size=10)
        for w in (self.all_good_lbl, self.all_bad_lbl, self.all_warning_lbl):
            layout.addWidget(w)

        layout.addStretch()
        return panel

    def _make_summary_lbl(self, icon, text, color, size=11):
        lbl = QLabel(f"{icon} {text}: 0")
        lbl.setFont(QFont('Arial', size))
        lbl.setStyleSheet(f"QLabel {{ color: {color}; padding: 2px 6px; }}")
        return lbl

    def _build_right_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        hdr = QHBoxLayout()
        title = QLabel("Check Details")
        title.setFont(QFont('Arial', 15, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; color: white; border: none;
                padding: 8px 16px; border-radius: 4px; font-weight: bold;
            }
            QPushButton:hover { background-color: #1976D2; }
        """)
        refresh_btn.clicked.connect(self._populate_table)
        hdr.addWidget(refresh_btn)
        layout.addLayout(hdr)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ['Check Name', 'Category', 'Current Value', 'Expected', 'Status', 'Note', 'Action']
        )
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget { border: 1px solid #ddd; border-radius: 5px; background-color: white; }
            QTableWidget::item { padding: 7px; }
            QHeaderView::section {
                background-color: #2196F3; color: white;
                padding: 8px; border: none; font-weight: bold;
            }
        """)

        hv = self.table.horizontalHeader()
        hv.setSectionResizeMode(COL_NAME,     QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(COL_CATEGORY, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(COL_CURRENT,  QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(COL_EXPECTED, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(COL_STATUS,   QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(COL_NOTE,     QHeaderView.ResizeMode.Stretch)
        hv.setSectionResizeMode(COL_ACTION,   QHeaderView.ResizeMode.ResizeToContents)

        for col in ADVANCED_COLS:
            self.table.setColumnHidden(col, True)

        self.table.cellClicked.connect(self._handle_cell_click)
        layout.addWidget(self.table)
        return panel

    def _populate_table(self):
        self.table.setRowCount(len(self.results))

        for row, r in enumerate(self.results):
            note_display = r['note'] or ''
            if len(note_display) > 60:
                note_display = note_display[:60] + '...'

            action_text = "[FIX]" if (r['check_type'] == 'registry' and r['status'] in ('BAD', 'ERROR')) else ""

            def _cell(text):
                item = QTableWidgetItem(str(text) if text is not None else '')
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                return item

            self.table.setItem(row, COL_NAME,     _cell(r['check_name']))
            self.table.setItem(row, COL_CATEGORY, _cell(r['category']))
            self.table.setItem(row, COL_CURRENT,  _cell(r['current_value'] if r['current_value'] is not None else 'None'))
            self.table.setItem(row, COL_EXPECTED, _cell(r['expected']))

            # Status cell
            status = r['status']
            status_item = QTableWidgetItem(status)
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item.setFont(QFont('Arial', 15, QFont.Weight.Bold))
            colors = {
                'GOOD':    (QColor(200, 230, 201), QColor(27,  94,  32)),
                'BAD':     (QColor(255, 205, 210), QColor(183, 28,  28)),
                'WARNING': (QColor(255, 224, 178), QColor(230, 81,   0)),
                'ERROR':   (QColor(255, 249, 196), QColor(130, 100,  0)),
            }
            if status in colors:
                bg, fg = colors[status]
                status_item.setBackground(bg)
                status_item.setForeground(fg)
            self.table.setItem(row, COL_STATUS, status_item)

            note_item = _cell(note_display)
            if r.get('link_port'):
                note_item.setForeground(QColor(21, 101, 192))
                f = QFont('Arial', 10)
                f.setUnderline(True)
                note_item.setFont(f)
            self.table.setItem(row, COL_NOTE, note_item)

            action_item = _cell(action_text)
            if action_text:
                action_item.setForeground(QColor(21, 101, 192))
                action_item.setFont(QFont('Arial', 10, QFont.Weight.Bold))
                action_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, COL_ACTION, action_item)

        for col in ADVANCED_COLS:
            self.table.setColumnHidden(col, not self.advanced_mode)

        self._update_circles()

    def _update_circles(self):
        sev1 = [r for r in self.results if r.get('severity', 1) == 1]
        g1 = sum(1 for r in sev1 if r['status'] == 'GOOD')
        b1 = sum(1 for r in sev1 if r['status'] in ('BAD', 'ERROR'))
        w1 = sum(1 for r in sev1 if r['status'] == 'WARNING')
        self.circle_sev1.set_progress(g1, b1, w1, len(sev1))
        self.sev1_good_lbl.setText(f"✓ Good: {g1}")
        self.sev1_bad_lbl.setText(f"✗ Bad: {b1}")
        self.sev1_warning_lbl.setText(f"⚠ Warning: {w1}")

        ga = sum(1 for r in self.results if r['status'] == 'GOOD')
        ba = sum(1 for r in self.results if r['status'] in ('BAD', 'ERROR'))
        wa = sum(1 for r in self.results if r['status'] == 'WARNING')
        self.circle_all.set_progress(ga, ba, wa, len(self.results))
        self.all_good_lbl.setText(f"✓ Good: {ga}")
        self.all_bad_lbl.setText(f"✗ Bad: {ba}")
        self.all_warning_lbl.setText(f"⚠ Warning: {wa}")

    def _handle_cell_click(self, row, col):
        if row >= len(self.results):
            return
        r = self.results[row]

        if col == COL_NOTE and r.get('link_port'):
            webbrowser.open(f"https://www.speedguide.net/port.php?port={r['link_port']}")

        elif col == COL_ACTION and r['check_type'] == 'registry' and r['status'] in ('BAD', 'ERROR'):
            msg = (
                f"Apply registry fix?\n\n"
                f"Path: {r['reg_path']}\n"
                f"Value Name: {r['reg_value_name']}\n"
                f"Current: {r['current_value']}\n"
                f"Expected: {r['expected_value']}\n\n"
                f"This will require administrator privileges."
            )
            reply = QMessageBox.question(self, "Confirm Registry Change", msg,
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                if not is_admin():
                    fix_data = {
                        'reg_path':       r['reg_path'],
                        'reg_value_name': r['reg_value_name'],
                        'expected_value': r['expected_value'],
                    }
                    QMessageBox.information(
                        self, "Admin Rights Required",
                        "This operation requires administrator privileges.\n\n"
                        "The application will now restart with elevated privileges\n"
                        "and automatically apply the fix."
                    )
                    run_as_admin(fix_data)
                    sys.exit()

                success, message = apply_registry_value(
                    r['reg_path'], r['reg_value_name'], r['expected_value']
                )
                if success:
                    self._recheck_registry(row)
                    QMessageBox.information(self, "Success",
                                            "Registry value updated successfully!\n\nThe status has been refreshed.")
                else:
                    QMessageBox.critical(self, "Error", f"Failed to update registry value:\n{message}")

    def _recheck_registry(self, row):
        r = self.results[row]
        if r['check_type'] != 'registry':
            return

        current_value  = read_registry_value(r['reg_path'], r['reg_value_name'])
        r['current_value'] = current_value
        condition      = r['condition']
        expected_value = r['expected_value']
        note           = r['note']
        allow_not_exist = note and 'or not exist' in note.lower()

        if condition == 'equals':
            r['status'] = 'GOOD' if current_value == expected_value or (allow_not_exist and current_value is None) else 'BAD'
        elif condition == 'not_exists':
            r['status'] = 'GOOD' if current_value is None else 'BAD'
        elif condition == 'exists':
            r['status'] = 'GOOD' if current_value is not None else 'BAD'
        elif condition == 'contains':
            r['status'] = 'GOOD' if current_value and expected_value in current_value else 'BAD'
        elif condition == 'regex':
            r['status'] = 'GOOD' if current_value and re.match(expected_value, current_value) else 'BAD'
        elif condition in ['gt', 'lt', 'ge', 'le', 'eq', 'ne']:
            if current_value is None or current_value == 'installed':
                r['status'] = 'BAD'
            else:
                r['status'] = 'GOOD' if compare_versions(current_value, expected_value, condition) else 'BAD'
        elif allow_not_exist and current_value is None:
            r['status'] = 'GOOD'
        elif current_value is None:
            r['status'] = 'BAD'

        self._populate_table()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = SystemCheckerWindow(results)
    window.show()

    if pending_fix and is_admin():
        success, message = apply_registry_value(
            pending_fix['reg_path'],
            pending_fix['reg_value_name'],
            pending_fix['expected_value'],
        )
        if success:
            for i, r in enumerate(results):
                if (r.get('reg_path') == pending_fix['reg_path'] and
                        r.get('reg_value_name') == pending_fix['reg_value_name']):
                    window._recheck_registry(i)
                    break
            QMessageBox.information(
                window, "Success",
                f"Registry value updated successfully!\n\n"
                f"Path: {pending_fix['reg_path']}\n"
                f"Value: {pending_fix['reg_value_name']}\n\nThe status has been refreshed."
            )
        else:
            QMessageBox.critical(window, "Error", f"Failed to update registry value:\n{message}")

    sys.exit(app.exec())


if __name__ == '__main__':
    main()