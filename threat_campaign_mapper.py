#!/usr/bin/env python3
"""
threat_campaign_mapper.py

PySide6 GUI app that fetches ATT&CK campaigns asynchronously using QRunnable and QThreadPool.
Streams results progressively to the UI and supports exports.
"""

__version__ = "0.5.1"
__author__= "eth08"

import sys
import re
import os
import time
import pandas as pd
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Tuple
import json
import requests
import logging
import traceback
import uuid
from collections import defaultdict

# AlienVault OTX library is required for this feature
try:
    from OTXv2 import OTXv2
    OTX_AVAILABLE = True
except ImportError:
    OTX_AVAILABLE = False

# Keyring is used for secure API key storage
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

from mitreattack.stix20 import MitreAttackData

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QDateEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QFileDialog, QMessageBox, QCheckBox, QProgressBar, QHeaderView,
    QComboBox, QTextEdit, QDialog, QDialogButtonBox, QSizePolicy, QGroupBox,
    QTextBrowser
)
from PySide6.QtCore import QDate, QRunnable, QThreadPool, QObject, Signal, Slot, Qt, QRect, QSize, QUrl
from PySide6.QtGui import QIcon, QTextOption, QDesktopServices


# --------------------
# Configuration
# --------------------

class Column:
    """Holds constants for all data column names."""
    CATEGORY = "ATT&CK Category"
    CAMPAIGN_ID = "Campaign ID"
    CAMPAIGN_NAME = "Campaign Name"
    ALIASES = "Aliases"
    DESCRIPTION = "Description"
    APT_GROUP = "APT Group"
    TTPS = "TTPs"
    TOOLS = "Tools"
    FIRST_SEEN = "First Seen"
    LAST_SEEN = "Last Seen"
    IOCS = "IOCs"
    UUID = "__UUID"

COLUMN_HEADERS = [
    Column.CATEGORY, Column.CAMPAIGN_ID, Column.CAMPAIGN_NAME, Column.ALIASES,
    Column.DESCRIPTION, Column.APT_GROUP, Column.TTPS, Column.TOOLS,
    Column.FIRST_SEEN, Column.LAST_SEEN, Column.IOCS
]

COLUMN_HEADERS_FOR_EXPORT_XLSX = [
    Column.CATEGORY, Column.CAMPAIGN_ID, Column.CAMPAIGN_NAME, Column.ALIASES,
    Column.DESCRIPTION, Column.APT_GROUP, Column.TTPS, Column.TOOLS,
    Column.FIRST_SEEN, Column.LAST_SEEN
]

# The full list of columns including our internal one
ALL_COLUMNS = COLUMN_HEADERS + [Column.UUID]


ATTACK_DATA_CONFIG = {
    "Enterprise": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "file": "enterprise-attack.json"
    },
    "ICS": {
        "url": "https://github.com/mitre-attack/attack-stix-data/blob/master/ics-attack/ics-attack.json?raw=true",
        "file": "ics-attack.json"
    },
    "Mobile": {
        "url": "https://github.com/mitre-attack/attack-stix-data/blob/master/mobile-attack/mobile-attack.json?raw=true",
        "file": "mobile-attack.json"
    }
}

CACHE_DURATION_SECONDS = 24 * 60 * 60  # 24 hours
KEYRING_SERVICE_NAME = "ThreatCampaignMapper"
KEYRING_USERNAME = "OTX_API_KEY"

# --------------------
# Worker Signals
# --------------------
class WorkerSignals(QObject):
    progress = Signal(int)
    partial = Signal(list)
    finished = Signal(list)
    error = Signal(str)

class IocWorkerSignals(QObject):
    finished = Signal(str, list, list)  # uuid, iocs_list, structured_iocs
    error = Signal(str, str) # uuid, error_message

# --------------------
# Worker Runnables
# --------------------
class CampaignFetchRunnable(QRunnable):
    """Fetches and filters campaign data in a background thread."""
    def __init__(self, search_pat, date_filter_enabled, start_date, end_date, mitre_data_objects, batch_size=10):
        super().__init__()
        self.signals = WorkerSignals()
        self.search_pat = search_pat
        self.date_filter_enabled = date_filter_enabled
        self.start_date = start_date
        self.end_date = end_date
        self.mitre_data_objects = mitre_data_objects
        self.batch_size = batch_size
        self._interrupted = False

    def interrupt(self):
        self._interrupted = True

    def run(self):
        try:
            self.signals.progress.emit(5)
            results = []
            batch = []
            total_campaigns = sum(len(data.get_campaigns(remove_revoked_deprecated=True)) for data in self.mitre_data_objects.values()) or 1
            processed_count = 0

            for category, mitre_attack_data in self.mitre_data_objects.items():
                if self._interrupted: break
                all_campaigns = mitre_attack_data.get_campaigns(remove_revoked_deprecated=True)

                for campaign in all_campaigns:
                    if self._interrupted: break
                    processed_count += 1
                    percent = 5 + int((processed_count / total_campaigns) * 90)
                    self.signals.progress.emit(min(95, percent))

                    c_id = campaign.get("id")
                    c_name = campaign.get("name")
                    c_aliases = campaign.get("aliases", [])
                    c_desc = campaign.get("description")
                    c_first_seen = self._format_date(campaign.get("first_seen"))
                    c_last_seen = self._format_date(campaign.get("last_seen"))

                    techniques = mitre_attack_data.get_techniques_used_by_campaign(c_id)
                    c_ttps = [f'{t["object"].name} ({mitre_attack_data.get_attack_id(t["object"].id)})' for t in techniques]
                    software = mitre_attack_data.get_software_used_by_campaign(c_id)
                    c_tools = [f'{s["object"].name} ({mitre_attack_data.get_attack_id(s["object"].id)})' for s in software]
                    groups = mitre_attack_data.get_groups_attributing_to_campaign(c_id)
                    apt_group_name_str = " | ".join([f'{g["object"].name} (ID: {mitre_attack_data.get_attack_id(g["object"].id)})' for g in groups])

                    if not self._passes_filters(c_name, apt_group_name_str, c_aliases, c_desc, c_last_seen, c_ttps, c_tools):
                        continue
                    
                    # A unique ID is added to every row as it's created.
                    entry = {
                        Column.UUID: uuid.uuid4().hex,
                        Column.CATEGORY: category,
                        Column.CAMPAIGN_ID: c_id,
                        Column.CAMPAIGN_NAME: c_name,
                        Column.APT_GROUP: apt_group_name_str,
                        Column.ALIASES: c_aliases,
                        Column.DESCRIPTION: c_desc,
                        Column.TTPS: c_ttps,
                        Column.TOOLS: c_tools,
                        Column.FIRST_SEEN: c_first_seen,
                        Column.LAST_SEEN: c_last_seen,
                        Column.IOCS: "" 
                    }
                    results.append(entry)
                    batch.append(entry)
                    if len(batch) >= self.batch_size:
                        self.signals.partial.emit(batch.copy())
                        batch.clear()
                
                if self._interrupted: break

            if not self._interrupted and batch: self.signals.partial.emit(batch.copy())
            self.signals.progress.emit(100)
            self.signals.finished.emit(results)
        except Exception as e:
            logging.error("Error in CampaignFetchRunnable", exc_info=True)
            error_str = f"An error occurred in the worker thread:\n{e}\n\n{traceback.format_exc()}"
            self.signals.error.emit(error_str)

    def _format_date(self, timestamp_str: Optional[str]) -> str:
        if not timestamp_str: return "N/A"
        try:
            dt = datetime.fromisoformat(str(timestamp_str).replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, TypeError):
            return "Invalid Date Format"
            
    def _passes_filters(self, c_name, apt_group, c_aliases, c_desc, c_last_seen, c_ttps, c_tools) -> bool:
        if self.search_pat:
            search_text = " ".join(filter(None, [c_name, apt_group, c_desc, " ".join(c_aliases), " ".join(c_ttps), " ".join(c_tools)]))
            if not self.search_pat.search(search_text):
                return False
        
        if self.date_filter_enabled:
            if c_last_seen == "N/A": return False
            try:
                last_seen_date = datetime.strptime(c_last_seen, "%Y-%m-%d %H:%M:%S UTC").date()
                return self.start_date <= last_seen_date <= self.end_date
            except (ValueError, TypeError):
                return False
        
        return True

# The worker operates on the UUID.
class IocFetchRunnable(QRunnable):
    """Fetches IOCs for a specific campaign from OTX."""
    def __init__(self, otx_key: str, mitre_attack_data: Any, campaign_info: dict):
        super().__init__()
        self.otx_key = otx_key
        self.mitre_attack_data = mitre_attack_data
        self.campaign_info = campaign_info
        self.uuid = campaign_info.get(Column.UUID)
        self.campaign_id = campaign_info.get(Column.CAMPAIGN_ID)
        self.campaign_name = campaign_info.get(Column.CAMPAIGN_NAME)
        self.signals = IocWorkerSignals()
        self._interrupted = False

    def interrupt(self): self._interrupted = True

    def run(self):
        if not OTX_AVAILABLE:
            self.signals.error.emit(self.uuid, "OTXv2 library not available.")
            return
        try:
            otx = OTXv2(self.otx_key)
            all_iocs_structured = []
            search_terms = {self.campaign_name}
            
            groups = self.mitre_attack_data.get_groups_attributing_to_campaign(self.campaign_id)
            for group in groups: search_terms.add(group['object'].name)
            software = self.mitre_attack_data.get_software_used_by_campaign(self.campaign_id)
            for s in software: search_terms.add(s['object'].name)
            
            for term in search_terms:
                if self._interrupted: return
                try:
                    for pulse in otx.search_pulses(query=term).get('results', []):
                        if self._interrupted: return
                        pulse_id = pulse.get('id')
                        if not pulse_id: continue
                        for indicator in otx.get_pulse_indicators(pulse_id=pulse_id, limit=20):
                            if indicator.get('indicator'):
                                ioc = self.campaign_info.copy()
                                ioc.update({
                                    "type": indicator.get('type'),
                                    "value": indicator.get('indicator'),
                                    "source_pulse_name": pulse.get('name', 'N/A')
                                })
                                all_iocs_structured.append(ioc)
                except Exception as e:
                    logging.warning(f"OTX search term '{term}' failed: {e}")
            
            if self._interrupted: return
            unique_iocs = {ioc["value"]: ioc for ioc in all_iocs_structured}
            
            self.signals.finished.emit(self.uuid,
                                       [ioc["value"] for ioc in unique_iocs.values()], 
                                       list(unique_iocs.values()))
        except Exception as e:
            if not self._interrupted:
                logging.error(f"OTX API error for campaign '{self.campaign_name}'", exc_info=True)
                self.signals.error.emit(self.uuid, f"OTX API error: {e}")

# --------------------
# Helper Utilities
# --------------------
def compile_user_pattern(text: str, use_regex: bool) -> Optional[re.Pattern]:
    if not text: return None
    pattern = text if use_regex else re.escape(text)
    return re.compile(pattern, re.IGNORECASE)

def qdate_to_date(qdate):
    return datetime.strptime(qdate.toString("yyyy-MM-dd"), "%Y-%m-%d").date()

class FullTextDialog(QDialog):
    def __init__(self, title, text, parent=None, is_html=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setGeometry(QRect(100, 100, 600, 400))
        layout = QVBoxLayout(self)
        self.text_viewer = QTextBrowser()
        self.text_viewer.setReadOnly(True)

        if is_html:
            self.text_viewer.setHtml(text)
            self.text_viewer.setOpenExternalLinks(True)
        else:
            self.text_viewer.setMarkdown(text)

        self.text_viewer.setStyleSheet("font-family: sans-serif; font-size: 10pt; line-height: 1.5;")
        layout.addWidget(self.text_viewer)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

# --------------------
# Main Application
# --------------------
class ThreatCampaignMapperApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Threat Campaign Mapper v{__version__}")
        self.setGeometry(100, 100, 1400, 800)
        self.app_icon = QIcon('icon.png')
        if not self.app_icon.isNull():
            self.setWindowIcon(self.app_icon)
        else:
            logging.warning("icon.png not found. The application will use the default system icon.")
        
        self.saved_otx_key = None
        
        self.threadpool = QThreadPool()
        self._reset_state()
        self._build_ui()
        self._load_api_key_from_keyring()

    def _reset_state(self):
        """Resets all application data to its initial state."""
        self.results_df = pd.DataFrame(columns=ALL_COLUMNS)
        self.all_results_data = []
        self.ioc_structured_list = []
        self.otx_iocs_by_uuid = {}
        self.mitre_attack_data_caches = {}
        self.ioc_workers_by_uuid = {}
        self.current_runnable = None
        logging.info("Application state has been reset.")

    def _build_ui(self):
        """Constructs the main user interface."""
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.layout = QVBoxLayout(main_widget)
        
        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch()
        about_button = QPushButton("?")
        about_button.setFixedSize(QSize(60, 24))
        about_button.clicked.connect(self._show_about_dialog)
        top_bar_layout.addWidget(about_button)
        self.layout.addLayout(top_bar_layout)
        
        self._create_control_widgets()
        self._create_status_and_progress_widgets()
        self._create_table_widget()
        self._create_export_widgets()
        
        self._toggle_otx_ui() 

    def _create_control_widgets(self):
        """Builds the top control panel with search, filters, and API keys."""
        control_layout = QVBoxLayout()
        # Category Selector
        cat_layout = QHBoxLayout()
        cat_layout.addWidget(QLabel("ATT&CK Category:"))
        self.category_selector = QComboBox()
        self.category_selector.addItems(["All"] + list(ATTACK_DATA_CONFIG.keys()))
        cat_layout.addWidget(self.category_selector)
        cat_layout.addStretch()
        control_layout.addLayout(cat_layout)
        # Search Box
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search Text:"))
        self.input_search = QLineEdit()
        search_layout.addWidget(self.input_search)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.input_search.clear)
        self.clear_button.setEnabled(False)
        self.input_search.textChanged.connect(lambda text: self.clear_button.setEnabled(bool(text)))
        search_layout.addWidget(self.clear_button)
        control_layout.addLayout(search_layout)
        # Main Buttons
        main_buttons_layout = QHBoxLayout()
        self.regex_checkbox = QCheckBox("Use Regex")
        self.search_button = QPushButton("Search Campaigns")
        self.search_button.clicked.connect(self.on_search_clicked)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.on_cancel_clicked)
        self.cancel_button.setEnabled(False)
        main_buttons_layout.addWidget(self.regex_checkbox)
        main_buttons_layout.addStretch()
        main_buttons_layout.addWidget(self.search_button)
        main_buttons_layout.addWidget(self.cancel_button)
        control_layout.addLayout(main_buttons_layout)
        # Date Filter
        date_layout = QHBoxLayout()
        self.date_filter_checkbox = QCheckBox("Enable Date Filter")
        self.date_filter_checkbox.toggled.connect(self._toggle_date_inputs)
        date_layout.addWidget(self.date_filter_checkbox)
        date_layout.addStretch()
        self.start_date = QDateEdit(calendarPopup=True, date=QDate.currentDate().addMonths(-1))
        self.end_date = QDateEdit(calendarPopup=True, date=QDate.currentDate())
        self._toggle_date_inputs(False) # Initially disabled
        date_layout.addWidget(QLabel("From:"))
        date_layout.addWidget(self.start_date)
        date_layout.addWidget(QLabel("To:"))
        date_layout.addWidget(self.end_date)
        control_layout.addLayout(date_layout)
        # OTX Controls
        otx_layout = QHBoxLayout()
        self.otx_checkbox = QCheckBox("Enable OTX IOCs Search")
        self.otx_checkbox.setEnabled(OTX_AVAILABLE)
        self.otx_checkbox.toggled.connect(self._toggle_otx_ui)
        otx_layout.addWidget(self.otx_checkbox)
        otx_layout.addWidget(QLabel("OTX API Key:"))
        self.otx_key_input = QLineEdit()
        self.otx_key_input.setEchoMode(QLineEdit.Password)
        self.otx_key_input.textChanged.connect(self._toggle_otx_ui)
        otx_layout.addWidget(self.otx_key_input, 1) # Give it stretch factor
        self.save_key_button = QPushButton("Save Key")
        self.clear_key_button = QPushButton("Clear Saved Key")
        self.save_key_button.setEnabled(False)
        self.clear_key_button.setEnabled(False) 
        if KEYRING_AVAILABLE:
            self.save_key_button.clicked.connect(self._save_api_key_to_keyring)
            self.clear_key_button.clicked.connect(self._clear_api_key_from_keyring)
        else:
            self.save_key_button.setToolTip("`keyring` library not found.")
        otx_layout.addWidget(self.save_key_button)
        otx_layout.addWidget(self.clear_key_button)
        control_layout.addLayout(otx_layout)
        
        self.layout.addLayout(control_layout)

    def _create_status_and_progress_widgets(self):
        prog_layout = QHBoxLayout()
        self.progress_bar = QProgressBar(minimum=0, maximum=100, value=0)
        prog_layout.addWidget(self.progress_bar, 3)
        self.status_label = QLabel("Idle")
        prog_layout.addWidget(self.status_label, 2)
        self.layout.addLayout(prog_layout)

    def _create_table_widget(self):
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(len(COLUMN_HEADERS))
        self.result_table.setHorizontalHeaderLabels(COLUMN_HEADERS)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setSortingEnabled(True)
        self.result_table.cellDoubleClicked.connect(self.on_cell_double_clicked)
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionsMovable(True)
        header.setStretchLastSection(True)
        self.layout.addWidget(self.result_table)

    def _create_export_widgets(self):
        bottom_layout = QVBoxLayout()
        download_layout = QHBoxLayout()
        self.download_xlsx_button = QPushButton("Export Campaigns (XLSX)")
        self.download_xlsx_button.setEnabled(False)
        self.download_xlsx_button.clicked.connect(self.download_as_xlsx)
        self.otx_export_xlsx_button = QPushButton("Export IOCs (XLSX)")
        self.otx_export_xlsx_button.clicked.connect(self.download_otx_iocs_as_xlsx)
        download_layout.addWidget(self.download_xlsx_button)
        download_layout.addWidget(self.otx_export_xlsx_button)
        download_layout.setAlignment(Qt.AlignCenter)
        bottom_layout.addLayout(download_layout)
        
        self.ioc_group_box = QGroupBox("Export Specific IOC Types (TXT)")
        self.ioc_group_box.setStyleSheet("QGroupBox { font-weight: bold; color: green}")
        self.ioc_group_box.setVisible(False)
        self.ioc_btn_layout = QHBoxLayout(self.ioc_group_box)
        self.ioc_btn_layout.addStretch()
        bottom_layout.addWidget(self.ioc_group_box)
        self.layout.addLayout(bottom_layout)
        
    def _show_about_dialog(self):
        """Displays a rich-text 'About' message box."""
        about_text = (
            f"<h3>Threat Campaign Mapper</h3>"
            f"<p><b>Version:</b>&nbsp;{__version__}</p>"
            f"<p><b>Author:</b>&nbsp;<a href='https://github.com/{__author__}'>{__author__}</a></p>"
            f"<p>This application automates the process of pulling malware campaign details from MITRE ATT&CK and gathering associated IOCs from AlienVault OTX, providing a comprehensive view for threat intelligence.</p>"
        )
        QMessageBox.about(self, "About", about_text)

    # helper method to find the visual row from a UUID.
    def _find_visual_row_by_uuid(self, uuid_to_find: str) -> Optional[int]:
        """Scans the table to find the visual row index for a given UUID."""
        if not uuid_to_find:
            return None
        for visual_row in range(self.result_table.rowCount()):
            # Check the item in the first column (where we now store the UUID)
            item = self.result_table.item(visual_row, 0)
            if item:
                stored_uuid = item.data(Qt.UserRole + 1)
                if stored_uuid == uuid_to_find:
                    return visual_row
        logging.warning(f"Could not find visual row for UUID: {uuid_to_find}")
        return None

    # --- UI State & Toggles ---
    def _toggle_ui_state(self, is_running: bool):
        self.search_button.setEnabled(not is_running)
        self.cancel_button.setEnabled(is_running)
        self.input_search.setEnabled(not is_running)
        self.date_filter_checkbox.setEnabled(not is_running)
        self._toggle_date_inputs(self.date_filter_checkbox.isChecked() and not is_running)
        self.category_selector.setEnabled(not is_running)

    def _toggle_date_inputs(self, checked: bool):
        self.start_date.setEnabled(checked)
        self.end_date.setEnabled(checked)
    
    def _toggle_otx_ui(self):
        is_otx_enabled = self.otx_checkbox.isChecked()
        current_key_text = self.otx_key_input.text()
        api_key_present = bool(current_key_text)
        
        if not is_otx_enabled and current_key_text and (current_key_text != self.saved_otx_key):
            self.otx_key_input.clear()
            current_key_text = ""
            api_key_present = False
        
        self.otx_key_input.setEnabled(is_otx_enabled)
        
        is_new_key = current_key_text != self.saved_otx_key
        self.save_key_button.setEnabled(is_otx_enabled and api_key_present and is_new_key)
        
        should_show_iocs = is_otx_enabled and api_key_present
        logical_ioc_col = COLUMN_HEADERS.index(Column.IOCS)
        self.result_table.setColumnHidden(logical_ioc_col, not should_show_iocs)
        self.otx_export_xlsx_button.setEnabled(should_show_iocs and bool(self.otx_iocs_by_uuid))
        self._refresh_ioc_buttons_ui()

    # --- Keyring & API Key Management ---
    def _load_api_key_from_keyring(self):
        if not KEYRING_AVAILABLE:
            logging.warning("Keyring library not available. Secure API key storage is disabled.")
            return
        try:
            api_key = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
            if api_key:
                self.otx_key_input.blockSignals(True)
                self.otx_checkbox.blockSignals(True)

                self.otx_key_input.setText(api_key)
                self.otx_checkbox.setChecked(True)
                self.saved_otx_key = api_key
                self.clear_key_button.setEnabled(True)

                self.otx_key_input.blockSignals(False)
                self.otx_checkbox.blockSignals(False)
                
                logging.info("Successfully loaded OTX API key from secure keyring.")
                self._toggle_otx_ui()
            else:
                self.clear_key_button.setEnabled(False)
                logging.info("No OTX API key found in keyring.")

        except Exception as e:
            logging.error("Failed to load API key from keyring.", exc_info=True)
            QMessageBox.warning(self, "Keyring Error", f"Could not load API key from keyring:\n{e}")

    def _save_api_key_to_keyring(self):
        api_key = self.otx_key_input.text()
        if not api_key:
            QMessageBox.warning(self, "No API Key", "Please enter an API key to save.")
            return
        try:
            keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, api_key)
            self.saved_otx_key = api_key
            self.clear_key_button.setEnabled(True)
            self._toggle_otx_ui()
            logging.info("Successfully saved OTX API key to secure keyring.")
            QMessageBox.information(self, "Success", "API key has been saved securely for future sessions.")
        except Exception as e:
            logging.error("Failed to save API key to keyring.", exc_info=True)
            QMessageBox.critical(self, "Keyring Error", f"Could not save API key:\n{e}")

    def _clear_api_key_from_keyring(self):
        try:
            if keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME):
                keyring.delete_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
                self.saved_otx_key = None
                self.clear_key_button.setEnabled(False)
                self._toggle_otx_ui()
                logging.info("Cleared OTX API key from secure keyring.")
                QMessageBox.information(self, "Success", "Saved API key has been cleared.")
            else:
                QMessageBox.information(self, "Not Found", "No saved API key to clear.")
        except Exception as e:
            logging.error("Failed to clear API key from keyring.", exc_info=True)
            QMessageBox.critical(self, "Keyring Error", f"Could not clear API key:\n{e}")

    # --- Data Fetching and File Management ---
    def _manage_mitre_data_file(self, attack_category: str) -> Optional[str]:
        config = ATTACK_DATA_CONFIG.get(attack_category)
        if not config:
            QMessageBox.critical(self, "Config Error", f"Invalid ATT&CK category: {attack_category}")
            return None
        
        cache_file_name = config["file"]
        if os.path.exists(cache_file_name):
            file_age = time.time() - os.path.getmtime(cache_file_name)
            if file_age < CACHE_DURATION_SECONDS:
                logging.info(f"Using fresh cached data file for {attack_category}.")
                return cache_file_name
            else:
                logging.info(f"Cached data for {attack_category} is stale. Re-downloading...")
                os.remove(cache_file_name)
        
        self.status_label.setText(f"Downloading {attack_category} data...")
        QApplication.processEvents()
        try:
            response = requests.get(config["url"])
            response.raise_for_status()
            with open(cache_file_name, "w", encoding="utf-8") as f:
                json.dump(response.json(), f)
            logging.info(f"Successfully downloaded and saved {attack_category} data.")
            return cache_file_name
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download MITRE data for {attack_category}", exc_info=True)
            QMessageBox.critical(self, "Download Error", f"Failed to download MITRE ATT&CK data for {attack_category}:\n{e}")
            return None
        except IOError as e:
            logging.error(f"Failed to save data file for {attack_category}", exc_info=True)
            QMessageBox.critical(self, "File Error", f"Failed to save data file for {attack_category}:\n{e}")
            return None
        
    def on_search_clicked(self):
        self._reset_ui_for_search()
        try:
            search_pat = compile_user_pattern(self.input_search.text().strip(), self.regex_checkbox.isChecked())
            date_filter_enabled = self.date_filter_checkbox.isChecked()
            start_date = qdate_to_date(self.start_date.date()) if date_filter_enabled else None
            end_date = qdate_to_date(self.end_date.date()) if date_filter_enabled else None
            selected_cat = self.category_selector.currentText()
            cats_to_search = list(ATTACK_DATA_CONFIG.keys()) if selected_cat == "All" else [selected_cat]
            
            self.mitre_attack_data_caches = {}
            for cat in cats_to_search:
                cache_file = self._manage_mitre_data_file(cat)
                if not cache_file:
                     self._toggle_ui_state(False)
                     return
                self.mitre_attack_data_caches[cat] = MitreAttackData(cache_file)
            
            self.current_runnable = CampaignFetchRunnable(search_pat, date_filter_enabled, start_date, end_date, self.mitre_attack_data_caches)
            self.current_runnable.signals.progress.connect(self.progress_bar.setValue)
            self.current_runnable.signals.partial.connect(self.on_partial_results)
            self.current_runnable.signals.finished.connect(self.on_runnable_finished)
            self.current_runnable.signals.error.connect(self.on_runnable_error)
            self.threadpool.start(self.current_runnable)
        except re.error as e:
            QMessageBox.critical(self, "Invalid Regex", f"Your search pattern is an invalid regular expression:\n{e}")
            self._toggle_ui_state(False)
        except Exception as e:
            logging.critical("Unexpected error during search setup", exc_info=True)
            QMessageBox.critical(self, "Search Error", f"An unexpected error occurred: {e}")
            self._toggle_ui_state(False)

    # Interaction is initiated by the unique row UUID.
    def on_get_iocs_clicked(self, row_uuid: str):
        df_slice = self.results_df[self.results_df[Column.UUID] == row_uuid]
        if df_slice.empty:
            logging.error(f"on_get_iocs_clicked: Could not find row with UUID {row_uuid}")
            return
        
        campaign_info = df_slice.iloc[0].to_dict()
        category = campaign_info.get(Column.CATEGORY)

        if row_uuid in self.ioc_workers_by_uuid:
            logging.warning(f"IOC search already running for UUID {row_uuid}")
            return
        
        mitre_data_for_ioc = self.mitre_attack_data_caches.get(category)
        if not mitre_data_for_ioc:
            QMessageBox.critical(self, "Internal Error", f"Could not find ATT&CK data for category '{category}'.")
            return

        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet("color: red;")
        cancel_button.clicked.connect(lambda: self.on_cancel_ioc_clicked(row_uuid))
        
        # Find the correct VISUAL row to update, not the logical one.
        visual_row = self._find_visual_row_by_uuid(row_uuid)
        if visual_row is not None:
            logical_col_idx = COLUMN_HEADERS.index(Column.IOCS)
            self.result_table.setCellWidget(visual_row, logical_col_idx, cancel_button)
            self.result_table.setItem(visual_row, logical_col_idx, QTableWidgetItem("Fetching..."))

        runnable = IocFetchRunnable(self.otx_key_input.text().strip(), mitre_data_for_ioc, campaign_info)
        runnable.signals.finished.connect(self.on_ioc_fetch_finished)
        runnable.signals.error.connect(self.on_ioc_fetch_error)
        
        self.ioc_workers_by_uuid[row_uuid] = runnable
        self.threadpool.start(runnable)

    # --- Worker Callbacks & Slots ---
    @Slot(list)
    def on_partial_results(self, partial_results: list):
        if not partial_results: return
        new_data_df = pd.DataFrame(partial_results)
        self.results_df = pd.concat([self.results_df, new_data_df], ignore_index=True)
        self.all_results_data.extend(partial_results)
        self._update_display()
        self.status_label.setText(f"Found {len(self.all_results_data)} campaigns so far...")

    @Slot(list)
    def on_runnable_finished(self, final_results: list):
        self.results_df = pd.DataFrame(final_results) if final_results else pd.DataFrame(columns=ALL_COLUMNS)
        self.all_results_data = final_results
        self._update_display()
        self.status_label.setText(f"Search complete. Found {len(final_results)} campaigns.")
        self._toggle_ui_state(False)
        self.current_runnable = None
        if not self.results_df.empty:
            self.download_xlsx_button.setEnabled(True)

    @Slot(str)
    def on_runnable_error(self, error_message: str):
        self._reset_ui_after_search()
        QMessageBox.critical(self, "Worker Error", error_message)
        self.status_label.setText("Error")

    def on_cancel_clicked(self):
        if self.current_runnable:
            self.current_runnable.interrupt()
            self.current_runnable = None
            self.status_label.setText("Search canceled.")
            self._toggle_ui_state(False)

    # All callbacks use the UUID to find and update the correct row.
    @Slot(str)
    def on_cancel_ioc_clicked(self, row_uuid: str):
        if row_uuid in self.ioc_workers_by_uuid:
            worker = self.ioc_workers_by_uuid.pop(row_uuid)
            worker.interrupt()
            logging.info(f"Cancelled IOC fetch for UUID {row_uuid}")
            
            # Find the correct VISUAL row to update.
            df_slice = self.results_df[self.results_df[Column.UUID] == row_uuid]
            visual_row = self._find_visual_row_by_uuid(row_uuid)
            if visual_row is not None and not df_slice.empty:
                self._populate_table_row(visual_row, df_slice.iloc[0])

    @Slot(str, list, list)
    def on_ioc_fetch_finished(self, row_uuid: str, iocs_str_list: list, iocs_structured_list: list):
        if row_uuid in self.ioc_workers_by_uuid:
            self.ioc_workers_by_uuid.pop(row_uuid)

        self.otx_iocs_by_uuid[row_uuid] = iocs_structured_list
        self.ioc_structured_list.extend(iocs_structured_list)
        self.ioc_structured_list = list({ioc['value']: ioc for ioc in self.ioc_structured_list}.values())
        
        self.otx_export_xlsx_button.setEnabled(True)
        self._refresh_ioc_buttons_ui()
        
        # Find the correct VISUAL row to update.
        df_slice = self.results_df[self.results_df[Column.UUID] == row_uuid]
        visual_row = self._find_visual_row_by_uuid(row_uuid)
        if visual_row is not None and not df_slice.empty:
            self._populate_table_row(visual_row, df_slice.iloc[0])

    @Slot(str, str)
    def on_ioc_fetch_error(self, row_uuid: str, message: str):
        campaign_name = "Unknown"
        # Find the correct VISUAL row to update.
        df_slice = self.results_df[self.results_df[Column.UUID] == row_uuid]
        visual_row = self._find_visual_row_by_uuid(row_uuid)

        if visual_row is not None and not df_slice.empty:
            campaign_name = df_slice.iloc[0].get(Column.CAMPAIGN_NAME, "Unknown")
            if row_uuid in self.ioc_workers_by_uuid:
                self.ioc_workers_by_uuid.pop(row_uuid)
            self._populate_table_row(visual_row, df_slice.iloc[0])

        QMessageBox.critical(self, "OTX Fetch Error", f"Failed to retrieve IOCs for '{campaign_name}'.\nReason: {message}")

    # --- UI Update and Display Logic ---
    def _reset_ui_for_search(self):
        """Clears results and prepares UI for a new search."""
        for worker in self.ioc_workers_by_uuid.values(): worker.interrupt()
        self.threadpool.clear()
        self._reset_state()
        self.result_table.setSortingEnabled(False)
        self.result_table.clearContents()
        self.result_table.setRowCount(0)
        self.result_table.setSortingEnabled(True)
        self.download_xlsx_button.setEnabled(False)
        self.otx_export_xlsx_button.setEnabled(False)
        self._refresh_ioc_buttons_ui()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting search...")
        self._toggle_ui_state(True)
        QApplication.processEvents()
        
    def _reset_ui_after_search(self):
        """Resets UI controls after a search is finished or cancelled."""
        self._toggle_ui_state(False)
        self.progress_bar.setValue(0)
        self.current_runnable = None
        
    def _update_display(self):
        """Updates the entire QTableWidget based on the current results_df."""
        self.result_table.setSortingEnabled(False)
        self.result_table.setRowCount(len(self.results_df))
        
        for logical_row_idx, row_data in self.results_df.iterrows():
            self._populate_table_row(logical_row_idx, row_data)
        
        logical_id_col = COLUMN_HEADERS.index(Column.CAMPAIGN_ID)
        self.result_table.setColumnHidden(logical_id_col, True)
        self._toggle_otx_ui()
        self.result_table.resizeColumnsToContents()
        self.result_table.setSortingEnabled(True)
    
    def _populate_table_row(self, logical_row_idx: int, row_data: pd.Series):
        """Populates a single row in the results table at a specific LOGICAL position."""
        for logical_col_idx, col_name in enumerate(COLUMN_HEADERS):
            if col_name == Column.IOCS:
                self._populate_ioc_cell(logical_row_idx, logical_col_idx, row_data)
                continue
            
            cell_data = row_data.get(col_name)
            full_content = ""
            
            if isinstance(cell_data, list):
                full_content = "\n".join([f"* {item}" for item in cell_data])
            else:
                full_content = str(cell_data) if cell_data is not None else ""
                if col_name == Column.APT_GROUP and full_content:
                    groups = [group.strip() for group in full_content.split('|')]
                    full_content = "\n".join([f"* {group}" for group in groups])

            display_text = full_content.replace('\n', ' ').replace('* ', '')
            if len(display_text) > 100:
                display_text = display_text[:97] + "..."
            
            item = QTableWidgetItem(display_text)
            item.setData(Qt.UserRole, full_content)

            # Attach the UUID to the item in the first column.
            # This allows us to find the row's visual position later.
            if logical_col_idx == 0:
                item.setData(Qt.UserRole + 1, row_data.get(Column.UUID))

            self.result_table.setItem(logical_row_idx, logical_col_idx, item)

    def _populate_ioc_cell(self, logical_row: int, logical_col: int, row_data: pd.Series):
        """Handles the special logic for a cell based on its LOGICAL position."""
        row_uuid = row_data.get(Column.UUID)
        if not row_uuid: return # Should never happen

        if row_uuid in self.ioc_workers_by_uuid:
            cancel_button = QPushButton("Cancel")
            cancel_button.setStyleSheet("color: red;")
            cancel_button.clicked.connect(lambda: self.on_cancel_ioc_clicked(row_uuid))
            self.result_table.setCellWidget(logical_row, logical_col, cancel_button)
            self.result_table.setItem(logical_row, logical_col, QTableWidgetItem("Fetching..."))
            return
        elif row_uuid in self.otx_iocs_by_uuid:
            iocs_structured = self.otx_iocs_by_uuid[row_uuid]
            count = len(iocs_structured)
            display_text = f"{count} IOCs found" if count > 0 else "No IOCs found"
            
            detailed_text_parts = [
                f"**Type:** `{ioc['type'].upper()}`\n\n**Value:** `{ioc['value']}`\n\n**Source:** *{ioc['source_pulse_name']}*"
                for ioc in iocs_structured
            ]
            detailed_text = "\n\n---\n\n".join(detailed_text_parts)

            item = QTableWidgetItem(display_text)
            item.setData(Qt.UserRole, detailed_text)
            item.setTextAlignment(Qt.AlignCenter)
            item.setForeground(Qt.GlobalColor.darkGreen)
            self.result_table.setCellWidget(logical_row, logical_col, None)
            self.result_table.setItem(logical_row, logical_col, item)
        else:
            button = QPushButton("Get IOCs")
            button.setStyleSheet("color: #d38b16;")
            # The lambda now captures the foolproof UUID.
            button.clicked.connect(lambda checked, u=row_uuid: self.on_get_iocs_clicked(u))
            self.result_table.setCellWidget(logical_row, logical_col, button)
            self.result_table.setItem(logical_row, logical_col, QTableWidgetItem(""))

    @Slot(int, int)
    def on_cell_double_clicked(self, row, column):
        item = self.result_table.item(row, column)
        if not item: return
        
        full_content = item.data(Qt.UserRole)
        column_name = COLUMN_HEADERS[column]

        if full_content:
            title = f"Full Content: {column_name}"
            is_html = False
            
            if column_name == Column.DESCRIPTION:
                processed_content = str(full_content)
                bracket_pattern = re.compile(r'\[(.*?)\]')
                highlight_color = "#c0392b" 
                processed_content = bracket_pattern.sub(
                    rf'<b style="color:{highlight_color};">\1</b>', 
                    processed_content
                )
                url_pattern = re.compile(r'https?://[^\s<>"\'()]+')
                processed_content = url_pattern.sub(
                    r'<a href="\g<0>">\g<0></a>', 
                    processed_content
                )
                full_content = processed_content.replace('\n', '<br>')
                is_html = True

            FullTextDialog(title, str(full_content), self, is_html=is_html).exec()
            
    def _refresh_ioc_buttons_ui(self):
        while self.ioc_btn_layout.count() > 1:
            item = self.ioc_btn_layout.takeAt(0)
            if item and item.widget(): item.widget().deleteLater()

        classified = defaultdict(list)
        for ioc in self.ioc_structured_list:
            if ioc.get("type"): classified[ioc["type"]].append(ioc["value"])

        if not classified:
            self.ioc_group_box.setVisible(False)
            return

        self.ioc_group_box.setVisible(True)
        for ioc_type in sorted(classified.keys()):
            button = QPushButton(ioc_type.capitalize())
            button.clicked.connect(lambda checked, t=ioc_type: self.export_iocs_by_type(t, classified[t]))
            self.ioc_btn_layout.insertWidget(self.ioc_btn_layout.count() - 1, button)

    # --- Exporting Logic ---
    def prompt_overwrite(self, path: str) -> bool:
        if not os.path.exists(path): return True
        resp = QMessageBox.question(self, "Overwrite File?", f"The file '{os.path.basename(path)}' already exists. Overwrite?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        return resp == QMessageBox.Yes
        
    def _get_save_path(self, title: str, suggestion: str, file_filter: str) -> Optional[str]:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path, _ = QFileDialog.getSaveFileName(self, title, f"{timestamp}_{suggestion}", file_filter)
        if path and not self.prompt_overwrite(path): return None
        return path

    def download_as_xlsx(self):
        if self.results_df.empty:
            QMessageBox.information(self, "No Data", "There is no data to save.")
            return
        path = self._get_save_path("Save Campaigns XLSX", "all_campaigns.xlsx", "Excel Files (*.xlsx)")
        if not path: return
        
        try:
            # Don't export our internal UUID column
            export_df = self.results_df[COLUMN_HEADERS_FOR_EXPORT_XLSX].copy()
            for col in [Column.ALIASES, Column.TTPS, Column.TOOLS]:
                export_df[col] = export_df[col].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
            export_df.to_excel(path, index=False, engine='openpyxl')
            QMessageBox.information(self, "Success", f"Results saved to:\n{path}")
        except Exception as e:
            logging.error("Failed to save campaign XLSX file", exc_info=True)
            QMessageBox.critical(self, "Save Error", f"Failed to save XLSX file:\n{e}")

    def download_otx_iocs_as_xlsx(self):
        if not self.ioc_structured_list:
            QMessageBox.information(self, "No Data", "No IOCs were found to export.")
            return
        path = self._get_save_path("Save IOCs XLSX", "all_iocs.xlsx", "Excel Files (*.xlsx)")
        if not path: return
        
        try:
            ioc_df = pd.DataFrame(self.ioc_structured_list)
            # Define order, excluding our internal UUID
            column_order = [
                Column.CATEGORY, Column.CAMPAIGN_ID, Column.CAMPAIGN_NAME, Column.ALIASES, 
                Column.APT_GROUP, Column.FIRST_SEEN, Column.LAST_SEEN, 
                "value", "type", "source_pulse_name"
            ]
            # Filter for columns that actually exist in the dataframe
            final_columns = [col for col in column_order if col in ioc_df.columns]
            
            ioc_df = ioc_df.reindex(columns=final_columns).rename(columns={
                "value": "IOC Value", "type": "IOC Type", "source_pulse_name": "Source Pulse Name"})
            
            if Column.ALIASES in ioc_df.columns:
                ioc_df[Column.ALIASES] = ioc_df[Column.ALIASES].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
            
            ioc_df.to_excel(path, index=False, engine='openpyxl')
            QMessageBox.information(self, "Success", f"IOCs saved to:\n{path}")
        except Exception as e:
            logging.error("Failed to save IOCs XLSX file", exc_info=True)
            QMessageBox.critical(self, "Save Error", f"Failed to save IOCs file:\n{e}")

    def export_iocs_by_type(self, ioc_type: str, iocs: list):
        path = self._get_save_path(f"Save {ioc_type} IOCs", f"{ioc_type}_iocs.txt", "Text Files (*.txt)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: f.write('\n'.join(iocs))
            QMessageBox.information(self, "Success", f"Data saved to:\n{path}")
        except Exception as e:
            logging.error(f"Failed to save {ioc_type} TXT file", exc_info=True)
            QMessageBox.critical(self, "Save Error", f"Failed to save TXT file:\n{e}")

# --------------------
# Main Execution
# --------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler("threat_campaign_mapper.log", mode='w'),
            logging.StreamHandler()
        ]
    )

    if not OTX_AVAILABLE:
        logging.warning("OTXv2 library not found. OTX features will be disabled.")
    if not KEYRING_AVAILABLE:
        logging.warning("keyring library not found. Secure API key storage is disabled.")
        
    app = QApplication(sys.argv)
    win = ThreatCampaignMapperApp()
    win.show()
    sys.exit(app.exec())