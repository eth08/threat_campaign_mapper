# Threat Campaign Mapper

![Python CI/CD](https://github.com/eth08/threat_campaign_mapper/actions/workflows/main.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-0.5.1-orange)

A Python script that automates the process of pulling malware campaign details from MITRE ATT&CK and gathering associated IOCs from AlienVault OTX, providing a comprehensive view for threat intelligence.

## Features

* **Asynchronous Data Fetching**: Uses `QThreadPool` and `QRunnable` to fetch and filter campaign data in a background thread, preventing the UI from freezing.
* **Progressive UI Updates**: Streams search results progressively to the UI as they are found, providing a responsive user experience.
* **Integrated OTX IOC Search**: Optionally fetches Indicators of Compromise (IOCs) from AlienVault OTX (requires an API key) for each campaign.
* **Secure API Key Storage**: Uses the `keyring` library to securely store your OTX API key, so you don't have to re-enter it.
* **Flexible Search & Filtering**: Search campaigns by text and filter results by a specific date range.
* **Data Export**: Export the results to a structured XLSX file or specific IOC types to a text file.
* **Cached Data**: Downloads and caches MITRE ATT&CK data files locally for 24 hours to reduce download times on subsequent searches.

## Installation

To set up the application, you'll first need to install the required Python packages. It's recommended to use a virtual environment.

1.  **Clone the repository (or download the script):**
    ```bash
    git clone [https://github.com/eth08/threat_campaign_mapper.git](https://github.com/eth08/threat_campaign_mapper.git)
    cd threat_campaign_mapper
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    * On Windows: `venv\Scripts\activate`
    * On macOS/Linux: `source venv/bin/activate`

4.  **Install dependencies from `requirements.txt`:**
    
    Install the packages:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: The `OTXv2` and `keyring` libraries are optional. The application will still function without them, but the IOC search and API key storage features will be disabled.*

## Usage

1.  **Run the application:**
    ```bash
    python threat_campaign_mapper.py
    ```

2.  **Using the UI:**
    * Enter search terms in the "Search Text" box.
    * Optionally, enable "Use Regex" for more advanced searches.
    * Set date filters to narrow down results based on the "Last Seen" date.
    * Check "Enable OTX IOCs Search" to retrieve IOCs for each campaign. If it's your first time, you will be prompted to enter your OTX API key, which can be saved securely using the "Save Key" button.
    * Click "Search Campaigns" to begin the search.

## Contributing

Feel free to open issues or submit pull requests to improve the application.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Credits

* **MITRE ATT&CK®**: The primary data source for campaigns and threat information.
* **AlienVault OTX**: For providing a public API to retrieve threat intelligence and IOCs.
* **PySide6**: The framework used for building the GUI.
* **Python Libraries**:
    * `mitreattack-stix`
    * `requests`
    * `pandas`
    * `openpyxl`
    * `OTXv2`
    * `keyring`
