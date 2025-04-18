# Intrusion Detection System (IDS) Project

Welcome to the Intrusion Detection System (IDS) project! This application is designed to monitor network traffic, detect potential security threats (e.g., SYN floods, port scans), and log alerts in real-time. The project is built using a combination of Python for packet sniffing, Node.js/Express for the middleware API, and React for the frontend interface.

## Overview

This IDS leverages the Scapy library to analyze network packets and identify malicious activities. The frontend provides a control panel to start/stop the IDS and view logs, while the middleware facilitates communication between the Python backend and the React frontend. The project is modular, with separate directories for the client, engine, middleware, and shared components.

## File Structure

```

PROJECT_ROOT/
├── .venv/                  # Virtual environment for Python dependencies
├── .vscode/                # VS Code configuration files
├── client/                 # React frontend application
│ ├── node_modules/         # Node.js dependencies for the client
│ ├── public/               # Static assets (e.g., index.html)
│ ├── src/                  # React source files (e.g., App.jsx, App.css)
│ ├── package.json          # Client-side npm configuration
│ ├── package-lock.json     # Lock file for client dependencies
│ ├── tailwind.config.js    # Tailwind CSS configuration (optional)
│ ├── postcss.config.js     # PostCSS configuration (optional)
│ ├── vite.config.js        # Vite configuration
│ └── ...                   # Other client files
├── engine/                 # Python scripts for packet sniffing and rule logic
│ ├── ids.py                # Main IDS logic
│ ├── rules/                # Detection rule definitions (e.g., syn_scan.py)
│ └── ...                   # Other engine files
├── logs/                   # Directory for storing alert logs (e.g., alerts.json)
├── middleware/             # Node.js/Express API server
│ ├── node_modules/         # Node.js dependencies for the middleware
│ ├── index.js              # Main middleware script
│ ├── package.json          # Middleware npm configuration
│ ├── package-lock.json     # Lock file for middleware dependencies
│ └── ...                   # Other middleware files
├── shared/                 # Shared resources
├── .gitignore              # Git ignore file
├── package-lock.json       # Project root lock file
├── package.json            # Project root npm configuration
├── README.md               # This file
└── test.py                 # Example Python script (for testing)

```

## Prerequisites

-   **Node.js** (v14.x or later recommended)
-   **npm** (comes with Node.js)
-   **Python** (v3.8 or later)
-   **Git** (for version control)
-   **Npcap** (or WinPcap on Windows) for Scapy packet sniffing

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/GitShivamNauriyal/Real-Time-Intrusion-Detection-System.git
cd PROJECT_ROOT
```

### 2. Set Up Python Virtual Environment

-   Create a virtual environment in the project root:
    ```bash
    python -m venv .venv
    ```
-   Activate the virtual environment:
    -   On Windows:
        ```bash
        .venv\Scripts\activate
        ```
    -   On macOS/Linux:
        ```bash
        source .venv/bin/activate
        ```
-   Install Python dependencies:
    ```bash
    pip install scapy
    ```

### 3. Install Node.js Dependencies

-   **Client Side:**

    -   Navigate to the `client/` directory:
        ```bash
        cd client
        ```
    -   Install client dependencies:
        ```bash
        npm install
        ```
    -   (Optional) Install Tailwind CSS and related tools if using Tailwind:
        ```bash
        npm install -D tailwindcss postcss autoprefixer
        npx tailwindcss init -p
        ```

-   **Middleware Side:**
    -   Navigate to the `middleware/` directory:
        ```bash
        cd ../middleware
        ```
    -   Install middleware dependencies:
        ```bash
        npm install
        ```

### 4. Configure the Project

-   Ensure the `logs/` directory exists and is writable (create it manually if needed):
    ```bash
    mkdir logs
    ```
-   Update paths in `middleware/index.js` and `engine/ids.py` if the virtual environment or script locations differ (e.g., adjust `pythonPath` in middleware).
-   Install Npcap (download from [Npcap website](https://nmap.org/npcap/) and follow installation instructions) for packet sniffing on Windows.

### 5. Run the Project

-   **Activate the Python Virtual Environment:**
    -   Run `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (macOS/Linux) in the project root.
-   **Start the Middleware Server:**
    -   Navigate to `middleware/`:
        ```bash
        cd middleware
        ```
    -   Run the server:
        ```bash
        node index.js
        ```
    -   Ensure it listens on `http://localhost:3000`.
-   **Start the Client Application:**
    -   Navigate to `client/`:
        ```bash
        cd ../client
        ```
    -   Start the React app:
        ```bash
        npm run dev
        ```
    -   Open `http://localhost:5173` in your browser to access the IDS control panel.

### 6. Test the IDS

-   Click "Start IDS" to begin packet sniffing. Generate traffic (e.g., using `nmap` or normal network activity) to trigger alerts.
-   Check the "Alerts & Logs" section for logged events.
-   Click "Stop IDS" to halt the process.

## Troubleshooting

-   **Tailwind CSS Not Applying:** Ensure `src/index.css` includes `@tailwind` directives and is imported in `src/main.jsx`. Verify `tailwind.config.js` `content` paths.
-   **Python Process Fails:** Confirm Npcap is installed and the virtual environment is active with Scapy.
-   **Middleware Errors:** Check console output for `ENOENT` or other errors; adjust `pythonPath` in `middleware/index.js` if needed.

## Contributing

Feel free to fork this repository, submit issues, or create pull requests to enhance the IDS functionality or documentation.

## Contact

For questions or support, contact shivamnauriyal1224@gmail.com
