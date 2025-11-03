# Suricata Rule Browser

A modern web-based browser for Suricata IDS/IPS rules with powerful search, filtering, and sorting capabilities.

## Quick Start

Get up and running in 3 simple steps:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
python run.py

# 3. Open your browser
# Navigate to http://localhost:8000
```

The application comes with 15 sample rules to test immediately!

## Features

- **Browse Rules**: View all Suricata rules in a clean, organized interface
- **Search**: Full-text search across rule messages, SIDs, and tags
- **Filter**: Filter by action, protocol, classification type, priority, and source
- **Sort**: Sort rules by SID, priority, or message
- **Detailed View**: Click any rule to see complete details including metadata and references
- **Real-time Stats**: Dashboard showing rule statistics and distributions
- **RESTful API**: Well-documented API endpoints (v1) for programmatic access
- **Sample Data**: 15 example rules included in `data/rules/example.rules`
- **Rule Downloads**: Download rules from ET Open, Stamus Networks, and other sources
- **Smart Caching**: Automatic caching to avoid unnecessary downloads
- **Source Tracking**: Each rule is tagged with its source for easy filtering

## Advanced Search

The application provides two search bars with powerful query syntax:

### Search Bars

1. **Standard Search**: Searches in message, SID, and tags
2. **Raw Text Search**: Searches in the complete raw rule text

Both search bars are combined with **AND** logic.

### Query Syntax

- **Space-separated terms** (OR logic): `malware trojan` → matches rules with "malware" OR "trojan"
- **Quoted phrases**: `"ET MALWARE"` → matches exact phrase
- **Negation** with `!`: `!malware` → excludes rules containing "malware"
- **Escaped negation**: `\!important` → searches for literal "!important"

### Examples

```
alert drop             → "alert" OR "drop"
"ET MALWARE"           → exact phrase "ET MALWARE"
!malware !trojan       → NOT "malware" AND NOT "trojan"
alert !malware         → "alert" AND NOT "malware"
pcre !"sid:2000"       → "pcre" AND NOT exact phrase "sid:2000"
```

### Combined Search

Standard: `alert drop` + Raw Text: `pcre:` → matches rules with ("alert" OR "drop") in message/SID/tags **AND** "pcre:"
in raw text.

The applied search logic is displayed below the search bars for clarity.

## Project Structure

```
suricata-rule-browser/
├── backend/
│   └── app/
│       ├── api/            # API endpoints
│       │   └── rules.py    # Rules API
│       ├── models/         # Data models
│       │   └── rule.py     # Suricata rule models
│       ├── parsers/        # Rule parsers
│       │   └── suricata_parser.py
│       ├── static/         # Static files
│       │   ├── css/
│       │   │   └── style.css
│       │   └── js/
│       │       └── app.js
│       ├── templates/      # Jinja2 templates
│       │   └── index.html
│       └── main.py         # FastAPI application
├── data/
│   └── rules/             # Place your .rules files here
├── requirements.txt
└── README.md
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/suricata-rule-browser.git
cd suricata-rule-browser
```

2. Create a virtual environment (recommended):

```bash
python -m venv venv
```

3. Activate the virtual environment:

**Windows PowerShell:**

```powershell
# If you get an execution policy error, run this first:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Then activate:
.\venv\Scripts\Activate.ps1

# Alternative (works without policy change):
.\venv\Scripts\activate.bat
```

**Windows Command Prompt:**

```cmd
venv\Scripts\activate.bat
```

**Linux/Mac:**

```bash
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Configure rule sources (optional):
    - Sample rules are already included in `data/rules/example.rules`
    - Edit `rules.yaml` to enable/disable rule sources
    - Professional rule sets are automatically downloaded on startup
    - See the Configuration section below for details

## Usage

### Starting the Server

**Option A - Using the startup script (Recommended):**

```bash
python run.py
```

**Option B - Using uvicorn directly:**

```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The application will be available at:

- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Alternative API Docs**: http://localhost:8000/redoc

### What You Can Do

#### Browse Sample Rules

The application includes 15 sample Suricata rules to help you get started immediately.

#### Search and Filter

- Use the search box to find rules by message, SID, or tags
- Filter by action (alert, drop, reject, pass)
- Filter by protocol (tcp, udp, icmp, http, tls, dns)
- Filter by classification type
- Filter by priority level

#### Sort Rules

- Sort by SID (signature ID)
- Sort by priority
- Sort by message
- Choose ascending or descending order

#### View Details

- Click any rule card to see complete details
- View metadata, references, and the full raw rule
- See network information (source/destination)

### API Endpoints

All API endpoints are prefixed with `/api/v1`:

- `GET /api/v1/rules` - List rules with filtering and pagination
    - Query parameters: `search`, `action`, `protocol`, `classtype`, `priority`, `sid`, `sort_by`, `sort_order`, `page`,
      `page_size`
- `GET /api/v1/rules/{sid}` - Get a specific rule by SID
- `GET /api/v1/stats` - Get statistics about the rules database
- `POST /api/v1/reload` - Reload rules from disk

### Testing the API

```bash
# Get all rules
curl http://localhost:8000/api/v1/rules

# Search for SQL injection rules
curl "http://localhost:8000/api/v1/rules?search=sql"

# Filter by action and protocol
curl "http://localhost:8000/api/v1/rules?action=alert&protocol=tcp"

# Get a specific rule by SID
curl http://localhost:8000/api/v1/rules/2000001

# Get statistics
curl http://localhost:8000/api/v1/stats

# Reload rules from disk
curl -X POST http://localhost:8000/api/v1/reload
```

## Configuration

The application uses a `rules.yaml` file to configure rule sources. Rules are automatically downloaded and loaded on
startup.

### Rule Sources Configuration

Edit `rules.yaml` to configure rule sources. The application supports three types of sources:

#### 1. URL Sources (Downloaded Automatically)

```yaml
sources:
  - name: et-open
    type: url
    description: Emerging Threats Open Ruleset
    url: https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz
    file_type: tar.gz
    cache_hours: 24
    enabled: true
```

**Features:**

- Automatically downloaded on startup
- Smart caching (default: 24 hours)
- Supports `tar.gz`, `zip`, and plain `.rules` files
- Set `enabled: false` to skip a source

#### 2. Local Directory Sources

```yaml
sources:
  - name: custom-local
    type: directory
    description: Custom local rules
    path: /path/to/custom/rules
    enabled: true
    exclude_subdirs: false  # Set to true to only load files in the directory itself
```

#### 3. Local File Sources

```yaml
sources:
  - name: my-rules
    type: file
    description: My custom rules file
    path: /path/to/my-rules.rules
    enabled: true
```

### Built-in Sources

The default configuration includes:

- **ET Open** (Emerging Threats Open): Community ruleset (enabled by default)
- **Stamus Networks**: Free SOC-grade ruleset (disabled by default)
- **Local**: Example rules in `data/rules/` directory

### How It Works

1. **Automatic Download**: When you start the server, enabled URL sources are downloaded automatically
2. **Smart Caching**: Downloads are cached (default 24 hours) to avoid unnecessary bandwidth
3. **Source Tracking**: Each rule is tagged with its source name for filtering
4. **Flexible Configuration**: Mix URL downloads with local files and directories

### Adding Your Own Rules

**Option 1: Add to rules.yaml**

```yaml
sources:
  - name: my-custom-rules
    type: directory
    path: /home/user/my-rules
    enabled: true
```

**Option 2: Place in data/rules/**

- Files in `data/rules/` are automatically loaded
- They'll be tagged with source name 'local'

**Option 3: Reference external directories**

```yaml
sources:
  - name: company-rules
    type: directory
    path: /opt/company/suricata-rules
    enabled: true
```

### Reloading Rules

After modifying `rules.yaml` or adding new rule files, reload:

```bash
curl -X POST http://localhost:8000/api/v1/reload
```

Or restart the application.

## Troubleshooting

### Port Already in Use

If port 8000 is already in use, specify a different port:

```bash
python run.py
# Or manually:
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
```

### No Rules Loading

- Ensure `.rules` files are in the `data/rules/` directory
- Check that rules follow standard Suricata format
- Look at the console output for parsing errors
- The application includes sample rules in `data/rules/example.rules`

### Module Not Found Error

Make sure you've activated the virtual environment and installed dependencies:

```bash
# Activate venv first (see Setup section)
pip install -r requirements.txt
```

### PowerShell Execution Policy Error

See the Setup section above for solutions to activate the virtual environment in PowerShell.

## Development

### Running in Development Mode

Both startup methods automatically enable development mode with auto-reload:

```bash
# Using the startup script
python run.py

# Or using uvicorn directly
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The `--reload` flag enables auto-reload when code changes are detected.

### Customization

- **Frontend Styling**: Edit `backend/app/static/css/style.css`
- **Frontend Logic**: Edit `backend/app/static/js/app.js`
- **HTML Templates**: Edit `backend/app/templates/index.html`
- **API Endpoints**: Edit `backend/app/api/rules.py`
- **Rule Parser**: Edit `backend/app/parsers/suricata_parser.py`
- **Data Models**: Edit `backend/app/models/rule.py`

### Project Technology Stack

- **Backend**: FastAPI (Python)
- **Frontend**: Vanilla JavaScript with Jinja2 templates
- **Styling**: Custom CSS with CSS Grid and Flexbox
- **API**: RESTful API v1 with OpenAPI documentation
- **Parser**: [suricataparser](https://github.com/m-chrome/py-suricataparser) library for robust rule parsing

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Suricata IDS/IPS](https://suricata.io/) project for the rule format
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- Community contributors and testers
