"""
Suricata Rule Downloader
Downloads and caches Suricata rules from various sources defined in rules.yaml
"""
import hashlib
import json
import shutil
import tarfile
import zipfile
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


class RuleSource:
    """Represents a source of Suricata rules"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize a rule source from configuration

        Args:
            config: Dictionary from rules.yaml source entry
        """
        self.name = config['name']
        self.type = config['type']  # 'url', 'directory', or 'file'
        self.description = config.get('description', '')
        self.enabled = config.get('enabled', True)

        # URL-specific fields
        if self.type == 'url':
            self.url = config['url']
            self.file_type = config.get('file_type', 'tar.gz')
            self.cache_hours = config.get('cache_hours', 24)

        # Local file/directory fields
        elif self.type in ['directory', 'file']:
            self.path = Path(config['path'])
            self.exclude_subdirs = config.get('exclude_subdirs', False)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        result = {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "enabled": self.enabled,
        }

        if self.type == 'url':
            result.update({
                "url": self.url,
                "file_type": self.file_type,
                "cache_hours": self.cache_hours,
            })
        elif self.type in ['directory', 'file']:
            result.update({
                "path": str(self.path),
            })
            if self.type == 'directory':
                result["exclude_subdirs"] = self.exclude_subdirs

        return result


class SuricataRuleDownloader:
    """Downloads and manages Suricata rule files from sources defined in rules.yaml"""

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the downloader

        Args:
            config_path: Path to rules.yaml (default: project_root/rules.yaml)
        """
        # Set default config path
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        self.config_path = config_path or project_root / "rules.yaml"

        # Set up directories
        self.cache_dir = project_root / "data" / "cache"
        self.rules_dir = project_root / "data" / "rules"

        # Create directories if they don't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        # Metadata file to track downloads
        self.metadata_file = self.cache_dir / "download_metadata.json"
        self.metadata = self._load_metadata()

        # Load sources from config
        self.sources = self._load_config()

    def _load_config(self) -> List[RuleSource]:
        """Load rule sources from rules.yaml"""
        if not self.config_path.exists():
            print(f"Warning: Config file not found: {self.config_path}")
            return []

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not config or 'sources' not in config:
                print(f"Warning: No sources defined in {self.config_path}")
                return []

            sources = []
            for source_config in config['sources']:
                try:
                    source = RuleSource(source_config)
                    sources.append(source)
                except Exception as e:
                    print(f"Error loading source config: {e}")
                    print(f"Config: {source_config}")

            return sources

        except yaml.YAMLError as e:
            print(f"Error parsing {self.config_path}: {e}")
            return []
        except Exception as e:
            print(f"Error loading config: {e}")
            return []

    def _load_metadata(self) -> Dict:
        """Load download metadata from cache"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading metadata: {e}")
                return {}
        return {}

    def _save_metadata(self):
        """Save download metadata to cache"""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving metadata: {e}")

    def _get_cache_path(self, source: RuleSource) -> Path:
        """Get the cache file path for a source"""
        # Create a hash of the URL for consistent naming
        url_hash = hashlib.md5(source.url.encode()).hexdigest()[:8]
        filename = f"{source.name}_{url_hash}.{source.file_type}"
        return self.cache_dir / filename

    def _is_cache_valid(self, source: RuleSource) -> bool:
        """Check if cached file is still valid"""
        if source.type != 'url':
            return False  # Local sources don't use cache

        cache_path = self._get_cache_path(source)

        if not cache_path.exists():
            return False

        # Check metadata
        source_key = source.name
        if source_key not in self.metadata:
            return False

        # Check if cache has expired
        try:
            last_download = datetime.fromisoformat(self.metadata[source_key]["last_download"])
            expiry = last_download + timedelta(hours=source.cache_hours)

            if datetime.now() > expiry:
                print(f"Cache expired for {source.name}")
                return False
        except (KeyError, ValueError) as e:
            print(f"Invalid metadata for {source.name}: {e}")
            return False

        return True

    def _download_file(self, url: str, destination: Path) -> bool:
        """
        Download a file from URL to destination

        Args:
            url: URL to download from
            destination: Path to save file to

        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"Downloading from {url}...")

            # Create request with user agent
            headers = {
                "User-Agent": "SuricataRuleBrowser/1.0 (Educational/Research Tool)"
            }
            request = Request(url, headers=headers)

            # Download with progress indication
            with urlopen(request, timeout=60) as response:
                total_size = int(response.headers.get("Content-Length", 0))

                with open(destination, "wb") as f:
                    downloaded = 0
                    chunk_size = 8192

                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break

                        f.write(chunk)
                        downloaded += len(chunk)

                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"  Progress: {percent:.1f}% ({downloaded}/{total_size} bytes)", end="\r")

            print(f"\n  Download complete: {destination}")
            return True

        except (URLError, HTTPError, TimeoutError) as e:
            print(f"Error downloading {url}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error downloading {url}: {e}")
            return False

    def _extract_archive(self, archive_path: Path, source: RuleSource) -> bool:
        """
        Extract rules from archive to rules directory

        Args:
            archive_path: Path to archive file
            source: Rule source information

        Returns:
            True if successful, False otherwise
        """
        # Create source-specific directory
        source_rules_dir = self.rules_dir / source.name
        source_rules_dir.mkdir(parents=True, exist_ok=True)

        try:
            if source.file_type == "tar.gz":
                print(f"Extracting tar.gz archive...")
                with tarfile.open(archive_path, "r:gz") as tar:
                    # Extract only .rules files
                    rules_files = [m for m in tar.getmembers() if m.name.endswith(".rules")]
                    print(f"  Found {len(rules_files)} rule files")

                    for member in rules_files:
                        # Extract to source-specific directory
                        member.name = Path(member.name).name  # Get just filename
                        tar.extract(member, source_rules_dir)
                        print(f"  Extracted: {member.name}")

            elif source.file_type == "zip":
                print(f"Extracting zip archive...")
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    # Extract only .rules files
                    rules_files = [name for name in zip_ref.namelist() if name.endswith(".rules")]
                    print(f"  Found {len(rules_files)} rule files")

                    for file_name in rules_files:
                        # Extract to source-specific directory
                        zip_ref.extract(file_name, source_rules_dir)
                        print(f"  Extracted: {file_name}")

            elif source.file_type == "rules":
                # Single rules file, just copy it
                print(f"Copying rules file...")
                dest_path = source_rules_dir / f"{source.name}.rules"
                shutil.copy(archive_path, dest_path)
                print(f"  Copied to: {dest_path}")

            else:
                print(f"Unsupported file type: {source.file_type}")
                return False

            return True

        except Exception as e:
            print(f"Error extracting {archive_path}: {e}")
            return False

    def process_url_source(self, source: RuleSource, force: bool = False) -> bool:
        """
        Process a URL source (download and extract)

        Args:
            source: URL source to process
            force: Force download even if cache is valid

        Returns:
            True if successful, False otherwise
        """
        cache_path = self._get_cache_path(source)

        # Check if we need to download
        if not force and self._is_cache_valid(source):
            print(f"Using cached rules for {source.name}")
        else:
            # Download the file
            if not self._download_file(source.url, cache_path):
                return False

            # Update metadata
            self.metadata[source.name] = {
                "last_download": datetime.now().isoformat(),
                "url": source.url,
                "cache_path": str(cache_path),
                "description": source.description,
                "type": source.type,
            }
            self._save_metadata()

        # Extract rules
        print(f"Extracting rules for {source.name}...")
        return self._extract_archive(cache_path, source)

    def process_local_source(self, source: RuleSource) -> bool:
        """
        Process a local file or directory source

        Args:
            source: Local source to process

        Returns:
            True if successful, False otherwise
        """
        # For local sources, we just verify the path exists
        # The parser will handle loading them directly
        if not source.path.exists():
            print(f"Warning: Path does not exist: {source.path}")
            return False

        if source.type == 'file':
            if not source.path.is_file():
                print(f"Error: Not a file: {source.path}")
                return False
            print(f"Local rules file verified: {source.path}")

        elif source.type == 'directory':
            if not source.path.is_dir():
                print(f"Error: Not a directory: {source.path}")
                return False

            # Count rules files
            if source.exclude_subdirs:
                rules_files = list(source.path.glob("*.rules"))
            else:
                rules_files = list(source.path.glob("**/*.rules"))

            print(f"Local rules directory verified: {source.path} ({len(rules_files)} files)")

        return True

    def download_all(self, force: bool = False) -> Dict[str, bool]:
        """
        Process all enabled sources

        Args:
            force: Force download even if cache is valid

        Returns:
            Dictionary mapping source names to success status
        """
        results = {}

        for source in self.sources:
            if not source.enabled:
                print(f"Skipping disabled source: {source.name}")
                continue

            print(f"\n{'='*60}")
            print(f"Processing source: {source.name} ({source.type})")
            print(f"{'='*60}")

            try:
                if source.type == 'url':
                    success = self.process_url_source(source, force=force)
                elif source.type in ['file', 'directory']:
                    success = self.process_local_source(source)
                else:
                    print(f"Unknown source type: {source.type}")
                    success = False

                results[source.name] = success

            except Exception as e:
                print(f"Error processing source {source.name}: {e}")
                results[source.name] = False

        return results

    def get_all_sources(self) -> List[Dict]:
        """Get information about all configured sources"""
        sources_info = []

        for source in self.sources:
            info = source.to_dict()

            # Add metadata for URL sources
            if source.type == 'url' and source.name in self.metadata:
                info["last_download"] = self.metadata[source.name].get("last_download")
                info["cached"] = self._is_cache_valid(source)

            sources_info.append(info)

        return sources_info

    def get_source_by_name(self, name: str) -> Optional[RuleSource]:
        """Get a source by name"""
        for source in self.sources:
            if source.name == name:
                return source
        return None
