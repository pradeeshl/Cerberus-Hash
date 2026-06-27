from pathlib import Path
import os
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = PROJECT_ROOT / 'backend'

# Load environment variables from .env files if present
load_dotenv(dotenv_path=PROJECT_ROOT / '.env')
load_dotenv(dotenv_path=BACKEND_ROOT / '.env')

DEFAULT_DATABASE_PATH = BACKEND_ROOT / 'cerberus_hash.db'
DEFAULT_UPLOAD_DIR = PROJECT_ROOT / 'uploads'
DEFAULT_YARA_RULES_PATH = PROJECT_ROOT / 'yara_rules' / 'malware_rules.yar'


class Settings:
    SECRET_KEY = os.getenv('SECRET_KEY', 'cerberus-hash-dev-secret-key')
    ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '60'))
    DATABASE_URL = os.getenv('DATABASE_URL', f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}")
    UPLOAD_DIR = Path(os.getenv('UPLOAD_DIR', str(DEFAULT_UPLOAD_DIR)))
    YARA_RULES_PATH = Path(os.getenv('YARA_RULES_PATH', str(DEFAULT_YARA_RULES_PATH)))
    MALWAREBAZAAR_API_KEY = os.getenv('MALWAREBAZAAR_API_KEY', '')


settings = Settings()