# generic_log_parser.py
"""
Generic Log Parser for Root Cause Analysis
Works with any log format - structured or unstructured
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class LogEntry:
    """Simple log entry"""
    line_number: int
    text: str
    is_error: bool = False
    is_warning: bool = False
    has_exception: bool = False
    has_stack_trace: bool = False
    timestamp: Optional[str] = None
    meta Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedLog:
    """Parsed log result"""
    all_entries: List[LogEntry]
    errors: List[LogEntry]
    warnings: List[LogEntry]
    exceptions: List[Dict[str, Any]]
    summary: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON"""
        return {
            "summary": self.summary,
            "errors": [{"line": e.line_number, "text": e.text} for e in self.errors],
            "warnings": [{"line": w.line_number, "text": w.text} for w in self.warnings],
            "exceptions": self.exceptions,
            "total_lines": len(self.all_entries)
        }


class GenericLogParser:
    """Simple generic log parser for any format"""
    
    ERROR_KEYWORDS = [
        'error', 'fail', 'failed', 'failure', 'fatal', 'critical',
        'exception', 'crash', 'abort', 'panic', 'timeout'
    ]
    
    WARNING_KEYWORDS = [
        'warn', 'warning', 'caution', 'alert', 'deprecat'
    ]
    
    EXCEPTION_PATTERNS = [
        r'(\w+(?:Error|Exception))[\s:]',
        r'Traceback \(most recent call last\)',
        r'Exception in thread',
        r'Caused by:',
        r'at \w+\.\w+\(',
    ]
    
    STACK_TRACE_INDICATORS = [
        r'^\s+at ',
        r'^\s+File "',
        r'^\s+in \w+',
        r'^\s+\d+\s+',
        r'^\s*---',
    ]
    
    TIMESTAMP_PATTERNS = [
        r'\d{4}[-/]\d{2}[-/]\d{2}',
        r'\d{2}[-/]\d{2}[-/]\d{4}',
        r'\d{2}:\d{2}:\d{2}',
        r'\d{10,13}',
    ]
    
    def _init_(self, context_lines: int = 3, min_error_length: int = 10):
        self.context_lines = context_lines
        self.min_error_length = min_error_length
    
    def parse(self, log_text: str) -> ParsedLog:
        """Parse any log format"""
        lines = log_text.split('\n')
        entries = []
        errors = []
        warnings = []
        exceptions = []
        
        current_exception = None
        in_stack_trace = False
        
        for line_num, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            
            entry = LogEntry(
                line_number=line_num,
                text=line,
                timestamp=self._extract_timestamp(line)
            )
            
            # Check for errors
            if self._is_error_line(line):
                entry.is_error = True
                errors.append(entry)
                
                exception_type = self._extract_exception_type(line)
                if exception_type:
                    entry.has_exception = True
                    
                    if current_exception:
                        exceptions.append(current_exception)
                    
                    current_exception = {
                        'type': exception_type,
                        'line': line_num,
                        'message': line.strip(),
                        'stack_trace': [],
                        'context_before': self._get_context_before(lines, line_num),
                        'context_after': []
                    }
                    in_stack_trace = True
            
            elif self._is_warning_line(line):
                entry.is_warning = True
                warnings.append(entry)
            
            elif in_stack_trace and self._is_stack_trace_line(line):
                entry.has_stack_trace = True
                if current_exception:
                    current_exception['stack_trace'].append(line.strip())
            else:
                if in_stack_trace and current_exception:
                    current_exception['context_after'] = self._get_context_after(
                        lines, current_exception['line'], line_num
                    )
                in_stack_trace = False
            
            entries.append(entry)
        
        if current_exception:
            exceptions.append(current_exception)
        
        summary = self._build_summary(entries, errors, warnings, exceptions)
        
        return ParsedLog(
            all_entries=entries,
            errors=errors,
            warnings=warnings,
            exceptions=exceptions,
            summary=summary
        )
    
    def _is_error_line(self, line: str) -> bool:
        """Check if line contains error indicators"""
        line_lower = line.lower()
        
        for keyword in self.ERROR_KEYWORDS:
            if re.search(r'\b' + keyword + r'\b', line_lower):
                return True
        
        for pattern in self.EXCEPTION_PATTERNS:
            if re.search(pattern, line):
                return True
        
        return False
    
    def _is_warning_line(self, line: str) -> bool:
        """Check if line contains warning indicators"""
        line_lower = line.lower()
        for keyword in self.WARNING_KEYWORDS:
            if re.search(r'\b' + keyword, line_lower):
                return True
        return False
    
    def _is_stack_trace_line(self, line: str) -> bool:
        """Check if line is part of stack trace"""
        if not line[0].isspace():
            return False
        
        for pattern in self.STACK_TRACE_INDICATORS:
            if re.match(pattern, line):
                return True
        return False
    
    def _extract_exception_type(self, line: str) -> Optional[str]:
        """Extract exception type from line"""
        for pattern in self.EXCEPTION_PATTERNS:
            match = re.search(pattern, line)
            if match:
                if 'Error' in match.group(0) or 'Exception' in match.group(0):
                    return match.group(1) if match.lastindex else match.group(0).strip()
        return None
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract any timestamp format from line"""
        for pattern in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None
    
    def _get_context_before(self, lines: List[str], current_line: int) -> List[str]:
        """Get context lines before error"""
        start = max(0, current_line - self.context_lines - 1)
        end = current_line - 1
        
        context = []
        for i in range(start, end):
            if i < len(lines) and lines[i].strip():
                context.append(lines[i].strip())
        return context
    
    def _get_context_after(self, lines: List[str], error_line: int, current_line: int) -> List[str]:
        """Get context lines after error/stack trace"""
        start = current_line
        end = min(len(lines), error_line + self.context_lines + 10)
        
        context = []
        for i in range(start, end):
            if i < len(lines) and lines[i].strip():
                if not self._is_stack_trace_line(lines[i]):
                    context.append(lines[i].strip())
                    if len(context) >= self.context_lines:
                        break
        return context
    
    def _build_summary(
        self,
        entries: List[LogEntry],
        errors: List[LogEntry],
        warnings: List[LogEntry],
        exceptions: List[Dict]
    ) -> Dict[str, Any]:
        """Build summary statistics"""
        
        exception_types = defaultdict(int)
        for exc in exceptions:
            exception_types[exc['type']] += 1
        
        total_lines = len(entries)
        error_density = (len(errors) / total_lines * 100) if total_lines > 0 else 0
        
        timestamps = [e.timestamp for e in entries if e.timestamp]
        
        return {
            'total_lines': total_lines,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'exception_count': len(exceptions),
            'exception_types': dict(exception_types),
            'error_density': round(error_density, 2),
            'has_timestamps': len(timestamps) > 0,
            'timestamp_coverage': round(len(timestamps) / total_lines * 100, 2) if total_lines > 0 else 0
        }
    
    def prepare_for_rca(self, parsed_log: ParsedLog) -> Dict:
        """Prepare parsed log for RCA LLM processing"""
        rca_data = {
            'summary': parsed_log.summary,
            'critical_errors': [],
            'all_exceptions': parsed_log.exceptions,
            'error_patterns': self._identify_error_patterns(parsed_log.errors)
        }
        
        for error in parsed_log.errors[:20]:
            error_data = {
                'line_number': error.line_number,
                'message': error.text.strip(),
                'timestamp': error.timestamp,
                'context_before': [],
                'context_after': []
            }
            
            start_idx = max(0, error.line_number - self.context_lines - 1)
            end_idx = min(len(parsed_log.all_entries), error.line_number + self.context_lines)
            
            for idx in range(start_idx, error.line_number - 1):
                if idx < len(parsed_log.all_entries):
                    error_data['context_before'].append(parsed_log.all_entries[idx].text.strip())
            
            for idx in range(error.line_number, end_idx):
                if idx < len(parsed_log.all_entries):
                    error_data['context_after'].append(parsed_log.all_entries[idx].text.strip())
            
            rca_data['critical_errors'].append(error_data)
        
        return rca_data
    
    def _identify_error_patterns(self, errors: List[LogEntry]) -> Dict[str, int]:
        """Identify common error patterns"""
        patterns = defaultdict(int)
        
        for error in errors:
            text = error.text.lower()
            
            if 'timeout' in text or 'timed out' in text:
                patterns['timeout'] += 1
            elif 'connection' in text or 'connect' in text:
                patterns['connection_issue'] += 1
            elif 'permission' in text or 'denied' in text or 'forbidden' in text:
                patterns['permission_denied'] += 1
            elif 'not found' in text or '404' in text:
                patterns['not_found'] += 1
            elif 'null' in text or 'none' in text:
                patterns['null_reference'] += 1
            elif 'assert' in text:
                patterns['assertion_failure'] += 1
            elif 'memory' in text or 'oom' in text:
                patterns['memory_issue'] += 1
            else:
                patterns['other'] += 1
        
        return dict(patterns)


def parse_log_file(file_path: str) -> ParsedLog:
    """Parse log file with generic parser"""
    parser = GenericLogParser()
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_text = f.read()
    
    return parser.parse(log_text)




# rca_prompt_system.py
"""
Complete RCA Prompt System for LLM
Integrates log parser, categories, and output format
"""

from typing import Dict
from config.failure_categories import format_categories_for_prompt


# Output format template
RCA_OUTPUT_FORMAT = """
PRIMARY ROOT CAUSE: [One-line description]

CATEGORY: [Main Category] → [Subcategory]
CONFIDENCE SCORE: [High/Medium/Low] ([0.0-1.0 numeric score])

DETAILED ANALYSIS:
[Explain what went wrong and why, referencing specific log evidence]

KEY EVIDENCE:
- Line [number]: [Critical log line 1]
- Line [number]: [Critical log line 2]
- Line [number]: [Critical log line 3]

CONTRIBUTING FACTORS:
1. [Primary contributing factor]
2. [Secondary contributing factor]
3. [Tertiary contributing factor]

SEVERITY: [Critical/High/Medium/Low]
IMPACT: [Business/user impact description]

FAILURE TYPE: [Permanent/Transient]
REQUIRES CODE FIX: [Yes/No]
REQUIRES CONFIG CHANGE: [Yes/No]

IMMEDIATE RECOMMENDATIONS:
1. [Action with expected impact]
2. [Action with expected impact]
3. [Action with expected impact]

SHORT-TERM FIXES (1-2 weeks):
1. [Action and benefit]
2. [Action and benefit]

LONG-TERM PREVENTION (1-3 months):
1. [Strategic improvement]
2. [Strategic improvement]

MONITORING & ALERTS:
- Metrics to Track: [metric1, metric2, metric3]
- Alert Thresholds: [threshold details]

PREVENTION STRATEGY:
[How to prevent this in the future with specific steps]
"""


def build_log_context(parsed_log_ dict) -> str:
    """Build formatted log context from parsed data"""
    context = "=== LOG CONTEXT ===\n\n"
    
    # Summary
    context += "*SUMMARY:*\n"
    context += f"- Total Lines: {parsed_log_data['summary']['total_lines']}\n"
    context += f"- Errors: {parsed_log_data['summary']['error_count']}\n"
    context += f"- Warnings: {parsed_log_data['summary']['warning_count']}\n"
    context += f"- Exceptions: {parsed_log_data['summary']['exception_count']}\n"
    
    # Exception types
    if parsed_log_data['summary'].get('exception_types'):
        context += f"\n*EXCEPTION TYPES:*\n"
        for exc_type, count in parsed_log_data['summary']['exception_types'].items():
            context += f"- {exc_type}: {count}\n"
    
    # Error patterns
    if parsed_log_data.get('error_patterns'):
        context += f"\n*ERROR PATTERNS:*\n"
        for pattern, count in parsed_log_data['error_patterns'].items():
            context += f"- {pattern.replace('_', ' ').title()}: {count}\n"
    
    # Critical errors with context
    context += f"\n*CRITICAL ERRORS:*\n"
    for idx, error in enumerate(parsed_log_data['critical_errors'][:5], 1):
        context += f"\n--- Error #{idx} (Line {error['line_number']}) ---\n"
        
        if error.get('timestamp'):
            context += f"Time: {error['timestamp']}\n"
        
        if error.get('context_before'):
            context += "Before:\n"
            for line in error['context_before'][-2:]:
                context += f"  {line}\n"
        
        context += f">>> {error['message']}\n"
        
        if error.get('context_after'):
            context += "After:\n"
            for line in error['context_after'][:2]:
                context += f"  {line}\n"
    
    # Detailed exceptions
    if parsed_log_data.get('all_exceptions'):
        context += f"\n*EXCEPTION DETAILS:*\n"
        for idx, exc in enumerate(parsed_log_data['all_exceptions'][:3], 1):
            context += f"\n--- Exception #{idx}: {exc['type']} ---\n"
            context += f"Message: {exc['message']}\n"
            
            if exc.get('stack_trace'):
                context += "Stack Trace:\n"
                for line in exc['stack_trace'][:6]:
                    context += f"  {line}\n"
    
    return context


def generate_rca_prompt(parsed_log_ dict) -> Dict[str, str]:
    """
    Generate complete RCA prompt for LLM
    
    Args:
        parsed_log_ Output from generic_log_parser.prepare_for_rca()
        
    Returns:
        Dictionary with system and user prompts
    """
    
    system_instruction = """You are an expert Root Cause Analysis (RCA) AI system.

Analyze the provided log context and classify the failure using the comprehensive category reference.

Select ONE primary category and ONE subcategory that best matches the failure.
Use the provided indicators, examples, and descriptions to guide your classification.

Follow the specified output format exactly."""

    # Get formatted categories
    categories_text = format_categories_for_prompt()
    
    # Build log context
    log_context = build_log_context(parsed_log_data)
    
    # User prompt
    user_prompt = f"""{categories_text}

{log_context}

Analyze this failure and provide your response in the following format:

{RCA_OUTPUT_FORMAT}"""

    return {
        "system": system_instruction,
        "user": user_prompt
    }


def format_for_openai(system_prompt: str, user_prompt: str) -> list:
    """Format prompts for OpenAI API"""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]


def format_for_anthropic(system_prompt: str, user_prompt: str) -> dict:
    """Format prompts for Anthropic Claude API"""
    return {
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}]
    }



# config/failure_categories.py
"""
Comprehensive Failure Categories for RCA
"""

FAILURE_CATEGORIES = {
    # ============================================
    # 1. PRODUCT/APPLICATION ISSUES
    # ============================================
    
    "Application Defect": {
        "description": "Bug in the application under test",
        "sub_categories": [
            "Functional - Business logic or calculation errors",
            "API/Backend - REST API, microservices, server errors",
            "UI/Frontend - Interface rendering, display, user interaction issues",
            "Database - Data persistence, retrieval, integrity problems",
            "Integration - Service-to-service communication failures"
        ],
        "examples": [
            "Wrong calculation result",
            "API returns 500 error",
            "Button doesn't respond to click",
            "Data not saved to database",
            "Service call timeout between microservices"
        ],
        "indicators": [
            "expected != actual in business logic",
            "5xx status codes",
            "element not responding",
            "data mismatch",
            "integration failure"
        ]
    },
    
    # ============================================
    # 2. TEST AUTOMATION ISSUES
    # ============================================
    
    "Test Automation Issue": {
        "description": "Problem with test code, not the application",
        "sub_categories": [
            "Test Logic - Wrong assertions, incorrect expected values",
            "Locators - UI element selectors incorrect or outdated",
            "Synchronization - Missing waits, timing issues in test",
            "Test Design - Flawed test approach or validation"
        ],
        "examples": [
            "Test checking wrong field",
            "CSS selector changed after UI update",
            "Test doesn't wait for page load",
            "Assertion validates non-critical behavior"
        ],
        "indicators": [
            "element not found",
            "stale element reference",
            "test logic error",
            "premature assertion"
        ]
    },
    
    # ============================================
    # 3. TEST DATA ISSUES
    # ============================================
    
    "Test Data Issue": {
        "description": "Problems with test data or test accounts",
        "sub_categories": [
            "Invalid/Missing Data - Required data not available",
            "Expired Credentials - Test accounts locked or expired",
            "Data Isolation - Tests interfering with each other",
            "Data Dependencies - Prerequisite data not set up"
        ],
        "examples": [
            "Test user account locked",
            "Required product data missing",
            "Parallel tests using same data",
            "Database not seeded with test data"
        ],
        "indicators": [
            "user not found",
            "invalid credentials",
            "data not available",
            "constraint violation",
            "duplicate key error"
        ]
    },
    
    # ============================================
    # 4. ENVIRONMENT/INFRASTRUCTURE
    # ============================================
    
    "Environment Issue": {
        "description": "Infrastructure, deployment, or configuration problems",
        "sub_categories": [
            "Service Down - Application or services unavailable",
            "Configuration - Wrong settings, missing env variables",
            "Deployment - Service restart, rollout in progress",
            "Resources - Memory, disk, CPU exhaustion"
        ],
        "examples": [
            "Test environment offline",
            "Wrong API endpoint URL in config",
            "Pod restarting during test",
            "Out of memory error"
        ],
        "indicators": [
            "connection refused",
            "503 service unavailable",
            "502 bad gateway",
            "configuration error",
            "OOM killed",
            "disk full"
        ]
    },
    
    # ============================================
    # 5. NETWORK/CONNECTIVITY
    # ============================================
    
    "Network/Timeout Issue": {
        "description": "Network communication or performance problems",
        "sub_categories": [
            "Connectivity - Network failures, DNS, firewall",
            "Timeout - Operations exceeding time limits",
            "Performance - Slow response times"
        ],
        "examples": [
            "DNS resolution failed",
            "API response took 60 seconds",
            "Network timeout after 30s",
            "Firewall blocking request"
        ],
        "indicators": [
            "timeout",
            "DNS error",
            "connection timed out",
            "network unreachable",
            "slow response"
        ]
    },
    
    # ============================================
    # 6. EXTERNAL DEPENDENCIES
    # ============================================
    
    "External Dependency Failure": {
        "description": "Third-party services or tools failing",
        "sub_categories": [
            "Third-Party API - External services down or rate limited",
            "Browser/Driver - Selenium, WebDriver issues",
            "Cloud Services - AWS, Azure, GCP outages"
        ],
        "examples": [
            "Payment gateway unavailable",
            "OAuth provider down",
            "WebDriver crashed",
            "S3 bucket unreachable"
        ],
        "indicators": [
            "third party",
            "external service",
            "rate limit",
            "webdriver",
            "browser crashed"
        ]
    },
    
    # ============================================
    # 7. TIMING/FLAKINESS
    # ============================================
    
    "Intermittent/Flaky": {
        "description": "Non-deterministic or timing-dependent failures",
        "sub_categories": [
            "Race Condition - Concurrent operations conflicting",
            "Flaky Test - Random, non-reproducible failures",
            "Timing Dependent - Works sometimes, fails other times"
        ],
        "examples": [
            "Passes on retry",
            "Works locally, fails in CI",
            "Concurrent modification error",
            "Time-based behavior variation"
        ],
        "indicators": [
            "intermittent",
            "race condition",
            "concurrent modification",
            "non-deterministic",
            "random failure"
        ]
    },
    
    # ============================================
    # 8. SECURITY/ACCESS
    # ============================================
    
    "Security/Access Issue": {
        "description": "Authentication, authorization, or security problems",
        "sub_categories": [
            "Authentication - Login, token validation failures",
            "Authorization - Permission denied, access control",
            "Security Policy - CORS, SSL, certificate issues"
        ],
        "examples": [
            "Token expired",
            "User lacks permission",
            "CORS policy violation",
            "SSL certificate invalid"
        ],
        "indicators": [
            "401 unauthorized",
            "403 forbidden",
            "CORS error",
            "SSL error",
            "authentication failed"
        ]
    },
    
    # ============================================
    # 9. SPECIAL CATEGORIES
    # ============================================
    
    "Known Issue": {
        "description": "Expected failure due to documented limitation",
        "sub_categories": [
            "Feature Not Implemented - Planned but not yet developed",
            "Documented Bug - Known issue in backlog",
            "Technical Debt - Existing limitation"
        ],
        "examples": [
            "Feature scheduled for next sprint",
            "Bug ticket XYZ-123 already exists",
            "Legacy system limitation"
        ],
        "indicators": [
            "known issue",
            "expected failure",
            "backlog item"
        ]
    },
    
    "Blocked/Cannot Execute": {
        "description": "Test cannot run due to earlier failure",
        "sub_categories": [
            "Prerequisite Failed - Setup or login failed",
            "Dependency - Required test or service failed",
            "Environment Not Ready - Setup incomplete"
        ],
        "examples": [
            "Login test failed, cannot proceed",
            "Database seed script failed",
            "Required service not deployed"
        ],
        "indicators": [
            "blocked",
            "prerequisite",
            "setup failed",
            "cannot proceed"
        ]
    },
    
    "Needs Investigation": {
        "description": "Insufficient information to classify definitively",
        "sub_categories": [
            "Insufficient Logs - Not enough diagnostic information",
            "New Pattern - Previously unseen error",
            "Complex Failure - Multiple contributing factors"
        ],
        "examples": [
            "Generic error with no details",
            "New error pattern after deployment",
            "Multiple services failed simultaneously"
        ],
        "indicators": [
            "unknown error",
            "unclear cause",
            "minimal logs"
        ]
    }
}


def format_categories_for_prompt() -> str:
    """Format categories dictionary as readable text for LLM prompt"""
    output = ["=== FAILURE CATEGORY REFERENCE ===\n"]
    
    for idx, (category, details) in enumerate(FAILURE_CATEGORIES.items(), 1):
        output.append(f"\n*{idx}. {category.upper()}*")
        output.append(f"Description: {details['description']}\n")
        
        output.append("Sub-categories:")
        for sub in details['sub_categories']:
            output.append(f"  • {sub}")
        
        output.append("\nExamples:")
        for example in details['examples'][:3]:
            output.append(f"  - {example}")
        
        output.append("\nKey Indicators:")
        indicators_str = ", ".join(details['indicators'][:5])
        output.append(f"  {indicators_str}")
        output.append("")
    
    return "\n".join(output)


def get_category_list() -> list:
    """Get list of all main categories"""
    return list(FAILURE_CATEGORIES.keys())


def get_subcategories(main_category: str) -> list:
    """Get subcategories for a main category"""
    if main_category in FAILURE_CATEGORIES:
        return FAILURE_CATEGORIES[main_category]['sub_categories']
    return []


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
logger = logging.getLogger(_name_)


class SeverityLevel(Enum):
    """Validation severity levels"""
    CRITICAL = "critical"  # Block processing
    HIGH = "high"         # Block processing
    MEDIUM = "medium"     # Warn but allow
    LOW = "low"          # Info only
    INFO = "info"        # Informational


@dataclass
class ValidationIssue:
    """Individual validation issue"""
    severity: SeverityLevel
    category: str
    message: str
    location: Optional[str] = None
    recommendation: str = ""


@dataclass
class ValidationResult:
    """Log validation result"""
    is_valid: bool
    log_id: str
    timestamp: str
    issues: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    sanitized_log: Optional[str] = None
    
    def get_critical_issues(self) -> List[ValidationIssue]:
        """Get critical/high severity issues"""
        return [i for i in self.issues if i.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
    
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


class LogValidator:
    """Production-ready log input validator"""
    
    # Size limits
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_LINE_LENGTH = 50000
    MAX_LINES = 100000
    
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
        'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'
    }
    
    # Log injection patterns
    INJECTION_PATTERNS = {
        'command_injection': r'[;&|`$(){}]',
        'path_traversal': r'\.\.[/\\]',
        'null_byte': r'\x00',
        'script_tag': r'<script[^>]>.?</script>',
        'sql_injection': r'(?i)(union|select|insert|update|delete|drop|exec|execute)\s',
        'ldap_injection': r'[*()\\]',
        'xml_injection': r'<!(?:DOCTYPE|ENTITY)',
        'format_string': r'%[sdxn]',
        'control_chars': r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'encoded_data': r'(?:[A-Za-z0-9+/]{40,}={0,2})',  # Base64
        'hex_encoded': r'(?:0x)?[0-9a-fA-F]{40,}',
        'unicode_escape': r'\\u[0-9a-fA-F]{4}',
        'excessive_repetition': r'(.)\1{50,}',
        'obfuscation': r'(?:[A-Z]{10,}|[a-z]{10,}){3,}'
    }
    
    def _init_(
        self,
        max_log_size: int = MAX_LOG_SIZE,
        allow_pii: bool = False,
        sanitize_pii: bool = True,
        strict_mode: bool = True
    ):
        """
        Initialize log validator
        
        Args:
            max_log_size: Maximum log size in bytes
            allow_pii: Allow PII in logs
            sanitize_pii: Sanitize detected PII
            strict_mode: Fail on any critical issue
        """
        self.max_log_size = max_log_size
        self.allow_pii = allow_pii
        self.sanitize_pii = sanitize_pii
        self.strict_mode = strict_mode
    
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
        size_issues = self._validate_size(log_text)
        issues.extend(size_issues)
        
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
        
        return issues
    
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


def validate_log_batch(logs: List[str], validator: Optional[LogValidator] = None) -> List[ValidationResult]:
    """Validate multiple logs"""
    if validator is None:
        validator = LogValidator()
    
    return [validator.validate(log, {"batch_index": idx}) for idx, log in enumerate(logs)]


# Example usage
if _name_ == "_main_":
    # Initialize validator
    validator = LogValidator(
        max_log_size=5 * 1024 * 1024,  # 5MB
        allow_pii=False,
        sanitize_pii=True,
        strict_mode=True
    )
    
    # Example log with issues
    test_log = """
    2025-11-05 14:30:00 ERROR Test failed
    User email: john.doe@example.com
    API Key: sk_live_1234567890abcdefghijklmnop
    Connection failed to 192.168.1.100
    """
    
    # Validate
    result = validator.validate(test_log)
    
    # Print results
    print(json.dumps(result.to_dict(), indent=2))
    
    if result.sanitized_log:
        print("\n=== Sanitized Log ===")
        print(result.sanitized_log)
