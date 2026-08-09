#!/usr/bin/env python3
"""
SMTP Stress Test
A comprehensive stress testing tool that runs for a set duration and pushes the system to its limits.
Features configurable intensity levels, real-time monitoring, and detailed performance reporting.
"""

import smtplib
import threading
import time
import statistics
import psutil
import json
import signal
import sys
from pathlib import Path
import argparse
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.parser import Parser
from email.message import Message
from email import policy
from email.header import Header
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, asdict
import random
from datetime import datetime, timedelta

@dataclass
class StressTestConfig:
    """Configuration for stress test"""
    duration_seconds: int = 300  # 5 minutes default
    max_concurrent_connections: int = 100
    min_concurrent_connections: int = 10
    ramp_up_time: int = 30  # seconds to reach max connections
    message_size_bytes: int = 1024
    target_host: str = 'localhost'
    target_port: int = 2525
    use_authentication: bool = False
    username: str = ''
    password: str = ''
    burst_mode: bool = False  # Enable burst patterns
    burst_interval: int = 30  # seconds between bursts
    burst_duration: int = 5   # seconds for each burst
    monitor_system_resources: bool = True
    output_file: str = ''
    # Advanced testing options
    use_tls: bool = False
    connection_reuse: bool = True  # Use keep-alive connections
    messages_per_connection: int = 10  # Messages per connection if reuse enabled
    use_pipelining: bool = False  # SMTP pipelining
    slow_client_mode: bool = False  # Test slow client behavior
    slow_read_delay: float = 0.1  # Seconds delay between reads
    malformed_commands: bool = False  # Test malformed SMTP commands
    auth_failure_rate: float = 0.0  # Rate of intentional auth failures (0.0-1.0)
    # Email content options
    corpus_dir: str = 'tests/corpus'  # Directory containing email files
    use_corpus: bool = True  # Use real email files from corpus
    corpus_limit: int = 20000  # Max messages to index; 0 means no limit
    corpus_max_bytes: int = 25 * 1024 * 1024  # Skip corpus files larger than this
    # Authentication options
    auth_user_prefix: str = 'stressuser'  # Prefix for test users
    auth_user_count: int = 10  # Number of test users to create
    auth_password: str = 'testpass123'  # Password for test users
    auth_domain: str = 'example.com'  # Domain for test users

@dataclass
class SystemMetrics:
    """System resource metrics"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    active_connections: int
    threads_count: int
    network_io_mb: float
    file_descriptors: int
    queue_depth: int = 0  # SMTP server queue depth if available

@dataclass
class StressTestResults:
    """Complete stress test results"""
    config: StressTestConfig
    start_time: datetime
    end_time: datetime
    total_duration: float
    total_emails_sent: int
    successful_emails: int
    failed_emails: int
    emails_per_second: float
    response_times: List[float]
    error_counts: Dict[str, int]
    system_metrics: List[SystemMetrics]
    percentile_50: float
    percentile_95: float
    percentile_99: float
    max_response_time: float
    min_response_time: float
    # Categorized metrics for email types
    clean_sent: int = 0
    clean_accepted: int = 0
    spam_sent: int = 0
    spam_accepted: int = 0
    spam_rejected: int = 0
    virus_sent: int = 0
    virus_accepted: int = 0
    virus_rejected: int = 0
    other_sent: int = 0
    other_accepted: int = 0

class ConnectionPool:
    """Manages SMTP connection reuse and TLS"""
    
    def __init__(self, config: StressTestConfig):
        self.config = config
        self.connections: Dict[int, smtplib.SMTP] = {}
        self.connection_lock = threading.Lock()
        self.connection_usage: Dict[int, int] = {}
    
    def get_connection(self, thread_id: int) -> smtplib.SMTP:
        """Get or create a connection for the thread"""
        with self.connection_lock:
            if thread_id in self.connections:
                # Check if connection is still valid
                try:
                    # Test connection with RSET instead of NOOP to reset state
                    self.connections[thread_id].rset()
                    return self.connections[thread_id]
                except:
                    # Connection is dead, remove it
                    try:
                        self.connections[thread_id].quit()
                    except:
                        pass
                    del self.connections[thread_id]
                    del self.connection_usage[thread_id]
            
            # Create new connection
            try:
                if self.config.use_tls:
                    server = smtplib.SMTP_SSL(self.config.target_host, self.config.target_port, timeout=10)
                else:
                    server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
                    if self.config.use_tls:
                        server.starttls()
                
                if self.config.use_authentication and self.config.username:
                    server.login(self.config.username, self.config.password)
                
                self.connections[thread_id] = server
                self.connection_usage[thread_id] = 1
                return server
                
            except Exception as e:
                raise Exception(f"Failed to create connection: {e}")
    
    def release_connection(self, thread_id: int):
        """Release a connection (close if usage limit reached)"""
        with self.connection_lock:
            if thread_id in self.connection_usage:
                self.connection_usage[thread_id] += 1
                
                # Close connection if usage limit reached
                if self.connection_usage[thread_id] >= self.config.messages_per_connection:
                    try:
                        self.connections[thread_id].quit()
                    except:
                        pass
                    del self.connections[thread_id]
                    del self.connection_usage[thread_id]
    
    def close_all(self):
        """Close all connections"""
        with self.connection_lock:
            for server in self.connections.values():
                try:
                    server.quit()
                except:
                    pass
            self.connections.clear()
            self.connection_usage.clear()

def _set_unique_header(msg, name: str, value: str) -> None:
    """Set a header to exactly one value, whatever was there before.

    The obvious `replace_header` raises when the header is absent, so the code
    used to branch on `msg.get(name)` and call `add_header` otherwise. That
    reads correctly but is wrong for a header that is *present but empty* —
    "To:" with nothing after it, which real mail contains. `.get()` returns ""
    for those, which is falsy, so the else branch added a second copy and the
    email policy refused it with "There may be at most 1 To headers in a
    message". The whole message was then thrown away in favour of a synthetic
    fallback, so the corpus files most worth testing — the malformed ones —
    were the exact ones that never reached the server.

    `del` removes every occurrence and is a no-op when there are none, so this
    handles absent, empty and duplicated headers alike.
    """
    del msg[name]
    msg[name] = value


class SMTPStressTester:
    """Advanced SMTP stress testing utility"""
    
    def __init__(self, config: StressTestConfig):
        self.config = config
        self.results: List[Tuple[float, bool, str]] = []
        self.system_metrics: List[SystemMetrics] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.current_connections = 0
        self.connection_lock = threading.Lock()
        self.start_time = None
        self.end_time = None
        self.connection_pool = ConnectionPool(config) if config.connection_reuse else None
        self.corpus_files = []
        self.corpus_lock = threading.Lock()
        # Corpus messages that could not be rewritten, counted per file rather
        # than printed per occurrence: the same handful of files get picked
        # thousands of times in a run, and the repeated warnings drowned out
        # everything else on the console.
        self.corpus_fallbacks = {}
        self.corpus_fallback_lock = threading.Lock()
        self.auth_users = []
        self.user_index = 0
        
        # Load corpus files if enabled (filter out spam/virus for stress testing)
        if config.use_corpus:
            self._load_corpus_files()
        
        # Generate authenticated user pool
        self._generate_auth_users()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, gracefully shutting down...")
        self.stop_event.set()
    
    # Files that are not messages, by name or extension.
    _CORPUS_SKIP_SUFFIXES = ('.tar', '.gz', '.bz2', '.zip', '.7z', '.xz', '.md', '.txt.gz')
    _CORPUS_SKIP_NAMES = ('.extracted', 'cmds', 'index')

    def _load_corpus_files(self):
        """Index message files under the corpus directory.

        Only paths are held. Real corpora are large — the Enron, SpamAssassin,
        TREC and untroubled sets together run to tens of gigabytes across
        millions of files — so reading every message into memory at startup is
        not an option. Content is read at send time instead.

        Discovery is recursive and does not require a particular extension:
        maildir-style corpora name messages things like `1.` or
        `1425868898.28783_3577.lorien`, and an earlier version of this loader
        globbed a single directory for `*.eml`, which found nothing in them.
        """
        if not self.config.use_corpus:
            return

        corpus_path = Path(self.config.corpus_dir)
        if not corpus_path.exists():
            print(f"⚠️  Corpus directory {self.config.corpus_dir} not found, using synthetic content")
            return

        self.corpus_stats = {'clean': 0, 'spam': 0, 'virus': 0, 'other': 0}
        limit = self.config.corpus_limit or 0

        # Draw from each top-level collection in turn rather than filling the
        # limit from whichever branch the walk enters first. A corpus like this
        # one holds ~500k Enron messages next to ~8.7M spam messages, and a
        # depth-first prefix of it is entirely one or the other — which makes
        # the run look clean and never exercises spam handling at all.
        roots = sorted(p for p in corpus_path.iterdir() if p.is_dir()) or [corpus_path]
        share = (limit // len(roots)) if limit else 0

        try:
            for root in roots:
                taken = 0
                for path in self._walk_corpus(root):
                    entry = self._corpus_entry(path)
                    if entry is None:
                        continue

                    self.corpus_files.append(entry)
                    self.corpus_stats[entry['type']] += 1
                    taken += 1

                    if share and taken >= share:
                        break
                    if limit and len(self.corpus_files) >= limit:
                        break
                if limit and len(self.corpus_files) >= limit:
                    break

            if self.corpus_files:
                print(f"📧 Indexed {len(self.corpus_files)} messages from {self.config.corpus_dir}:")
                for email_type, count in self.corpus_stats.items():
                    if count:
                        print(f"   {email_type}: {count}")
            else:
                print(f"⚠️  No usable messages found in {self.config.corpus_dir}, using synthetic content")

        except Exception as e:
            print(f"⚠️  Error indexing corpus: {e}")

    def _walk_corpus(self, root: Path):
        """Yield candidate message paths beneath root, depth first."""
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
            except (PermissionError, OSError):
                continue

    def _corpus_entry(self, path: Path):
        """Build an index entry for a path, or None if it is not a message."""
        name = path.name
        if name.startswith('.') or name in self._CORPUS_SKIP_NAMES:
            return None
        if name.lower().endswith(self._CORPUS_SKIP_SUFFIXES):
            return None

        try:
            size = path.stat().st_size
        except OSError:
            return None
        if size == 0 or size > self.config.corpus_max_bytes:
            return None

        return {'filename': name, 'path': str(path), 'type': self._classify_corpus_path(path)}

    # Well-known public corpora whose contents are not described by their paths.
    # untroubled.org publishes a spam archive laid out by date, so nothing in a
    # message's path says what it is.
    _CORPUS_KNOWN_COLLECTIONS = {
        'untroubled': 'spam',
        'enron': 'clean',
    }

    @classmethod
    def _classify_corpus_path(cls, path: Path) -> str:
        """Classify a message from its location.

        Public corpora encode ham and spam in directory names — easy_ham,
        hard_ham, spam_2 — rather than in the filename, which is what an
        earlier filename-prefix check assumed. Where the layout says nothing,
        a small table of known collections fills the gap, and anything
        unrecognised is reported as "other" rather than guessed at.
        """
        parts = [p.lower() for p in path.parts]

        for part in reversed(parts):
            if 'virus' in part:
                return 'virus'
            if 'spam' in part:
                return 'spam'
            if 'ham' in part:
                return 'clean'

        for part in parts:
            if part in cls._CORPUS_KNOWN_COLLECTIONS:
                return cls._CORPUS_KNOWN_COLLECTIONS[part]

        if 'maildir' in parts:
            return 'clean'
        return 'other'

    def _read_corpus_message(self, entry: dict):
        """Read one indexed message, returning (text, bytes) or None."""
        try:
            with open(entry['path'], 'rb') as f:
                content_bytes = f.read()
        except OSError:
            return None

        if not content_bytes or not content_bytes.strip():
            return None

        for encoding in ('utf-8', 'latin-1', 'cp1252'):
            try:
                return content_bytes.decode(encoding), content_bytes
            except UnicodeDecodeError:
                continue
        return None

    def _generate_auth_users(self):
        """Generate pool of authenticated test users"""
        if not self.config.use_authentication:
            return
        
        for i in range(1, self.config.auth_user_count + 1):
            user_num = f"{i:02d}"  # Zero-pad (01, 02, etc.)
            username = f"{self.config.auth_user_prefix}{user_num}"
            email = f"{username}@{self.config.auth_domain}"
            
            self.auth_users.append({
                'username': username,
                'email': email,
                'password': self.config.auth_password
            })
        
        print(f"👥 Generated {len(self.auth_users)} authenticated users for stress testing")
        print(f"   Pattern: {self.config.auth_user_prefix}01@{self.config.auth_domain} - {self.config.auth_user_prefix}{self.config.auth_user_count:02d}@{self.config.auth_domain}")
    
    def _get_auth_user(self) -> dict:
        """Get next authenticated user from pool (round-robin)"""
        if not self.auth_users:
            return {
                'username': f"stress{threading.current_thread().ident}@example.com",
                'email': f"stress{threading.current_thread().ident}@example.com",
                'password': ''
            }
        
        user = self.auth_users[self.user_index % len(self.auth_users)]
        self.user_index += 1
        return user
    
    def _get_recipient_email(self, thread_id: int) -> str:
        """Get a valid recipient email address"""
        # Use existing test users as recipients
        valid_recipients = [
            'recipient@example.com',
            'user@example.com', 
            'demo@example.com',
            'sender@example.com'
        ]
        
        # Add stress users as recipients too
        for i in range(1, 21):
            valid_recipients.append(f'stressuser{i:02d}@example.com')
        
        # Use thread_id to select recipient consistently
        import random
        random.seed(thread_id)  # Ensure same thread uses same recipient
        return random.choice(valid_recipients)
    
    def _is_expected_outcome(self, email_type: str, smtp_code: int, error_message: str = "") -> bool:
        """Determine if the SMTP response matches the expected outcome for the email type"""
        if email_type == 'clean':
            # Clean emails should be accepted (250)
            return smtp_code == 250
        elif email_type in ['spam', 'virus']:
            # Spam/virus emails should be rejected at SMTP time (550, 554, 552)
            # If server accepts them (250), that's NOT expected rejection
            return smtp_code in [550, 554, 552]
        else:
            # Other emails - assume they should be accepted
            return smtp_code == 250
    
    def _verify_smtp_connection(self) -> bool:
        """Verify SMTP server is reachable before starting stress test"""
        try:
            print(f"🔍 Verifying SMTP connection to {self.config.target_host}:{self.config.target_port}")
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
            
            if self.config.use_tls:
                server.starttls()
            
            if self.config.use_authentication and self.config.username:
                server.login(self.config.username, self.config.password)
            
            server.quit()
            print(f"✅ SMTP connection verified")
            return True
            
        except Exception as e:
            print(f"❌ SMTP connection failed: {e}")
            print(f"   Please check:")
            print(f"   - SMTP server is running at {self.config.target_host}:{self.config.target_port}")
            print(f"   - Network connectivity is working")
            print(f"   - Authentication credentials are correct (if provided)")
            return False
    
    def _verify_authentication(self) -> bool:
        """Verify that at least one authenticated user can successfully authenticate"""
        if not self.config.use_authentication:
            print(f"ℹ️  Authentication disabled - skipping user verification")
            return True
        
        if not self.auth_users:
            print(f"❌ No authenticated users configured")
            return False
        
        try:
            # Test authentication with the first user
            test_user = self.auth_users[0]
            print(f"🔍 Verifying authentication with user: {test_user['username']}")
            
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
            
            if self.config.use_tls:
                server.starttls()
            
            server.login(test_user['username'], test_user['password'])
            server.quit()
            
            print(f"✅ Authentication verified for user: {test_user['username']}")
            print(f"   Ready to use {len(self.auth_users)} users: {self.auth_users[0]['username']} - {self.auth_users[-1]['username']}")
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed for user {test_user['username']}: {e}")
            print(f"   Please check:")
            print(f"   - LDAP users exist in your directory")
            print(f"   - Password is correct for all users")
            print(f"   - LDAP authentication is properly configured")
            print(f"")
            print(f"   To create LDAP users, use this LDIF:")
            print(f"   (See instructions in README_stress_test.md)")
            return False
    
    def _get_email_content(self, thread_id: int, email_id: int, auth_user: dict = None) -> tuple:
        """Get email content and type - either from corpus or synthetic with RFC 5322 compliance"""
        if self.config.use_corpus and self.corpus_files:
            # Pick an indexed message and read it now. The index holds paths
            # only, so a corpus far larger than memory can be used.
            import random
            corpus_file = None
            content = content_bytes = None
            for _ in range(5):  # a few retries in case a file is unreadable
                with self.corpus_lock:
                    candidate = random.choice(self.corpus_files)
                loaded = self._read_corpus_message(candidate)
                if loaded is not None:
                    corpus_file = candidate
                    content, content_bytes = loaded
                    break

            if corpus_file is not None:
                email_type = corpus_file['type']

                # Use authenticated user's email if available, otherwise fallback
                from_email = auth_user['email'] if auth_user else f"stress{thread_id}@example.com"

                try:
                    # Parse email using proper RFC 5322 parser with SMTPUTF8 policy for UTF-8 support
                    from email.parser import BytesParser
                    parser = BytesParser(policy=policy.SMTPUTF8)
                    msg = parser.parsebytes(content_bytes)
                        
                    # Rewrite the headers this test needs to control: envelope
                    # routing, and an identifiable subject and Message-ID.
                    _set_unique_header(msg, 'From', from_email)
                    _set_unique_header(msg, 'To', self._get_recipient_email(thread_id))
                    _set_unique_header(msg, 'Subject',
                                       f"Stress Test - T{thread_id} - E{email_id} - {email_type.upper()} - {time.time()}")
                    _set_unique_header(msg, 'Message-ID',
                                       f"<stress-{thread_id}-{email_id}-{int(time.time())}@example.com>")
                    _set_unique_header(msg, 'Date', time.ctime())

                    # Ensure proper UTF-8 charset in Content-Type header
                    content_type = str(msg.get('Content-Type') or '')
                    if not content_type:
                        _set_unique_header(msg, 'Content-Type', 'text/plain; charset=utf-8')
                    elif 'charset=' not in content_type.lower():
                        _set_unique_header(msg, 'Content-Type', content_type + '; charset=utf-8')
                        
                    # Return properly formatted email message object and type
                    return msg, email_type
                        
                except Exception as e:
                    # Record rather than print: one bad file is picked many
                    # times per run, and the summary at the end says which.
                    with self.corpus_fallback_lock:
                        key = (corpus_file['filename'], str(e))
                        self.corpus_fallbacks[key] = self.corpus_fallbacks.get(key, 0) + 1
                        
                    # Fallback to simple string replacement if parsing fails
                    lines = content.split('\n')
                    updated_lines = []
                        
                    for line in lines:
                        line_stripped = line.strip()
                        if line_stripped.startswith('From:'):
                            updated_lines.append(f"From: {from_email}")
                        elif line_stripped.startswith('To:'):
                            updated_lines.append(f"To: {self._get_recipient_email(thread_id)}")
                        elif line_stripped.startswith('Subject:'):
                            updated_lines.append(f"Subject: Stress Test - T{thread_id} - E{email_id} - {time.time()}")
                        elif line_stripped.startswith('Message-ID:'):
                            updated_lines.append(f"Message-ID: <stress-{thread_id}-{email_id}-{int(time.time())}@example.com>")
                        elif line_stripped.startswith('Date:'):
                            updated_lines.append(f"Date: {time.ctime()}")
                        else:
                            updated_lines.append(line)
                        
                    # Create proper email message object from fallback content
                    # Rebuild with CRLF. Splitting on '\n' leaves the '\r' on
                    # untouched lines but strips it from rewritten ones, so the
                    # old join produced a message with mixed line endings —
                    # which a server enforcing RFC 5321 CRLF will refuse, making
                    # the fallback look like a server bug.
                    fallback_content = '\r\n'.join(line.rstrip('\r') for line in updated_lines)
                    fallback_msg = Parser(policy=policy.SMTP).parsestr(fallback_content)
                    return fallback_msg, email_type
        
        # Fallback to synthetic content
        synthetic_content = self._generate_message_content(self.config.message_size_bytes)
        synthetic_msg = Parser(policy=policy.SMTP).parsestr(f"From: stress{thread_id}@example.com\nTo: target@example.com\nSubject: Synthetic Test - {time.time()}\n\n{synthetic_content}")
        return synthetic_msg, 'clean'
    
    def _monitor_system_resources(self):
        """Monitor system resources during stress test"""
        if not self.config.monitor_system_resources:
            return
            
        while not self.stop_event.is_set():
            try:
                # Get network I/O stats with graceful degradation
                network_io_mb = 0
                file_descriptors = 0
                
                try:
                    net_io = psutil.net_io_counters()
                    network_io_mb = (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024
                except:
                    pass  # Network monitoring not available
                
                try:
                    file_descriptors = psutil.Process().num_fds()
                except:
                    try:
                        file_descriptors = len(psutil.Process().connections())
                    except:
                        pass  # File descriptor monitoring not available
                
                metrics = SystemMetrics(
                    timestamp=time.time(),
                    cpu_percent=psutil.cpu_percent(interval=0.1),
                    memory_percent=psutil.virtual_memory().percent,
                    memory_used_mb=psutil.virtual_memory().used / 1024 / 1024,
                    active_connections=self.current_connections,
                    threads_count=threading.active_count(),
                    network_io_mb=network_io_mb,
                    file_descriptors=file_descriptors
                )
                
                with self.lock:
                    self.system_metrics.append(metrics)
                
                time.sleep(0.5)  # Collect metrics more frequently for burst analysis
                
            except Exception as e:
                print(f"⚠️  Error monitoring system resources: {e}")
                break
    
    def _generate_message_content(self, size_bytes: int) -> str:
        """Generate message content of specified size"""
        base_content = "This is a stress test message. "
        repetitions = max(1, size_bytes // len(base_content))
        content = base_content * repetitions
        
        # Trim to exact size
        if len(content) > size_bytes:
            content = content[:size_bytes]
        
        return content
    
    def _send_standard_email(self, thread_id: int, email_id: int) -> Tuple[float, bool, str]:
        """Send a standard email using corpus content with authentication"""
        start_time = time.time()
        
        try:
            # Increment connection counter
            with self.connection_lock:
                self.current_connections += 1
            
            # Get authenticated user for this request
            auth_user = self._get_auth_user()
            
            # Get email content and type from corpus or synthetic
            email_content, email_type = self._get_email_content(thread_id, email_id, auth_user)
            
            # Always use fresh connections when using user rotation (disable pooling)
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
            
            if self.config.use_tls:
                server.starttls()
            
            if self.config.use_authentication:
                server.login(auth_user['username'], auth_user['password'])
            
            try:
                server.sendmail(auth_user['email'],
                              [self._get_recipient_email(thread_id)],
                              email_content.as_bytes(policy=policy.SMTPUTF8),
                              mail_options=['SMTPUTF8'])
            except UnicodeEncodeError as e:
                server.quit()
                duration = time.time() - start_time
                return (duration, False, f"Unicode encoding error: {str(e)} (skipping email)")
            
            server.quit()
            
            duration = time.time() - start_time
            return (duration, True, f"Success (auth: {auth_user['username']}, type: {email_type})")
            
        except smtplib.SMTPResponseException as e:
            duration = time.time() - start_time
            # Check if this rejection is expected for the email type
            expected_outcome = self._is_expected_outcome(email_type, e.smtp_code, str(e))
            return (duration, expected_outcome, f"SMTP {e.smtp_code}: {str(e)} (expected: {expected_outcome}, type: {email_type})")
        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
        
        finally:
            # Decrement connection counter
            with self.connection_lock:
                self.current_connections -= 1
    
    def _send_slow_client_email(self, thread_id: int, email_id: int) -> Tuple[float, bool, str]:
        """Send email with slow client behavior using corpus content with authentication"""
        start_time = time.time()
        
        try:
            with self.connection_lock:
                self.current_connections += 1
            
            # Get authenticated user for this request
            auth_user = self._get_auth_user()
            
            # Get email content and type from corpus or synthetic
            email_content, email_type = self._get_email_content(thread_id, email_id, auth_user)
            
            # Connect with delays
            time.sleep(self.config.slow_read_delay)  # Delay before connection
            
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=30)
            
            # Add delays between SMTP operations
            time.sleep(self.config.slow_read_delay)
            
            if self.config.use_tls:
                server.starttls()
                time.sleep(self.config.slow_read_delay)
            
            if self.config.use_authentication:
                server.login(auth_user['username'], auth_user['password'])
                time.sleep(self.config.slow_read_delay)
            
            # Slow send
            time.sleep(self.config.slow_read_delay)
            try:
                server.sendmail(auth_user['email'],
                              [self._get_recipient_email(thread_id)],
                              email_content.as_bytes(policy=policy.SMTPUTF8),
                              mail_options=['SMTPUTF8'])
            except UnicodeEncodeError as e:
                server.quit()
                duration = time.time() - start_time
                return (duration, False, f"Unicode encoding error: {str(e)} (skipping email)")
            
            time.sleep(self.config.slow_read_delay)
            server.quit()
            
            duration = time.time() - start_time
            return (duration, True, f"Success (slow client, auth: {auth_user['username']}, type: {email_type})")
            
        except smtplib.SMTPResponseException as e:
            duration = time.time() - start_time
            # Check if this rejection is expected for the email type
            expected_outcome = self._is_expected_outcome(email_type, e.smtp_code, str(e))
            return (duration, expected_outcome, f"SMTP {e.smtp_code}: {str(e)} (expected: {expected_outcome}, type: {email_type})")
        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
        
        finally:
            with self.connection_lock:
                self.current_connections -= 1
    
    def _send_malformed_email(self, thread_id: int, email_id: int) -> Tuple[float, bool, str]:
        """Send email with malformed SMTP commands"""
        start_time = time.time()
        
        try:
            with self.connection_lock:
                self.current_connections += 1
            
            # Connect and send malformed commands
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
            
            # Send various malformed commands.
            #
            # Note: a command containing CR/LF cannot be tested through
            # smtplib. Since CVE-2016-0772 its docmd refuses to transmit one,
            # raising "command and arguments contain prohibited newline
            # characters" client-side, so the server never sees it and the
            # attempt is scored as a failure. Newline injection is worth
            # exercising, but it needs a raw socket rather than smtplib; see
            # the SMTP smuggling tests in internal/smtp for that coverage.
            malformed_commands = [
                "INVALID_COMMAND",
                "HELO",
                "MAIL FROM: invalid-format",
                "RCPT TO: malformed<>address",
                "DATA",
                "MAIL FROM:<unclosed@example.com",
                "RCPT TO:<>@bad",
            ]

            command = random.choice(malformed_commands)

            # docmd returns (code, message); it does not raise on a 4xx/5xx
            # reply. The point of this scenario is that the server rejects
            # malformed input, so a 4xx/5xx is the pass condition and a 2xx is
            # the failure.
            #
            # This used to be wrapped in `except smtplib.SMTPServerException`,
            # which is not a name smtplib defines. Every rejection therefore
            # raised AttributeError, fell through to the generic handler and
            # was recorded as a failed message, so a correctly hardened server
            # scored badly on this scenario.
            try:
                code, _ = server.docmd(command)
            except smtplib.SMTPServerDisconnected:
                # Also expected: the server drops sessions that exceed its
                # protocol-error limit rather than letting them continue.
                duration = time.time() - start_time
                return (duration, True, f"Connection closed after malformed command: {command}")

            duration = time.time() - start_time
            if code >= 400:
                return (duration, True, f"Malformed command rejected as expected ({code}): {command}")
            return (duration, False, f"Malformed command accepted ({code}): {command}")

        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
        
        finally:
            with self.connection_lock:
                self.current_connections -= 1
    
    def _send_pipelined_email(self, thread_id: int, email_id: int) -> Tuple[float, bool, str]:
        """Send email using SMTP pipelining with corpus content and authentication"""
        start_time = time.time()
        
        try:
            with self.connection_lock:
                self.current_connections += 1
            
            # Get authenticated user for this request
            auth_user = self._get_auth_user()
            
            # Create multiple messages using corpus content
            messages = []
            email_types = []
            for i in range(3):  # Send 3 messages in pipeline
                email_content, email_type = self._get_email_content(thread_id, f"{email_id}-{i}", auth_user)
                messages.append(email_content)
                email_types.append(email_type)
            
            # Connect and pipeline
            server = smtplib.SMTP(self.config.target_host, self.config.target_port, timeout=10)
            
            if self.config.use_authentication:
                server.login(auth_user['username'], auth_user['password'])
            
            # Send all messages rapidly (pipelining simulation)
            for msg_content in messages:
                try:
                    server.sendmail(auth_user['email'],
                                  [self._get_recipient_email(thread_id)],
                                  msg_content.as_bytes(policy=policy.SMTPUTF8),
                                  mail_options=['SMTPUTF8'])
                except UnicodeEncodeError as e:
                    # Skip problematic message but continue with others
                    continue
            
            server.quit()
            
            duration = time.time() - start_time
            return (duration, True, f"Success (pipelined {len(messages)} messages, auth: {auth_user['username']}, types: {', '.join(email_types)})")
            
        except smtplib.SMTPResponseException as e:
            duration = time.time() - start_time
            # Check if this rejection is expected for the email type (use first email type for pipelined results)
            first_email_type = email_types[0] if email_types else 'clean'
            expected_outcome = self._is_expected_outcome(first_email_type, e.smtp_code, str(e))
            return (duration, expected_outcome, f"SMTP {e.smtp_code}: {str(e)} (expected: {expected_outcome}, types: {', '.join(email_types)})")
        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
        
        finally:
            with self.connection_lock:
                self.current_connections -= 1
    
    def _send_single_email(self, thread_id: int, email_id: int) -> Tuple[float, bool, str]:
        """Dispatch email sending based on configuration"""
        # Determine which testing method to use
        if self.config.malformed_commands:
            return self._send_malformed_email(thread_id, email_id)
        elif self.config.slow_client_mode:
            return self._send_slow_client_email(thread_id, email_id)
        elif self.config.use_pipelining:
            return self._send_pipelined_email(thread_id, email_id)
        else:
            return self._send_standard_email(thread_id, email_id)
    
    def _worker_thread(self, thread_id: int):
        """Worker thread that continuously sends emails until stop event"""
        email_id = 0
        
        while not self.stop_event.is_set():
            try:
                # Add small delay to prevent overwhelming
                time.sleep(0.01)
                
                duration, success, msg = self._send_single_email(thread_id, email_id)
                
                with self.lock:
                    self.results.append((duration, success, msg))
                
                email_id += 1
                
            except Exception as e:
                print(f"⚠️  Thread {thread_id} error: {e}")
                break
    
    def _calculate_current_connections(self, elapsed_time: float) -> int:
        """Calculate current number of connections based on ramp-up"""
        if elapsed_time >= self.config.ramp_up_time:
            return self.config.max_concurrent_connections
        
        # Linear ramp-up
        progress = elapsed_time / self.config.ramp_up_time
        current = int(self.config.min_concurrent_connections + 
                     (self.config.max_concurrent_connections - self.config.min_concurrent_connections) * progress)
        
        return min(current, self.config.max_concurrent_connections)
    
    def _should_send_burst(self, elapsed_time: float) -> bool:
        """Check if we should send a burst of traffic"""
        if not self.config.burst_mode:
            return False
        
        cycle_time = elapsed_time % self.config.burst_interval
        return cycle_time < self.config.burst_duration
    
    def _dynamic_connection_manager(self):
        """Dynamically adjust connection count based on test phase"""
        start_time = time.time()
        
        while not self.stop_event.is_set():
            elapsed_time = time.time() - start_time
            
            # Calculate target connections
            if self._should_send_burst(elapsed_time):
                target_connections = self.config.max_concurrent_connections * 2  # Double during bursts
            else:
                target_connections = self._calculate_current_connections(elapsed_time)
            
            # Adjust thread pool size if needed (this is simplified)
            # In a real implementation, you'd manage a dynamic thread pool
            
            time.sleep(1)  # Check every second
    
    def run_stress_test(self) -> StressTestResults:
        """Run the comprehensive stress test"""
        print("🚀 Starting SMTP Stress Test")
        print(f"⏱️  Duration: {self.config.duration_seconds}s")
        print(f"🔗 Max Connections: {self.config.max_concurrent_connections}")
        print(f"📈 Ramp-up Time: {self.config.ramp_up_time}s")
        print(f"📧 Message Size: {self.config.message_size_bytes} bytes")
        print(f"🎯 Target: {self.config.target_host}:{self.config.target_port}")
        
        if self.config.burst_mode:
            print(f"💥 Burst Mode: {self.config.burst_interval}s intervals, {self.config.burst_duration}s duration")
        
        if self.config.use_corpus:
            print(f"📧 Using corpus files from: {self.config.corpus_dir}")
        
        # Verify SMTP connection before starting
        if not self._verify_smtp_connection():
            raise Exception("SMTP connection verification failed")
        
        # Verify authentication if enabled
        if not self._verify_authentication():
            raise Exception("Authentication verification failed")
        
        self.start_time = datetime.now()
        start_timestamp = time.time()
        
        # Start system monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_system_resources)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start dynamic connection manager
        manager_thread = threading.Thread(target=self._dynamic_connection_manager)
        manager_thread.daemon = True
        manager_thread.start()
        
        # Start with minimum connections and ramp up
        initial_connections = self.config.min_concurrent_connections
        executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_connections)
        
        # Submit initial worker threads
        futures = []
        for i in range(initial_connections):
            future = executor.submit(self._worker_thread, i)
            futures.append(future)
        
        print(f"📊 Started with {initial_connections} connections...")
        
        # Main test loop - manage connections dynamically
        last_connection_count = initial_connections
        next_thread_id = initial_connections
        
        try:
            while time.time() - start_timestamp < self.config.duration_seconds and not self.stop_event.is_set():
                elapsed_time = time.time() - start_timestamp
                
                # Calculate desired connection count
                if self._should_send_burst(elapsed_time):
                    desired_connections = min(self.config.max_concurrent_connections * 2, 
                                            self.config.max_concurrent_connections + 50)
                else:
                    desired_connections = self._calculate_current_connections(elapsed_time)
                
                # Add connections if needed
                if desired_connections > last_connection_count:
                    connections_to_add = desired_connections - last_connection_count
                    print(f"📈 Adding {connections_to_add} connections (total: {desired_connections})")
                    
                    for i in range(connections_to_add):
                        if len(futures) < self.config.max_concurrent_connections:
                            future = executor.submit(self._worker_thread, next_thread_id)
                            futures.append(future)
                            next_thread_id += 1
                
                # Remove connections if needed (simplified - would need proper thread management)
                elif desired_connections < last_connection_count:
                    connections_to_remove = last_connection_count - desired_connections
                    print(f"📉 Removing {connections_to_remove} connections (total: {desired_connections})")
                    # In practice, you'd signal threads to stop gracefully
                
                last_connection_count = desired_connections
                
                # Progress indicator
                progress = (elapsed_time / self.config.duration_seconds) * 100
                current_rate = len(self.results) / elapsed_time if elapsed_time > 0 else 0
                
                print(f"⏰ Progress: {progress:.1f}% | Rate: {current_rate:.1f} msg/s | "
                      f"Connections: {last_connection_count} | Active: {self.current_connections}")
                
                time.sleep(5)  # Adjust every 5 seconds
        
        except KeyboardInterrupt:
            print("\n⚠️  Test interrupted by user")
        
        finally:
            # Stop all threads
            self.stop_event.set()
            
            # Wait for all futures to complete or timeout
            for future in futures:
                try:
                    future.result(timeout=5)
                except:
                    pass
            
            executor.shutdown(wait=True)
        
        self.end_time = datetime.now()
        total_duration = time.time() - start_timestamp
        
        print(f"\n🏁 Stress test completed in {total_duration:.2f}s")
        
        # Analyze results
        return self._analyze_results(total_duration)
    
    def _analyze_results(self, total_duration: float) -> StressTestResults:
        """Analyze test results and generate comprehensive report"""
        successful_emails = [r for r in self.results if r[1]]
        failed_emails = [r for r in self.results if not r[1]]
        
        response_times = [r[0] for r in successful_emails]
        
        # Calculate error counts
        error_counts = {}
        for _, _, error in failed_emails:
            error_counts[error] = error_counts.get(error, 0) + 1
        
        # Analyze categorized metrics by parsing email types from messages
        import re
        categorized_metrics = {
            'clean_sent': 0, 'clean_accepted': 0,
            'spam_sent': 0, 'spam_rejected': 0, 
            'virus_sent': 0, 'virus_rejected': 0,
            'other_sent': 0, 'other_accepted': 0
        }
        
        for _, success, message in self.results:
            # Extract email type from message using regex
            type_match = re.search(r'type:\s*(\w+)', message.lower())
            email_type = type_match.group(1) if type_match else 'other'
            
            # Increment sent counter
            sent_key = f'{email_type}_sent'
            if sent_key in categorized_metrics:
                categorized_metrics[sent_key] += 1
            
            # Increment accepted/rejected counter based on actual SMTP response
            if email_type == 'clean':
                if success:  # Clean emails accepted at SMTP time
                    categorized_metrics['clean_accepted'] += 1
            elif email_type in ['spam', 'virus']:
                if success:  # Spam/virus accepted at SMTP time (NOT rejected)
                    if email_type == 'spam':
                        categorized_metrics['spam_accepted'] = categorized_metrics.get('spam_accepted', 0) + 1
                    else:
                        categorized_metrics['virus_accepted'] = categorized_metrics.get('virus_accepted', 0) + 1
                else:  # Spam/virus actually rejected at SMTP time
                    if email_type == 'spam':
                        categorized_metrics['spam_rejected'] += 1
                    else:
                        categorized_metrics['virus_rejected'] += 1
            else:  # other
                if success:
                    categorized_metrics['other_accepted'] += 1
        
        # Calculate percentiles
        if response_times:
            percentile_50 = statistics.quantiles(response_times, n=100)[49]  # 50th percentile
            percentile_95 = statistics.quantiles(response_times, n=100)[94]  # 95th percentile
            percentile_99 = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
        else:
            percentile_50 = percentile_95 = percentile_99 = 0
        
        results = StressTestResults(
            config=self.config,
            start_time=self.start_time,
            end_time=self.end_time,
            total_duration=total_duration,
            total_emails_sent=len(self.results),
            successful_emails=len(successful_emails),
            failed_emails=len(failed_emails),
            emails_per_second=len(self.results) / total_duration if total_duration > 0 else 0,
            response_times=response_times,
            error_counts=error_counts,
            system_metrics=self.system_metrics,
            percentile_50=percentile_50,
            percentile_95=percentile_95,
            percentile_99=percentile_99,
            max_response_time=max(response_times) if response_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            # Categorized metrics
            clean_sent=categorized_metrics['clean_sent'],
            clean_accepted=categorized_metrics['clean_accepted'],
            spam_sent=categorized_metrics['spam_sent'],
            spam_accepted=categorized_metrics.get('spam_accepted', 0),
            spam_rejected=categorized_metrics['spam_rejected'],
            virus_sent=categorized_metrics['virus_sent'],
            virus_accepted=categorized_metrics.get('virus_accepted', 0),
            virus_rejected=categorized_metrics['virus_rejected'],
            other_sent=categorized_metrics['other_sent'],
            other_accepted=categorized_metrics['other_accepted']
        )
        
        return results
    
    def print_results(self, results: StressTestResults):
        """Print comprehensive test results"""
        print("\n" + "="*80)
        print("📊 STRESS TEST RESULTS")
        print("="*80)
        
        print(f"\n📅 Test Duration: {results.start_time} to {results.end_time}")
        print(f"⏱️  Total Duration: {results.total_duration:.2f}s")
        
        print(f"\n📧 EMAIL STATISTICS:")
        print(f"   Total Sent:        {results.total_emails_sent:,}")
        print(f"   Successful:        {results.successful_emails:,}")
        print(f"   Failed:            {results.failed_emails:,}")
        print(f"   Success Rate:      {(results.successful_emails/results.total_emails_sent*100):.2f}%")
        print(f"   Throughput:        {results.emails_per_second:.2f} messages/second")
        
        # Show categorized metrics if corpus was used
        total_categorized = results.clean_sent + results.spam_sent + results.virus_sent + results.other_sent
        if total_categorized > 0:
            print(f"\n📊 EMAIL TYPE BREAKDOWN:")
            if results.clean_sent > 0:
                clean_rate = (results.clean_accepted / results.clean_sent * 100) if results.clean_sent > 0 else 0
                print(f"   Clean Delivery:    {clean_rate:.1f}% ({results.clean_accepted}/{results.clean_sent} accepted)")
            if results.spam_sent > 0:
                if results.spam_rejected > 0:
                    spam_rejected_rate = (results.spam_rejected / results.spam_sent * 100) if results.spam_sent > 0 else 0
                    print(f"   Spam Rejected:     {spam_rejected_rate:.1f}% ({results.spam_rejected}/{results.spam_sent} rejected at SMTP)")
                if results.spam_accepted > 0:
                    spam_accepted_rate = (results.spam_accepted / results.spam_sent * 100) if results.spam_sent > 0 else 0
                    print(f"   Spam Accepted:     {spam_accepted_rate:.1f}% ({results.spam_accepted}/{results.spam_sent} accepted at SMTP)")
            if results.virus_sent > 0:
                if results.virus_rejected > 0:
                    virus_rejected_rate = (results.virus_rejected / results.virus_sent * 100) if results.virus_sent > 0 else 0
                    print(f"   Virus Rejected:    {virus_rejected_rate:.1f}% ({results.virus_rejected}/{results.virus_sent} rejected at SMTP)")
                if results.virus_accepted > 0:
                    virus_accepted_rate = (results.virus_accepted / results.virus_sent * 100) if results.virus_sent > 0 else 0
                    print(f"   Virus Accepted:    {virus_accepted_rate:.1f}% ({results.virus_accepted}/{results.virus_sent} accepted at SMTP)")
            if results.other_sent > 0:
                other_rate = (results.other_accepted / results.other_sent * 100) if results.other_sent > 0 else 0
                print(f"   Other Delivery:     {other_rate:.1f}% ({results.other_accepted}/{results.other_sent} accepted)")
        
        print(f"\n⚡ RESPONSE TIME STATISTICS:")
        print(f"   Average:           {statistics.mean(results.response_times):.3f}s" if results.response_times else "   Average:           N/A")
        print(f"   Median:            {statistics.median(results.response_times):.3f}s" if results.response_times else "   Median:            N/A")
        print(f"   Min:               {results.min_response_time:.3f}s")
        print(f"   Max:               {results.max_response_time:.3f}s")
        print(f"   50th Percentile:   {results.percentile_50:.3f}s")
        print(f"   95th Percentile:   {results.percentile_95:.3f}s")
        print(f"   99th Percentile:   {results.percentile_99:.3f}s")
        
        if getattr(self, 'corpus_fallbacks', None):
            total = sum(self.corpus_fallbacks.values())
            print(f"\n📄 CORPUS FALLBACKS: {total} send(s) across {len(self.corpus_fallbacks)} file(s)")
            print("   These messages could not be rewritten and were sent in a degraded form.")
            for (filename, reason), count in sorted(self.corpus_fallbacks.items(), key=lambda x: -x[1])[:10]:
                print(f"   {count:6d}  {filename}: {reason}")

        if results.error_counts:
            print(f"\n❌ ERROR ANALYSIS:")
            for error, count in sorted(results.error_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"   {error}: {count} occurrences")
        
        if results.system_metrics:
            print(f"\n🖥️  SYSTEM RESOURCE USAGE:")
            avg_cpu = statistics.mean([m.cpu_percent for m in results.system_metrics])
            max_cpu = max([m.cpu_percent for m in results.system_metrics])
            avg_memory = statistics.mean([m.memory_percent for m in results.system_metrics])
            max_memory = max([m.memory_percent for m in results.system_metrics])
            max_connections = max([m.active_connections for m in results.system_metrics])
            
            print(f"   CPU Usage:         Avg {avg_cpu:.1f}% | Max {max_cpu:.1f}%")
            print(f"   Memory Usage:      Avg {avg_memory:.1f}% | Max {max_memory:.1f}%")
            print(f"   Max Connections:   {max_connections}")
    
    def save_results(self, results: StressTestResults, filename: str):
        """Save results to JSON file"""
        # Convert dataclass to dict and handle datetime serialization
        results_dict = asdict(results)
        results_dict['start_time'] = results.start_time.isoformat()
        results_dict['end_time'] = results.end_time.isoformat()
        results_dict['system_metrics'] = [asdict(m) for m in results.system_metrics]
        
        with open(filename, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        print(f"💾 Results saved to {filename}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SMTP Stress Test Tool')
    
    # Basic options
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='Test duration in seconds (default: 300)')
    parser.add_argument('--max-connections', '-c', type=int, default=100,
                       help='Maximum concurrent connections (default: 100)')
    parser.add_argument('--min-connections', type=int, default=10,
                       help='Minimum concurrent connections (default: 10)')
    parser.add_argument('--ramp-up', type=int, default=30,
                       help='Ramp-up time in seconds (default: 30)')
    parser.add_argument('--message-size', type=int, default=1024,
                       help='Message size in bytes (default: 1024)')
    parser.add_argument('--host', default='localhost',
                       help='Target host (default: localhost)')
    parser.add_argument('--port', '-p', type=int, default=2525,
                       help='Target port (default: 2525)')
    
    # Authentication options
    parser.add_argument('--username', help='SMTP username for authentication')
    parser.add_argument('--password', help='SMTP password for authentication')
    
    # Traffic pattern options
    parser.add_argument('--burst-mode', action='store_true',
                       help='Enable burst mode traffic patterns')
    parser.add_argument('--burst-interval', type=int, default=30,
                       help='Burst interval in seconds (default: 30)')
    parser.add_argument('--burst-duration', type=int, default=5,
                       help='Burst duration in seconds (default: 5)')
    
    # Advanced testing options
    parser.add_argument('--use-tls', action='store_true',
                       help='Use TLS/STARTTLS for connections')
    parser.add_argument('--connection-reuse', action='store_true', default=True,
                       help='Use connection reuse (default: enabled)')
    parser.add_argument('--no-connection-reuse', dest='connection_reuse', action='store_false',
                       help='Disable connection reuse')
    parser.add_argument('--messages-per-connection', type=int, default=10,
                       help='Messages per connection when reuse enabled (default: 10)')
    parser.add_argument('--pipelining', action='store_true',
                       help='Enable SMTP pipelining testing')
    parser.add_argument('--slow-client', action='store_true',
                       help='Enable slow client behavior testing')
    parser.add_argument('--slow-delay', type=float, default=0.1,
                       help='Delay in seconds for slow client mode (default: 0.1)')
    parser.add_argument('--malformed', action='store_true',
                       help='Enable malformed SMTP command testing')
    parser.add_argument('--auth-failure-rate', type=float, default=0.0,
                       help='Rate of intentional auth failures (0.0-1.0, default: 0.0)')
    
    # Email content options
    parser.add_argument('--corpus-dir', default='tests/corpus',
                       help='Directory containing email files (default: tests/corpus)')
    parser.add_argument('--corpus-limit', type=int, default=20000,
                        help='Maximum number of corpus messages to index; 0 for no limit (default: 20000)')
    parser.add_argument('--no-corpus', dest='use_corpus', action='store_false', default=True,
                       help='Disable corpus file usage and use synthetic content')
    
    # Realistic scenario option
    parser.add_argument('--realistic', action='store_true',
                       help='Enable realistic production scenario with optimal settings')
    
    # Authentication options
    parser.add_argument('--auth-user-prefix', default='stressuser',
                       help='Prefix for test users (default: stressuser)')
    parser.add_argument('--auth-user-count', type=int, default=20,
                       help='Number of test users to create (default: 20)')
    parser.add_argument('--auth-password', default='testpass123',
                       help='Password for test users (default: testpass123)')
    parser.add_argument('--auth-domain', default='example.com',
                       help='Domain for test users (default: example.com)')
    
    # Monitoring and output options
    parser.add_argument('--no-monitor', action='store_true',
                       help='Disable system resource monitoring')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Validate arguments
    if args.auth_failure_rate < 0.0 or args.auth_failure_rate > 1.0:
        print("❌ Auth failure rate must be between 0.0 and 1.0")
        return 1
    
    if args.slow_delay < 0:
        print("❌ Slow delay must be positive")
        return 1
    
    # Create configuration
    config = StressTestConfig(
        duration_seconds=args.duration,
        max_concurrent_connections=args.max_connections,
        min_concurrent_connections=args.min_connections,
        ramp_up_time=args.ramp_up,
        message_size_bytes=args.message_size,
        target_host=args.host,
        target_port=args.port,
        use_authentication=bool(args.username),
        username=args.username or '',
        password=args.password or '',
        burst_mode=args.burst_mode,
        burst_interval=args.burst_interval,
        burst_duration=args.burst_duration,
        monitor_system_resources=not args.no_monitor,
        output_file=args.output or '',
        # Advanced options
        use_tls=args.use_tls,
        connection_reuse=args.connection_reuse,
        messages_per_connection=args.messages_per_connection,
        use_pipelining=args.pipelining,
        slow_client_mode=args.slow_client,
        slow_read_delay=args.slow_delay,
        malformed_commands=args.malformed,
        auth_failure_rate=args.auth_failure_rate,
        use_corpus=args.use_corpus,
        corpus_dir=args.corpus_dir,
        corpus_limit=args.corpus_limit,
        # Authentication options
        auth_user_prefix=args.auth_user_prefix,
        auth_user_count=args.auth_user_count,
        auth_password=args.auth_password,
        auth_domain=args.auth_domain,
    )
    
    # Apply realistic scenario overrides if requested
    if args.realistic:
        print("🎯 Enabling realistic production scenario...")
        
        # Only override if user didn't explicitly set these values
        if args.message_size == 1024:  # Default value
            config.message_size_bytes = 10240
            print("   ✓ Message size: 10KB (realistic email size)")
        
        if not args.burst_mode:  # User didn't enable burst mode
            config.burst_mode = True
            print("   ✓ Burst mode: Enabled (realistic traffic patterns)")
        
        if args.messages_per_connection == 10:  # Default value
            config.messages_per_connection = 25
            print("   ✓ Messages per connection: 25 (typical client behavior)")
        
        if args.max_connections == 100:  # Default value
            config.max_concurrent_connections = 50
            print("   ✓ Max connections: 50 (medium mail server)")
        
        print("   ✓ Realistic scenario configured!")
    
    # Run stress test
    tester = SMTPStressTester(config)
    
    try:
        results = tester.run_stress_test()
        
        # Print results
        tester.print_results(results)
        
        # Save results if requested
        if args.output:
            tester.save_results(results, args.output)
        
        # Return non-zero exit code if success rate is too low
        if results.total_emails_sent > 0 and results.successful_emails / results.total_emails_sent < 0.95:
            print(f"\n⚠️  Low success rate: {(results.successful_emails/results.total_emails_sent*100):.2f}%")
            return 1
        
        print(f"\n🎉 Stress test completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Stress test interrupted by user")
        return 130  # Standard exit code for SIGINT
    
    except Exception as e:
        print(f"\n❌ Stress test failed: {e}")
        return 1
    
    finally:
        # Ensure proper cleanup
        if tester.connection_pool:
            tester.connection_pool.close_all()

if __name__ == "__main__":
    sys.exit(main())
