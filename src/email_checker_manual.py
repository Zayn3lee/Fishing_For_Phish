import os
import sys
import glob
import re
from email.parser import Parser
from pathlib import Path
from typing import List, Dict, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass

@dataclass
class AnalysisResult:
    """Container for storing results of email security analysis."""
    filename: str
    sender_domain: str
    suspicious_domains: List[Tuple[str, float]]  # (domain, similarity_score)
    extracted_urls: List[str]
    suspicious_urls: List[Dict[str, str]]
    ip_addresses: List[str]
    domain_mismatches: List[Dict[str, str]]
    spam_score: float
    is_suspicious: bool
    word_count: int  # Added word count
    subject: str  # Added subject for reference

class EmailSecurityAnalyzer:
    """
    Performs in-depth security analysis on email content:
    - Detects suspicious sender domains
    - Extracts and analyzes URLs and IPs
    - Identifies domain mismatches and spam indicators
    """

    def __init__(self):
        """Initialize with known good domains and patterns."""
        self.legitimate_domains = {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'amazon.com', 'paypal.com', 'ebay.com', 'google.com',
            'microsoft.com', 'apple.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'instagram.com', 'netflix.com', 'spotify.com',
            'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com',
            'gamasutra.com', 'example.com', 
            'localhost.example.com'
        }

        self.typosquatting_patterns = [
            ('o', '0'), ('i', '1'), ('l', '1'), ('e', '3'),
            ('a', '@'), ('s', '$'), ('g', '9'), ('b', '6'),
            ('l', 'I')  # common confusion
        ]

        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.click', '.download'}

        # Regex for URL extraction
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            re.IGNORECASE
        )

        # Regex for IP extraction
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

        # Regex for email address extraction
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance (edit distance) between two strings."""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]
    
    def detect_typosquatting(self, domain: str) -> List[str]:
        """
        Detect typosquatting attempts by checking for character substitutions
        and homograph-like patterns (e.g., paypaI vs paypal).
        Returns a list of typosquatting alerts.
        """
        alerts = []
        domain_lower = domain.lower()

        # Skip legitimate domains
        if domain_lower in self.legitimate_domains:
            return alerts

        # Normalize domain (remove www. and subdomains)
        core_domain = domain_lower.split('.')[-2] + '.' + domain_lower.split('.')[-1] if '.' in domain_lower else domain_lower

        # Check if it resembles a known good domain
        for legit_domain in self.legitimate_domains:
            legit_core = legit_domain.lower()
            similarity = self.calculate_similarity(core_domain, legit_core)
            if similarity >= 75 and similarity < 100:
                alerts.append(f"Typosquatting suspected: {core_domain} vs {legit_core} ({similarity:.1f}% similarity)")

        # Check for character substitution patterns
        for original, replacement in self.typosquatting_patterns:
            if replacement in domain_lower or original in domain_lower:
                replaced = domain_lower.replace(replacement, original)
                if replaced in self.legitimate_domains:
                    alerts.append(f"Character substitution: '{replacement}' → '{original}' (looks like {replaced})")

        # Homoglyphs: visually similar letters (I vs l, 0 vs O)
        homoglyphs = {'0': 'o', '1': 'l', 'I': 'l'}
        for fake, real in homoglyphs.items():
            if fake in domain_lower:
                possible_fix = domain_lower.replace(fake, real)
                if possible_fix in self.legitimate_domains:
                    alerts.append(f"Homoglyph attack: '{fake}' → '{real}' (could mimic {possible_fix})")

        return alerts


    def calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 100.0
        distance = self.levenshtein_distance(s1.lower(), s2.lower())
        similarity = (1 - distance / max_len) * 100
        return similarity
    
    def extract_domain_from_email(self, email_address: str) -> str:
        """Extract the domain portion from an email address."""
        if '@' in email_address:
            # Handle cases like "Name <email@domain.com>"
            email_part = email_address.split('<')[-1].split('>')[0]
            return email_part.split('@')[-1].strip()
        return email_address.strip('<>')

    def analyze_domain_similarity(self, domain: str, threshold: float = 80.0) -> List[Tuple[str, float]]:
        """Compare domain to legitimate domains and return suspiciously similar ones."""
        suspicious_domains = []
        
        # Skip if domain is already in legitimate domains
        if domain.lower() in [d.lower() for d in self.legitimate_domains]:
            return suspicious_domains

        for legit_domain in self.legitimate_domains:
            similarity = self.calculate_similarity(domain, legit_domain)
            if threshold <= similarity < 100.0:
                suspicious_domains.append((legit_domain, similarity))

        return sorted(suspicious_domains, key=lambda x: x[1], reverse=True)[:5]

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from a given text."""
        return list(set(self.url_pattern.findall(text)))

    def extract_ip_addresses(self, text: str) -> List[str]:
        """Extract and filter public IP addresses from text."""
        ips = self.ip_pattern.findall(text)
        filtered_ips = []
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    first_octet = int(parts[0])
                    if not (
                        first_octet == 127 or  # localhost
                        first_octet == 10 or   # private
                        (first_octet == 172 and 16 <= int(parts[1]) <= 31) or
                        (first_octet == 192 and int(parts[1]) == 168)
                    ):
                        filtered_ips.append(ip)
                except ValueError:
                    filtered_ips.append(ip)
        return list(set(filtered_ips))

    def analyze_url(self, url: str) -> Dict[str, any]:
        """Analyze a single URL and identify any suspicious indicators."""
        analysis = {
            'url': url,
            'domain': '',
            'suspicious_reasons': []
        }

        try:
            parsed = urlparse(url)
            analysis['domain'] = parsed.netloc.lower()

            # Detect direct IP usage in URL
            if self.ip_pattern.match(parsed.netloc):
                analysis['suspicious_reasons'].append('Direct IP address')

            # Check for suspicious TLDs
            domain_parts = parsed.netloc.lower().split('.')
            if len(domain_parts) >= 2:
                tld = '.' + domain_parts[-1]
                if tld in self.suspicious_tlds:
                    analysis['suspicious_reasons'].append(f'Suspicious TLD: {tld}')

            # Too many subdomains
            if len(domain_parts) > 3:
                analysis['suspicious_reasons'].append('Excessive subdomains')

            # Similar to known domains?
            suspicious_domains = self.analyze_domain_similarity(analysis['domain'])
            if suspicious_domains:
                top_match = suspicious_domains[0]
                analysis['suspicious_reasons'].append(
                    f'Similar to {top_match[0]} ({top_match[1]:.1f}% similar)'
                )
            
            # Check for URL shortening patterns
            short_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            if any(short in analysis['domain'] for short in short_domains):
                analysis['suspicious_reasons'].append('URL shortening service')
            # Typosquatting detection
            typo_alerts = self.detect_typosquatting(analysis['domain'])
            if typo_alerts:
                 analysis['suspicious_reasons'].extend(typo_alerts)

        except Exception as e:
            analysis['suspicious_reasons'].append(f'URL parsing error: {str(e)}')
    
        return analysis

    def detect_domain_mismatches(self, text: str, urls: List[str]) -> List[Dict[str, str]]:
        """Detect mismatches between displayed email domains and actual URL domains."""
        mismatches = []
        email_addresses = self.email_pattern.findall(text)

        for email_addr in email_addresses:
            display_domain = self.extract_domain_from_email(email_addr)
            for url in urls:
                try:
                    url_domain = urlparse(url).netloc.lower()
                    if (
                        display_domain.lower() != url_domain and
                        display_domain.lower() not in url_domain and
                        url_domain not in display_domain.lower()
                    ):
                        mismatches.append({
                            'display_text': email_addr,
                            'actual_url': url,
                            'display_domain': display_domain,
                            'url_domain': url_domain
                        })
                except:
                    continue

        return mismatches

    def parse_email_file(self, file_content: str) -> Dict:
        """Parse raw email content and extract metadata - handles both proper email format and simple text."""
        # Try to parse as proper email first
        parser = Parser()
        try:
            email_obj = parser.parsestr(file_content)
            
            # Check if we got valid headers
            from_header = email_obj.get('From', '')
            subject_header = email_obj.get('Subject', '')
            body = self.get_email_body(email_obj)
            
            # If body is empty or very short, try alternative extraction
            if not body or len(body.strip()) < 10:
                body = self.extract_body_from_text(file_content)
            
            return {
                'from': from_header,
                'to': email_obj.get('To', ''),
                'subject': subject_header,
                'date': email_obj.get('Date', ''),
                'content_type': email_obj.get('Content-Type', ''),
                'spam_status': email_obj.get('X-Spam-Status', ''),
                'body': body
            }
        except Exception as e:
            # Fallback: parse as simple text format
            return self.parse_simple_text_format(file_content)

    def extract_body_from_text(self, text: str) -> str:
        """Extract body from simple text format (fallback method)."""
        lines = text.split('\n')
        body_lines = []
        in_body = False
        
        for line in lines:
            # Skip header lines
            if ':' in line and not in_body:
                header_match = re.match(r'^[A-Za-z-]+:', line)
                if header_match:
                    continue
            else:
                in_body = True
            
            if in_body:
                body_lines.append(line)
        
        return '\n'.join(body_lines).strip()

    def parse_simple_text_format(self, file_content: str) -> Dict:
        """Parse email in simple text format (From:, To:, Subject:, etc.)."""
        result = {
            'from': '',
            'to': '',
            'subject': '',
            'date': '',
            'content_type': '',
            'spam_status': '',
            'body': ''
        }
        
        lines = file_content.split('\n')
        body_start = 0
        
        # Extract headers
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if line_lower.startswith('from:'):
                result['from'] = line.split(':', 1)[1].strip()
            elif line_lower.startswith('to:'):
                result['to'] = line.split(':', 1)[1].strip()
            elif line_lower.startswith('subject:'):
                result['subject'] = line.split(':', 1)[1].strip()
            elif line_lower.startswith('date:'):
                result['date'] = line.split(':', 1)[1].strip()
            elif line_lower.startswith('content-type:'):
                result['content_type'] = line.split(':', 1)[1].strip()
            elif line_lower.startswith('x-spam-status:'):
                result['spam_status'] = line.split(':', 1)[1].strip()
            elif line.strip() == '' and i > 0:
                # Empty line usually marks start of body
                body_start = i + 1
                break
        
        # Extract body (everything after first blank line or after last header)
        if body_start > 0:
            result['body'] = '\n'.join(lines[body_start:]).strip()
        else:
            # No blank line found, take everything after headers
            header_count = sum(1 for k, v in result.items() if k != 'body' and v)
            if header_count > 0:
                result['body'] = '\n'.join(lines[header_count:]).strip()
        
        return result

    def get_email_body(self, email_obj) -> str:
        """Extract plain text body from email object."""
        if email_obj.is_multipart():
            body = ""
            for part in email_obj.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            body += payload.decode('utf-8', errors='ignore')
                        else:
                            body += str(payload)
                    except:
                        pass
        else:
            try:
                payload = email_obj.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body = payload.decode('utf-8', errors='ignore')
                else:
                    body = str(payload) if payload else ""
            except:
                body = str(email_obj.get_payload()) if email_obj.get_payload() else ""

        return body

    def count_words(self, text: str) -> int:
        """Count words in text."""
        # Remove extra whitespace and split by whitespace
        words = text.split()
        return len(words)

    def extract_spam_score(self, spam_status: str) -> float:
        """Extract spam score from X-Spam-Status header."""
        if not spam_status:
            return 0.0
        match = re.search(r'hits=(-?\d+\.?\d*)', spam_status)
        if match:
            return float(match.group(1))
        return 0.0

    def analyze_email_file(self, filename: str, file_content: str) -> AnalysisResult:
        """Perform complete security analysis on one email file."""
        try:
            email_data = self.parse_email_file(file_content)
            from_address = email_data['from']
            sender_domain = self.extract_domain_from_email(from_address)
            subject = email_data['subject']
            body = email_data['body']
            all_text = f"{subject} {body}"
            
            # Count words in body
            word_count = self.count_words(body)

            suspicious_domains = self.analyze_domain_similarity(sender_domain)
            extracted_urls = self.extract_urls(all_text)
            suspicious_urls = [self.analyze_url(url) for url in extracted_urls if self.analyze_url(url)['suspicious_reasons']]
            ip_addresses = self.extract_ip_addresses(all_text)
            domain_mismatches = self.detect_domain_mismatches(all_text, extracted_urls)
            spam_score = self.extract_spam_score(email_data['spam_status'])
            
            # Final suspicion decision
            is_suspicious = (
                len(suspicious_domains) > 0 or
                len(suspicious_urls) > 0 or
                len(ip_addresses) > 0 or
                len(domain_mismatches) > 0 or
                spam_score > 5.0
            )

            return AnalysisResult(
                filename=filename,
                sender_domain=sender_domain,
                suspicious_domains=suspicious_domains,
                extracted_urls=extracted_urls,
                suspicious_urls=suspicious_urls,
                ip_addresses=ip_addresses,
                domain_mismatches=domain_mismatches,
                spam_score=spam_score,
                is_suspicious=is_suspicious,
                word_count=word_count,
                subject=subject
            )

        except Exception as e:
            print(f"Error analyzing {filename}: {str(e)}")
            return AnalysisResult(
                filename=filename,
                sender_domain="unknown",
                suspicious_domains=[],
                extracted_urls=[],
                suspicious_urls=[],
                ip_addresses=[],
                domain_mismatches=[],
                spam_score=0.0,
                is_suspicious=False,
                word_count=0,
                subject=""
            )

    def analyze_multiple_files(self, file_contents: Dict[str, str]) -> List[AnalysisResult]:
        """Analyze multiple emails and return results."""
        return [self.analyze_email_file(fname, content) for fname, content in file_contents.items()]

    
    def generate_report(self, results: List[AnalysisResult]) -> str:
        """Generate a comprehensive security analysis report"""
        report = " EMAIL SECURITY ANALYSIS REPORT\n"
        report += "=" * 50 + "\n\n"
        
        total_emails = len(results)
        suspicious_emails = sum(1 for r in results if r.is_suspicious)
        
        report += f" SUMMARY:\n"
        report += f"Total emails analyzed: {total_emails}\n"
        report += f"Suspicious emails found: {suspicious_emails}\n"
        if total_emails > 0:
            report += f"Suspicion rate: {(suspicious_emails/total_emails*100):.1f}%\n"
        report += "\n"
        
        for result in results:
            report += f" FILE: {result.filename}\n"
            report += f"   Sender Domain: {result.sender_domain}\n"
            report += f"   Subject: {result.subject[:50]}{'...' if len(result.subject) > 50 else ''}\n"
            report += f"   Word Count: {result.word_count}\n"
            report += f"   Spam Score: {result.spam_score}\n"
            report += f"   Status: {' SUSPICIOUS' if result.is_suspicious else '✅ CLEAN'}\n"
            
            if result.suspicious_domains:
                report += f"    Domain Similarity Alerts:\n"
                for domain, similarity in result.suspicious_domains[:3]:
                    report += f"     • Similar to {domain} ({similarity:.1f}%)\n"
            
            if result.extracted_urls:
                report += f"    URLs Found: {len(result.extracted_urls)}\n"
                for url in result.extracted_urls[:3]:
                    report += f"     • {url}\n"
            
            if result.suspicious_urls:
                report += f"    Suspicious URLs:\n"
                for url_analysis in result.suspicious_urls:
                    report += f"     • {url_analysis['url']}\n"
                    for reason in url_analysis['suspicious_reasons']:
                        report += f"       - {reason}\n"
            
            if result.ip_addresses:
                report += f"    IP Addresses: {', '.join(result.ip_addresses)}\n"
            
            if result.domain_mismatches:
                report += f"    Domain Mismatches:\n"
                for mismatch in result.domain_mismatches:
                    report += f"     • Display: {mismatch['display_domain']} → Actual: {mismatch['url_domain']}\n"
            
            report += "-" * 40 + "\n"
        
        return report

class SimpleEmailAnalyzer:
    def __init__(self):
        self.analyzer = EmailSecurityAnalyzer()
    
    def analyze_files(self, file_paths):
        """Analyze specific files"""
        print(f" Analyzing {len(file_paths)} specific files...")
        email_files = {}
        
        for filepath in file_paths:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        email_files[filepath] = f.read()
                    print(f" Loaded: {filepath}")
                except Exception as e:
                    print(f" Error loading {filepath}: {e}")
            else:
                print(f" File not found: {filepath}")
        
        return self._run_analysis(email_files)
    
    def analyze_folder(self, folder_path, recursive=True, file_extensions=None):
        """Analyze all email files in a folder"""
        if file_extensions is None:
            file_extensions = ['.txt', '.eml', '.msg']
        
        print(f" Analyzing folder: {folder_path}")
        print(f"   Recursive: {recursive}")
        print(f"   Extensions: {file_extensions}")
        
        email_files = {}
        folder = Path(folder_path)
        
        if not folder.exists():
            print(f" Folder not found: {folder_path}")
            return []
        
        # Find files
        if recursive:
            for ext in file_extensions:
                for file_path in folder.rglob(f"*{ext}"):
                    if file_path.is_file():
                        email_files[str(file_path)] = self._read_file(file_path)
        else:
            for ext in file_extensions:
                for file_path in folder.glob(f"*{ext}"):
                    if file_path.is_file():
                        email_files[str(file_path)] = self._read_file(file_path)
        
        print(f" Found {len(email_files)} email files")
        return self._run_analysis(email_files)
    
    def analyze_pattern(self, pattern, recursive=True):
        """Analyze files matching a pattern"""
        print(f" Analyzing files matching pattern: {pattern}")
        
        email_files = {}
        matching_files = glob.glob(pattern, recursive=recursive)
        
        if not matching_files:
            print(f" No files found matching: {pattern}")
            return []
        
        for filepath in matching_files:
            if os.path.isfile(filepath):
                email_files[filepath] = self._read_file(filepath)
        
        print(f" Found {len(email_files)} files")
        return self._run_analysis(email_files)
    
    def interactive_analysis(self):
        """Interactive mode - ask user what to analyze"""
        print("\n SIMPLE EMAIL ANALYZER - INTERACTIVE MODE")
        print("=" * 50)
        
        while True:
            print("\nWhat would you like to analyze?")
            print("1. Specific files (enter file paths)")
            print("2. Entire folder")
            print("3. Files matching a pattern (*.txt, etc.)")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == "1":
                print("\nEnter file paths (one per line, press Enter twice when done):")
                file_paths = []
                while True:
                    path = input().strip()
                    if not path:
                        break
                    file_paths.append(path)
                
                if file_paths:
                    return self.analyze_files(file_paths)
                else:
                    print(" No files entered!")
            
            elif choice == "2":
                folder_path = input("\nEnter folder path: ").strip()
                recursive = input("Search subfolders too? (y/n): ").strip().lower() == 'y'
                
                print("File extensions to look for (press Enter for default: .txt .eml .msg):")
                ext_input = input().strip()
                if ext_input:
                    extensions = [ext.strip() for ext in ext_input.split()]
                    extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
                else:
                    extensions = ['.txt', '.eml', '.msg']
                
                return self.analyze_folder(folder_path, recursive, extensions)
            
            elif choice == "3":
                pattern = input("\nEnter file pattern (e.g., *.txt, emails/*.eml): ").strip()
                recursive = input("Search subfolders too? (y/n): ").strip().lower() == 'y'
                
                return self.analyze_pattern(pattern, recursive)
            
            elif choice == "4":
                print(" Goodbye!")
                return []
            
            else:
                print(" Invalid choice! Please enter 1-4.")
    
    def _read_file(self, filepath):
        """Read a single file safely"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            print(f" Loaded: {filepath}")
            return content
        except Exception as e:
            print(f" Error loading {filepath}: {e}")
            return ""
    
    def _run_analysis(self, email_files):
        """Run the actual analysis"""
        if not email_files:
            print(" No email files to analyze!")
            return []
        
        print(f"\n Running security analysis on {len(email_files)} files...")
        
        # Run analysis
        results = self.analyzer.analyze_multiple_files(email_files)
        
        # Print summary
        suspicious_count = sum(1 for r in results if r.is_suspicious)
        print(f"\n ANALYSIS COMPLETE!")
        print(f"   Total files: {len(results)}")
        print(f"   Suspicious: {suspicious_count}")
        print(f"   Clean: {len(results) - suspicious_count}")
        
        # Show suspicious files
        if suspicious_count > 0:
            print(f"\n SUSPICIOUS FILES FOUND:")
            for result in results:
                if result.is_suspicious:
                    print(f"\n {result.filename}")
                    print(f"   Sender: {result.sender_domain}")
                    print(f"   Subject: {result.subject[:50]}{'...' if len(result.subject) > 50 else ''}")
                    print(f"   Word Count: {result.word_count}")
                    print(f"   Spam Score: {result.spam_score}")
                    
                    # Show specific threats
                    threats = []
                    if result.suspicious_domains:
                        threats.append(f"Domain similarity ({len(result.suspicious_domains)})")
                    if result.suspicious_urls:
                        threats.append(f"Suspicious URLs ({len(result.suspicious_urls)})")
                    if result.ip_addresses:
                        threats.append(f"IP addresses ({len(result.ip_addresses)})")
                    if result.domain_mismatches:
                        threats.append(f"Domain mismatches ({len(result.domain_mismatches)})")
                    
                    if threats:
                        print(f"    Threats: {', '.join(threats)}")
        
        # Generate detailed report
        print(f"\n DETAILED REPORT:")
        print("=" * 60)
        report = self.analyzer.generate_report(results)
        print(report)
    
        return results

def main():
    """Main function with simple command line interface"""
    analyzer = SimpleEmailAnalyzer()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        # Command line mode
        if sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print(" SIMPLE EMAIL ANALYZER")
            print("=" * 30)
            print("Usage:")
            print("  python email_checker_script.py                    # Interactive mode")
            print("  python email_checker_script.py file1.txt file2.txt  # Analyze specific files")
            print("  python email_checker_script.py --folder /path/to/emails  # Analyze folder")
            print("  python email_checker_script.py --pattern '*.txt'  # Analyze pattern")
            print("\nExamples:")
            print("  python email_checker_script.py email1.txt email2.eml")
            print("  python email_checker_script.py --folder ./emails")
            print("  python email_checker_script.py --pattern 'inbox/*.txt'")
            return
        
        elif sys.argv[1] == '--folder':
            if len(sys.argv) > 2:
                analyzer.analyze_folder(sys.argv[2])
            else:
                print(" Please specify folder path")
        
        elif sys.argv[1] == '--pattern':
            if len(sys.argv) > 2:
                analyzer.analyze_pattern(sys.argv[2])
            else:
                print(" Please specify file pattern")
        
        else:
            # Treat all arguments as file paths
            file_paths = sys.argv[1:]
            analyzer.analyze_files(file_paths)
    
    else:
        # Interactive mode
        analyzer.interactive_analysis()

if __name__ == "__main__":
    main()