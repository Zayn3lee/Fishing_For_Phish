#!/usr/bin/env python3
"""
Simple Email Analyzer - No external dependencies required
Just specify your files/folders and run!
"""

import os
import sys
import glob
from pathlib import Path
from email_checker_manual import EmailSecurityAnalyzer

class SimpleEmailAnalyzer:
    """
    Simple email analyzer with no external dependencies
    """
    
    def __init__(self):
        self.analyzer = EmailSecurityAnalyzer()
    
    def analyze_files(self, file_paths):
        """
        Analyze specific files
        Usage: analyzer.analyze_files(['email1.txt', 'email2.txt'])
        """
        print(f"📧 Analyzing {len(file_paths)} specific files...")
        email_files = {}
        
        for filepath in file_paths:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        email_files[filepath] = f.read()
                    print(f"✅ Loaded: {filepath}")
                except Exception as e:
                    print(f"❌ Error loading {filepath}: {e}")
            else:
                print(f"❌ File not found: {filepath}")
        
        return self._run_analysis(email_files)
    
    def analyze_folder(self, folder_path, recursive=True, file_extensions=None):
        """
        Analyze all email files in a folder
        Usage: analyzer.analyze_folder('/path/to/emails')
        """
        if file_extensions is None:
            file_extensions = ['.txt', '.eml', '.msg']
        
        print(f"📁 Analyzing folder: {folder_path}")
        print(f"   Recursive: {recursive}")
        print(f"   Extensions: {file_extensions}")
        
        email_files = {}
        folder = Path(folder_path)
        
        if not folder.exists():
            print(f"❌ Folder not found: {folder_path}")
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
        
        print(f"📧 Found {len(email_files)} email files")
        return self._run_analysis(email_files)
    
    def analyze_pattern(self, pattern, recursive=True):
        """
        Analyze files matching a pattern
        Usage: analyzer.analyze_pattern('*.txt')
               analyzer.analyze_pattern('emails/**/*.eml')
        """
        print(f"🔍 Analyzing files matching pattern: {pattern}")
        
        email_files = {}
        matching_files = glob.glob(pattern, recursive=recursive)
        
        if not matching_files:
            print(f"❌ No files found matching: {pattern}")
            return []
        
        for filepath in matching_files:
            if os.path.isfile(filepath):
                email_files[filepath] = self._read_file(filepath)
        
        print(f"📧 Found {len(email_files)} files")
        return self._run_analysis(email_files)
    
    def interactive_analysis(self):
        """
        Interactive mode - ask user what to analyze
        """
        print("\n🔍 SIMPLE EMAIL ANALYZER - INTERACTIVE MODE")
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
                    print("No files entered!")
            
            elif choice == "2":
                folder_path = input("\nEnter folder path: ").strip()
                recursive = input("Search subfolders too? (y/n): ").strip().lower() == 'y'
                
                # Ask for file extensions
                print("File extensions to look for (press Enter for default: .txt .eml .msg):")
                ext_input = input().strip()
                if ext_input:
                    extensions = [ext.strip() for ext in ext_input.split()]
                    # Add dots if missing
                    extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
                else:
                    extensions = ['.txt', '.eml', '.msg']
                
                return self.analyze_folder(folder_path, recursive, extensions)
            
            elif choice == "3":
                pattern = input("\nEnter file pattern (e.g., *.txt, emails/*.eml): ").strip()
                recursive = input("Search subfolders too? (y/n): ").strip().lower() == 'y'
                
                return self.analyze_pattern(pattern, recursive)
            
            elif choice == "4":
                print("👋 Goodbye!")
                return []
            
            else:
                print("❌ Invalid choice! Please enter 1-4.")
    
    def _read_file(self, filepath):
        """Read a single file safely"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            print(f"✅ Loaded: {filepath}")
            return content
        except Exception as e:
            print(f"❌ Error loading {filepath}: {e}")
            return ""
    
    def _run_analysis(self, email_files):
        """Run the actual analysis"""
        if not email_files:
            print("❌ No email files to analyze!")
            return []
        
        print(f"\n🔍 Running security analysis on {len(email_files)} files...")
        
        # Run analysis
        results = self.analyzer.analyze_multiple_files(email_files)
        
        # Print summary
        suspicious_count = sum(1 for r in results if r.is_suspicious)
        print(f"\n📊 ANALYSIS COMPLETE!")
        print(f"   Total files: {len(results)}")
        print(f"   Suspicious: {suspicious_count}")
        print(f"   Clean: {len(results) - suspicious_count}")
        
        # Show suspicious files
        if suspicious_count > 0:
            print(f"\n🚨 SUSPICIOUS FILES FOUND:")
            for result in results:
                if result.is_suspicious:
                    print(f"\n📁 {result.filename}")
                    print(f"   Sender: {result.sender_domain}")
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
                        print(f"   ⚠️  Threats: {', '.join(threats)}")
        
        # Generate detailed report
        print(f"\n📄 DETAILED REPORT:")
        print("=" * 60)
        report = self.analyzer.generate_report(results)
        print(report)
        
        # Ask if user wants to save report
        save = input("\n💾 Save report to file? (y/n): ").strip().lower()
        if save == 'y':
            report_file = input("Enter filename (or press Enter for 'email_analysis_report.txt'): ").strip()
            if not report_file:
                report_file = 'email_analysis_report.txt'
            
            try:
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"✅ Report saved to: {report_file}")
            except Exception as e:
                print(f"❌ Error saving report: {e}")
        
        return results

def main():
    """Main function with simple command line interface"""
    analyzer = SimpleEmailAnalyzer()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        # Command line mode
        if sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("🛡️  SIMPLE EMAIL ANALYZER")
            print("=" * 30)
            print("Usage:")
            print("  python simple_email_analyzer.py                    # Interactive mode")
            print("  python simple_email_analyzer.py file1.txt file2.txt  # Analyze specific files")
            print("  python simple_email_analyzer.py --folder /path/to/emails  # Analyze folder")
            print("  python simple_email_analyzer.py --pattern '*.txt'  # Analyze pattern")
            print("\nExamples:")
            print("  python simple_email_analyzer.py email1.txt email2.eml")
            print("  python simple_email_analyzer.py --folder ./emails")
            print("  python simple_email_analyzer.py --pattern 'inbox/*.txt'")
            return
        
        elif sys.argv[1] == '--folder':
            if len(sys.argv) > 2:
                analyzer.analyze_folder(sys.argv[2])
            else:
                print("❌ Please specify folder path")
        
        elif sys.argv[1] == '--pattern':
            if len(sys.argv) > 2:
                analyzer.analyze_pattern(sys.argv[2])
            else:
                print("❌ Please specify file pattern")
        
        else:
            # Treat all arguments as file paths
            file_paths = sys.argv[1:]
            analyzer.analyze_files(file_paths)
    
    else:
        # Interactive mode
        analyzer.interactive_analysis()

if __name__ == "__main__":
    main()