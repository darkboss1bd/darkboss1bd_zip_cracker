import zipfile
import threading
import time
import os
import sys
import itertools
import string
from datetime import datetime
import webbrowser
import json
import hashlib
import argparse

class AdvancedDarkBossBruteForceSuite:
    def __init__(self):
        self.found_password = None
        self.attempts = 0
        self.start_time = None
        self.is_running = False
        self.results_file = "darkboss_results.txt"
        self.config_file = "darkboss_config.json"
        
    def display_banner(self):
        banner = """
\033[1;31m
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗  ██████╗ ███████╗███████╗        ║
║    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝        ║
║    ██║  ██║███████║██████╔╝█████╔╝ ██████╔╝██║   ██║███████╗███████╗        ║
║    ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██╗██║   ██║╚════██║╚════██║        ║
║    ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝╚██████╔╝███████║███████║        ║
║    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝        ║
║                                                                              ║
║                  ADVANCED BRUTE FORCE SUITE v3.0                            ║
║                         by darkboss1bd                                      ║
║                  Professional Security Toolkit                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
        print(banner)
        
    def display_info(self):
        info = """
\033[1;36m
╔══════════════════════════════════════════════════════════════════════════════╗
║                           CONTACT INFORMATION                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 🔹 Telegram ID: https://t.me/darkvaiadmin                                   ║
║ 🔹 Telegram Channel: https://t.me/windowspremiumkey                         ║
║ 🔹 Hacking/Cracking Website: https://crackyworld.com/                       ║
║ 🔹 Advanced Brute Force Tools & Security Solutions                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
        print(info)
        
    def open_links(self):
        """Automatically open the provided links"""
        links = [
            "https://t.me/darkvaiadmin",
            "https://t.me/windowspremiumkey", 
            "https://crackyworld.com/"
        ]
        
        print("\033[1;33m[INFO] Opening darkboss1bd professional links...\033[0m")
        for link in links:
            try:
                webbrowser.open(link)
                time.sleep(1)
            except Exception as e:
                print(f"\033[1;31m[ERROR] Could not open {link}: {e}\033[0m")

    def save_result(self, target, password, method, time_taken, attempts):
        """Save successful results to file"""
        result = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': target,
            'password': password,
            'method': method,
            'time_taken': f"{time_taken:.2f} seconds",
            'attempts': attempts,
            'tool': 'DarkBoss Advanced Brute Force Suite'
        }
        
        with open(self.results_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(result, indent=2) + '\n' + '-'*50 + '\n')
    
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            'default_threads': 8,
            'max_password_length': 12,
            'timeout': 300,
            'auto_save': True,
            'wordlist_paths': ['wordlists/']
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return default_config
    
    def save_config(self, config):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)

    # Advanced Wordlist Generator
    class AdvancedWordlistGenerator:
        def __init__(self):
            self.combinations = 0
            
        def calculate_combinations(self, charset, min_len, max_len):
            """Calculate total number of combinations"""
            total = 0
            for length in range(min_len, max_len + 1):
                total += len(charset) ** length
            return total
        
        def generate_wordlist(self, charset, min_len, max_len, output_file):
            """Generate advanced wordlist"""
            self.combinations = self.calculate_combinations(charset, min_len, max_len)
            print(f"\033[1;33m[INFO] Generating {self.combinations:,} combinations...\033[0m")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                generated = 0
                for length in range(min_len, max_len + 1):
                    for combo in itertools.product(charset, repeat=length):
                        password = ''.join(combo)
                        f.write(password + '\n')
                        generated += 1
                        if generated % 10000 == 0:
                            progress = (generated / self.combinations) * 100
                            print(f"\033[1;36m[PROGRESS] Generated: {generated:,} ({progress:.2f}%)\033[0m", end='\r')
            
            print(f"\033[1;32m[SUCCESS] Wordlist generated: {output_file}\033[0m")
            print(f"\033[1;32m[INFO] Total passwords: {generated:,}\033[0m")
            return output_file
        
        def smart_wordlist(self, base_words, output_file, max_variations=1000000):
            """Generate smart wordlist with common variations"""
            variations = []
            
            # Common substitutions
            substitutions = {
                'a': ['@', '4'],
                'e': ['3'],
                'i': ['1', '!'],
                'o': ['0'],
                's': ['5', '$'],
                't': ['7']
            }
            
            print("\033[1;33m[INFO] Generating smart wordlist with variations...\033[0m")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                count = 0
                for word in base_words:
                    word = word.strip().lower()
                    if not word:
                        continue
                    
                    # Original word
                    f.write(word + '\n')
                    count += 1
                    
                    # Capitalizations
                    f.write(word.capitalize() + '\n')
                    f.write(word.upper() + '\n')
                    count += 2
                    
                    # Add numbers
                    for i in range(100):
                        f.write(word + str(i) + '\n')
                        f.write(word.capitalize() + str(i) + '\n')
                        count += 2
                    
                    # Leet speak variations (limited)
                    leet_variations = self.generate_leet_variations(word, substitutions)
                    for variation in leet_variations[:100]:  # Limit variations
                        f.write(variation + '\n')
                        count += 1
                    
                    if count >= max_variations:
                        break
                    
                    if count % 1000 == 0:
                        print(f"\033[1;36m[PROGRESS] Generated: {count:,} passwords\033[0m", end='\r')
            
            print(f"\033[1;32m[SUCCESS] Smart wordlist generated: {output_file}\033[0m")
            print(f"\033[1;32m[INFO] Total passwords: {count:,}\033[0m")
            return output_file
        
        def generate_leet_variations(self, word, substitutions):
            """Generate leet speak variations"""
            variations = [word]
            
            for char, replacements in substitutions.items():
                new_variations = []
                for variation in variations:
                    if char in variation:
                        for replacement in replacements:
                            new_variations.append(variation.replace(char, replacement))
                variations.extend(new_variations)
            
            return list(set(variations))  # Remove duplicates

    # ZIP Brute Force
    def zip_brute_force(self, zip_path, wordlist_path, threads=8):
        """Advanced ZIP brute force with multiple techniques"""
        if not os.path.exists(zip_path):
            print(f"\033[1;31m[ERROR] ZIP file not found: {zip_path}\033[0m")
            return
        
        passwords = self.load_password_list(wordlist_path)
        if not passwords:
            return
        
        print(f"\033[1;32m[INFO] Loaded {len(passwords):,} passwords from wordlist\033[0m")
        print(f"\033[1;32m[INFO] Starting advanced brute force with {threads} threads...\033[0m")
        
        self.start_time = time.time()
        self.is_running = True
        self.attempts = 0
        self.found_password = None
        
        # Split passwords for threading
        chunk_size = len(passwords) // threads
        password_chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]
        
        def worker(password_list, thread_id):
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_file:
                    for password in password_list:
                        if not self.is_running or self.found_password:
                            return
                        
                        self.attempts += 1
                        if self.attempts % 1000 == 0:
                            elapsed = time.time() - self.start_time
                            speed = self.attempts / elapsed if elapsed > 0 else 0
                            print(f"\033[1;33m[STATUS] Thread {thread_id}: {self.attempts:,} attempts, {speed:,.0f} p/s\033[0m", end='\r')
                        
                        if self.try_zip_password(zip_file, password):
                            self.found_password = password
                            self.is_running = False
                            return
            except Exception as e:
                print(f"\033[1;31m[ERROR] Thread {thread_id} failed: {e}\033[0m")
        
        # Start threads
        thread_list = []
        for i, chunk in enumerate(password_chunks):
            if chunk:
                thread = threading.Thread(target=worker, args=(chunk, i+1))
                thread.daemon = True
                thread_list.append(thread)
                thread.start()
        
        # Monitor progress
        try:
            while self.is_running and not self.found_password:
                time.sleep(0.5)
                if all(not thread.is_alive() for thread in thread_list):
                    break
        except KeyboardInterrupt:
            print(f"\n\033[1;33m[INFO] Process interrupted by user\033[0m")
            self.is_running = False
        
        # Cleanup
        for thread in thread_list:
            thread.join(timeout=1)
        
        elapsed_time = time.time() - self.start_time
        
        if self.found_password:
            print(f"\n\033[1;32m[SUCCESS] Password found: {self.found_password}\033[0m")
            print(f"\033[1;32m[INFO] Time elapsed: {elapsed_time:.2f} seconds\033[0m")
            print(f"\033[1;32m[INFO] Total attempts: {self.attempts:,}\033[0m")
            print(f"\033[1;32m[INFO] Speed: {self.attempts/elapsed_time:,.0f} passwords/second\033[0m")
            
            # Save result
            self.save_result(zip_path, self.found_password, "ZIP Brute Force", elapsed_time, self.attempts)
        else:
            print(f"\n\033[1;31m[FAILED] Password not found in wordlist\033[0m")
            print(f"\033[1;33m[INFO] Total attempts: {self.attempts:,}\033[0m")
            print(f"\033[1;33m[INFO] Time elapsed: {elapsed_time:.2f} seconds\033[0m")

    def try_zip_password(self, zip_file, password):
        """Attempt to extract zip file with given password"""
        try:
            zip_file.extractall(pwd=password.encode())
            return True
        except:
            return False

    def load_password_list(self, wordlist_path):
        """Load password wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                passwords = [line.strip() for line in file if line.strip()]
            return passwords
        except FileNotFoundError:
            print(f"\033[1;31m[ERROR] Wordlist file not found: {wordlist_path}\033[0m")
            return None
        except Exception as e:
            print(f"\033[1;31m[ERROR] Could not read wordlist: {e}\033[0m")
            return None

    # Dictionary Attack
    def dictionary_attack(self, target_hash, wordlist_path, hash_type='md5'):
        """Perform dictionary attack against hashes"""
        print(f"\033[1;35m[INFO] Starting dictionary attack on {hash_type.upper()} hash\033[0m")
        
        passwords = self.load_password_list(wordlist_path)
        if not passwords:
            return
        
        self.start_time = time.time()
        self.attempts = 0
        self.found_password = None
        
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        if hash_type not in hash_functions:
            print(f"\033[1;31m[ERROR] Unsupported hash type: {hash_type}\033[0m")
            return
        
        hash_func = hash_functions[hash_type]
        
        for password in passwords:
            self.attempts += 1
            if self.attempts % 10000 == 0:
                elapsed = time.time() - self.start_time
                speed = self.attempts / elapsed if elapsed > 0 else 0
                print(f"\033[1;33m[STATUS] {self.attempts:,} attempts, {speed:,.0f} p/s\033[0m", end='\r')
            
            hashed_password = hash_func(password.encode()).hexdigest()
            if hashed_password == target_hash.lower():
                self.found_password = password
                break
        
        elapsed_time = time.time() - self.start_time
        
        if self.found_password:
            print(f"\n\033[1;32m[SUCCESS] Password found: {self.found_password}\033[0m")
            print(f"\033[1;32m[INFO] Hash: {target_hash}\033[0m")
            print(f"\033[1;32m[INFO] Time: {elapsed_time:.2f} seconds\033[0m")
            print(f"\033[1;32m[INFO] Attempts: {self.attempts:,}\033[0m")
            
            self.save_result(f"Hash_{target_hash}", self.found_password, f"Dictionary Attack ({hash_type})", elapsed_time, self.attempts)
        else:
            print(f"\n\033[1;31m[FAILED] Password not found for hash: {target_hash}\033[0m")

    # Advanced Menu System
    def main_menu(self):
        """Main menu system"""
        self.display_banner()
        self.display_info()
        self.open_links()
        
        wordlist_gen = self.AdvancedWordlistGenerator()
        config = self.load_config()
        
        while True:
            print("\n\033[1;36m" + "═" * 70 + "\033[0m")
            print("\033[1;35mDARKBOSS ADVANCED BRUTE FORCE SUITE - MAIN MENU\033[0m")
            print("\033[1;36m" + "═" * 70 + "\033[0m")
            print("\033[1;33m1. ZIP File Brute Force")
            print("2. Dictionary Attack (Hashes)")
            print("3. Advanced Wordlist Generator")
            print("4. Smart Wordlist Creator")
            print("5. View Previous Results")
            print("6. Configuration Settings")
            print("7. Exit\033[0m")
            print("\033[1;36m" + "─" * 70 + "\033[0m")
            
            choice = input("\n\033[1;32mEnter your choice (1-7): \033[0m").strip()
            
            if choice == "1":
                self.zip_attack_menu()
            elif choice == "2":
                self.hash_attack_menu()
            elif choice == "3":
                self.wordlist_generator_menu(wordlist_gen)
            elif choice == "4":
                self.smart_wordlist_menu(wordlist_gen)
            elif choice == "5":
                self.view_results()
            elif choice == "6":
                self.configuration_menu(config)
            elif choice == "7":
                print("\n\033[1;35mThank you for using DarkBoss Advanced Brute Force Suite!\033[0m")
                print("\033[1;36mVisit: https://crackyworld.com/ for more tools!\033[0m")
                break
            else:
                print("\033[1;31m[ERROR] Invalid choice. Please try again.\033[0m")

    def zip_attack_menu(self):
        """ZIP attack menu"""
        print("\n\033[1;35mZIP FILE BRUTE FORCE ATTACK\033[0m")
        zip_path = input("\033[1;32mEnter ZIP file path: \033[0m").strip()
        wordlist_path = input("\033[1;32mEnter wordlist path: \033[0m").strip()
        
        if not os.path.exists(wordlist_path):
            print("\033[1;33m[INFO] Wordlist not found. Please create one first.\033[0m")
            return
        
        threads = input("\033[1;32mEnter number of threads (default 8): \033[0m").strip()
        threads = int(threads) if threads.isdigit() else 8
        
        self.zip_brute_force(zip_path, wordlist_path, threads)

    def hash_attack_menu(self):
        """Hash attack menu"""
        print("\n\033[1;35mDICTIONARY ATTACK - HASH CRACKING\033[0m")
        target_hash = input("\033[1;32mEnter target hash: \033[0m").strip()
        hash_type = input("\033[1;32mEnter hash type (md5/sha1/sha256): \033[0m").strip().lower()
        wordlist_path = input("\033[1;32mEnter wordlist path: \033[0m").strip()
        
        if not os.path.exists(wordlist_path):
            print("\033[1;33m[INFO] Wordlist not found. Please create one first.\033[0m")
            return
        
        self.dictionary_attack(target_hash, wordlist_path, hash_type)

    def wordlist_generator_menu(self, wordlist_gen):
        """Wordlist generator menu"""
        print("\n\033[1;35mADVANCED WORDLIST GENERATOR\033[0m")
        print("\033[1;33mAvailable character sets:")
        print("1. Lowercase (a-z)")
        print("2. Uppercase (A-Z)")
        print("3. Numbers (0-9)")
        print("4. Special characters (!@#$%^&*)")
        print("5. Custom character set\033[0m")
        
        charset_choice = input("\033[1;32mChoose character set (1-5): \033[0m").strip()
        
        charset = ""
        if charset_choice == "1":
            charset = string.ascii_lowercase
        elif charset_choice == "2":
            charset = string.ascii_uppercase
        elif charset_choice == "3":
            charset = string.digits
        elif charset_choice == "4":
            charset = "!@#$%^&*"
        elif charset_choice == "5":
            charset = input("\033[1;32mEnter custom character set: \033[0m").strip()
        else:
            print("\033[1;31m[ERROR] Invalid choice\033[0m")
            return
        
        min_len = int(input("\033[1;32mMinimum password length: \033[0m").strip() or "1")
        max_len = int(input("\033[1;32mMaximum password length: \033[0m").strip() or "8")
        output_file = input("\033[1;32mOutput file name: \033[0m").strip() or "generated_wordlist.txt"
        
        wordlist_gen.generate_wordlist(charset, min_len, max_len, output_file)

    def smart_wordlist_menu(self, wordlist_gen):
        """Smart wordlist menu"""
        print("\n\033[1;35mSMART WORDLIST CREATOR\033[0m")
        base_file = input("\033[1;32mEnter base wordlist file: \033[0m").strip()
        output_file = input("\033[1;32mOutput file name: \033[0m").strip() or "smart_wordlist.txt"
        
        if not os.path.exists(base_file):
            print("\033[1;31m[ERROR] Base wordlist file not found\033[0m")
            return
        
        with open(base_file, 'r', encoding='utf-8', errors='ignore') as f:
            base_words = f.readlines()
        
        wordlist_gen.smart_wordlist(base_words, output_file)

    def view_results(self):
        """View previous results"""
        if not os.path.exists(self.results_file):
            print("\033[1;33m[INFO] No previous results found\033[0m")
            return
        
        print(f"\n\033[1;35mPREVIOUS ATTACK RESULTS from {self.results_file}\033[0m")
        print("\033[1;36m" + "═" * 70 + "\033[0m")
        
        with open(self.results_file, 'r', encoding='utf-8') as f:
            content = f.read()
            print(content)

    def configuration_menu(self, config):
        """Configuration menu"""
        print("\n\033[1;35mCONFIGURATION SETTINGS\033[0m")
        print(f"\033[1;33mCurrent settings: {json.dumps(config, indent=2)}\033[0m")
        
        print("\n\033[1;32m1. Change default threads")
        print("2. Change timeout settings")
        print("3. Reset to defaults")
        print("4. Back to main menu\033[0m")
        
        choice = input("\n\033[1;32mEnter choice (1-4): \033[0m").strip()
        
        if choice == "1":
            threads = input("Enter new default threads: ").strip()
            if threads.isdigit():
                config['default_threads'] = int(threads)
                self.save_config(config)
                print("\033[1;32m[SUCCESS] Configuration updated\033[0m")
        elif choice == "2":
            timeout = input("Enter new timeout (seconds): ").strip()
            if timeout.isdigit():
                config['timeout'] = int(timeout)
                self.save_config(config)
                print("\033[1;32m[SUCCESS] Configuration updated\033[0m")
        elif choice == "3":
            default_config = {
                'default_threads': 8,
                'max_password_length': 12,
                'timeout': 300,
                'auto_save': True
            }
            self.save_config(default_config)
            print("\033[1;32m[SUCCESS] Configuration reset to defaults\033[0m")

def main():
    try:
        suite = AdvancedDarkBossBruteForceSuite()
        suite.main_menu()
    except KeyboardInterrupt:
        print(f"\n\033[1;33m[INFO] Tool stopped by user\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m[ERROR] An error occurred: {e}\033[0m")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
