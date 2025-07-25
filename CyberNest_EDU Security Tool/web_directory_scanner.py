import requests
import threading
import time
from urllib.parse import urljoin, urlparse
import os

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Common directory and file list
COMMON_PATHS = [
    # Admin panels
    'admin', 'admin/', 'admin/login', 'admin/login.php', 'admin/index.php',
    'administrator', 'administrator/', 'wp-admin/', 'cpanel/', 'panel/',
    'control/', 'controlpanel/', 'admincp/', 'modcp/', 'adminarea/',
    'bb-admin/', 'adminLogin/', 'admin_area/', 'panel-administracion/',
    'instadmin/', 'memberadmin/', 'administratorlogin/', 'adm/',
    'admin/account.php', 'admin/index.html', 'admin/login.html',
    'admin/admin.html', 'admin_area/admin.html', 'admin_area/login.html',
    'siteadmin/login.html', 'siteadmin/index.html', 'siteadmin/login.php',
    
    # Login pages
    'login', 'login/', 'login.php', 'signin', 'signin/', 'signin.php',
    'log-in', 'log-in/', 'member/', 'membership/', 'auth/', 'authenticate/',
    'user/', 'users/', 'account/', 'my-account/', 'dashboard/',
    'portal/', 'secure/', 'private/', 'restricted/', 'members/',
    'login.html', 'signin.html', 'logon.html', 'logon.php',
    
    # Configuration files
    'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
    'clientaccesspolicy.xml', 'phpinfo.php', 'info.php', 'test.php',
    'config.php', 'configuration.php', 'settings.php', 'wp-config.php',
    '.env', 'config/', 'includes/', 'inc/', 'lib/', 'libs/',
    
    # Backup and log files
    'backup/', 'backups/', 'bak/', 'old/', 'temp/', 'tmp/', 'cache/',
    'logs/', 'log/', 'error_log', 'access_log', 'admin.log',
    'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
    'backup.zip', 'backup.tar.gz', 'site.zip', 'www.zip',
    
    # Development directories
    'dev/', 'development/', 'test/', 'testing/', 'stage/', 'staging/',
    'beta/', 'demo/', 'sandbox/', 'git/', '.git/', 'svn/', '.svn/',
    'cvs/', '.cvs/', 'debug/', 'trace/', 'profiler/',
    
    # Database management tools
    'phpmyadmin/', 'pma/', 'myadmin/', 'mysql/', 'mysqladmin/',
    'db/', 'database/', 'sql/', 'adminer/', 'adminer.php',
    'phpMyAdmin/', 'dbadmin/', 'sqlmanager/', 'websql/',
    
    # CMS specific files
    'wp-login.php', 'wp-admin.php', 'wp-config.php', 'wp-content/',
    'joomla/', 'drupal/', 'administrator/index.php', 'typo3/',
    'magento/', 'prestashop/', 'opencart/',
    
    # API endpoints
    'api/', 'api/v1/', 'api/v2/', 'rest/', 'graphql/', 'webhook/',
    'service/', 'services/', 'webservice/', 'rpc/', 'soap/',
    
    # File upload directories
    'upload/', 'uploads/', 'files/', 'media/', 'images/', 'img/',
    'documents/', 'docs/', 'assets/', 'static/', 'public/',
    
    # Server information pages
    'server-status', 'server-info', 'status/', 'stats/', 'statistics/',
    'health/', 'ping/', 'version/', 'info/', 'about/', 'readme.txt'
]

class WebDirectoryScanner:
    def __init__(self, target_url, threads=10, timeout=5):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.found_paths = []
        self.total_requests = 0
        self.completed_requests = 0
        self.start_time = None
        
        # URL format check
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'http://' + self.target_url
            
        # Create session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def check_path(self, path):
        """Check the specified path"""
        try:
            url = urljoin(self.target_url + '/', path)
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            self.completed_requests += 1
            
            # Save successful responses
            if response.status_code in [200, 301, 302, 403]:
                result = {
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('content-type', 'Unknown')
                }
                
                # Additional info for special cases
                if path == 'robots.txt' and response.status_code == 200:
                    result['note'] = 'Contains robots.txt directives'
                elif 'admin' in path.lower() and response.status_code == 200:
                    result['note'] = 'Potential admin interface'
                elif 'login' in path.lower() and response.status_code == 200:
                    result['note'] = 'Login page detected'
                elif response.status_code == 403:
                    result['note'] = 'Directory exists but access forbidden'
                elif response.status_code in [301, 302]:
                    result['note'] = f'Redirects to: {response.headers.get("location", "Unknown")}'
                
                self.found_paths.append(result)
                
                # Real-time result display
                status_color = GREEN if response.status_code == 200 else YELLOW
                print(f"{status_color}[{response.status_code}]{RESET} {BLUE}{url}{RESET} ({response.headers.get('content-type', 'Unknown')})")
                
        except requests.exceptions.RequestException:
            self.completed_requests += 1
            pass  # Silently pass on error
    
    def progress_monitor(self):
        """Show progress status"""
        while self.completed_requests < self.total_requests:
            elapsed = time.time() - self.start_time
            progress = (self.completed_requests / self.total_requests) * 100
            
            print(f"\r{CYAN}Progress: {progress:.1f}% ({self.completed_requests}/{self.total_requests}) - "
                  f"Elapsed: {elapsed:.1f}s - Found: {len(self.found_paths)}{RESET}", end='', flush=True)
            time.sleep(0.5)
    
    def scan(self, custom_paths=None):
        """Start scanning process"""
        paths_to_scan = custom_paths if custom_paths else COMMON_PATHS
        self.total_requests = len(paths_to_scan)
        self.start_time = time.time()
        
        print(f"{YELLOW}🔍 Starting directory scan on: {self.target_url}{RESET}")
        print(f"{BLUE}📊 Total paths to check: {len(paths_to_scan)}{RESET}")
        print(f"{BLUE}🧵 Using {self.threads} threads{RESET}")
        print(f"{WHITE}{'='*60}{RESET}\n")
        
        # Progress monitor thread
        progress_thread = threading.Thread(target=self.progress_monitor, daemon=True)
        progress_thread.start()
        
        # Worker threads
        threads = []
        path_index = 0
        
        def worker():
            nonlocal path_index
            while path_index < len(paths_to_scan):
                if path_index >= len(paths_to_scan):
                    break
                current_path = paths_to_scan[path_index]
                path_index += 1
                self.check_path(current_path)
        
        # Start threads
        for _ in range(self.threads):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for threads to complete
        for thread in threads:
            thread.join()
        
        # Final progress update
        elapsed = time.time() - self.start_time
        print(f"\r{GREEN}✅ Scan completed! - {elapsed:.1f}s - Found: {len(self.found_paths)} items{RESET}")
        
        return self.found_paths
    
    def display_results(self):
        """Display results"""
        if not self.found_paths:
            print(f"\n{RED}❌ No accessible directories or files found.{RESET}")
            return
        
        print(f"\n{GREEN}🎯 Found {len(self.found_paths)} accessible paths:{RESET}")
        print(f"{WHITE}{'='*80}{RESET}")
        
        # Categorize results
        categories = {
            'Admin Panels': [],
            'Login Pages': [],
            'Config Files': [],
            'Backups/Logs': [],
            'API Endpoints': [],
            'Other': []
        }
        
        for result in sorted(self.found_paths, key=lambda x: x['status_code']):
            path = result['path'].lower()
            
            if 'admin' in path or 'panel' in path:
                categories['Admin Panels'].append(result)
            elif 'login' in path or 'signin' in path or 'auth' in path:
                categories['Login Pages'].append(result)
            elif any(x in path for x in ['robots.txt', 'config', '.env', 'web.config', 'htaccess']):
                categories['Config Files'].append(result)
            elif any(x in path for x in ['backup', 'log', 'dump', '.sql']):
                categories['Backups/Logs'].append(result)
            elif 'api' in path or 'service' in path or 'rest' in path:
                categories['API Endpoints'].append(result)
            else:
                categories['Other'].append(result)
        
        # Show results by categories
        for category, items in categories.items():
            if items:
                print(f"\n{BOLD}{MAGENTA}📁 {category}:{RESET}")
                for item in items:
                    status_color = GREEN if item['status_code'] == 200 else YELLOW if item['status_code'] in [301, 302] else RED
                    print(f"  {status_color}[{item['status_code']}]{RESET} {BLUE}{item['url']}{RESET}")
                    print(f"      📝 Content-Type: {item['content_type']}")
                    print(f"      📏 Size: {item['content_length']} bytes")
                    if 'note' in item:
                        print(f"      ℹ️  {item['note']}")
                    print()

def run():
    """Main function"""
    print(f"{CYAN}🌐 Web Directory Scanner{RESET}")
    print(f"{WHITE}{'='*50}{RESET}")
    
    while True:
        print(f"\n{BOLD}{GREEN}===== Web Directory Scanner ====={RESET}")
        print(f"{BLUE}1.{RESET} {WHITE}Quick Scan (Common paths){RESET}")
        print(f"{BLUE}2.{RESET} {WHITE}Custom Path Scan{RESET}")
        print(f"{BLUE}3.{RESET} {WHITE}Full Comprehensive Scan{RESET}")
        print(f"{BLUE}0.{RESET} {RED}Return to Menu{RESET}")
        
        choice = input(f"\n{BOLD}{WHITE}Select an option: {RESET}")
        
        if choice == '1':
            target = input(f"{YELLOW}Enter target URL or IP: {RESET}").strip()
            if not target:
                print(f"{RED}❌ Please enter a valid target!{RESET}")
                continue
                
            threads = input(f"{YELLOW}Number of threads (default 10): {RESET}").strip()
            threads = int(threads) if threads.isdigit() else 10
            
            scanner = WebDirectoryScanner(target, threads=threads)
            
            # Important paths for quick scan
            quick_paths = [
                'robots.txt', 'admin/', 'login/', 'wp-admin/', 'phpmyadmin/',
                'admin/login', 'administrator/', 'panel/', '.htaccess', 'config.php',
                'backup/', 'test/', 'dev/', 'api/', 'upload/'
            ]
            
            results = scanner.scan(custom_paths=quick_paths)
            scanner.display_results()
            
        elif choice == '2':
            target = input(f"{YELLOW}Enter target URL or IP: {RESET}").strip()
            if not target:
                print(f"{RED}❌ Please enter a valid target!{RESET}")
                continue
            
            print(f"{BLUE}Enter custom paths (one per line, empty line to finish):{RESET}")
            custom_paths = []
            while True:
                path = input(f"{WHITE}Path: {RESET}").strip()
                if not path:
                    break
                custom_paths.append(path)
            
            if not custom_paths:
                print(f"{RED}❌ No paths entered!{RESET}")
                continue
            
            threads = input(f"{YELLOW}Number of threads (default 10): {RESET}").strip()
            threads = int(threads) if threads.isdigit() else 10
            
            scanner = WebDirectoryScanner(target, threads=threads)
            results = scanner.scan(custom_paths=custom_paths)
            scanner.display_results()
            
        elif choice == '3':
            target = input(f"{YELLOW}Enter target URL or IP: {RESET}").strip()
            if not target:
                print(f"{RED}❌ Please enter a valid target!{RESET}")
                continue
                
            threads = input(f"{YELLOW}Number of threads (default 20): {RESET}").strip()
            threads = int(threads) if threads.isdigit() else 20
            
            print(f"{RED}⚠️  This will perform a comprehensive scan with {len(COMMON_PATHS)} requests!{RESET}")
            confirm = input(f"{YELLOW}Continue? (y/N): {RESET}").strip().lower()
            
            if confirm != 'y':
                continue
            
            scanner = WebDirectoryScanner(target, threads=threads)
            results = scanner.scan()
            scanner.display_results()
            
        elif choice == '0':
            break
            
        else:
            print(f"{RED}❌ Invalid selection!{RESET}")
        
        input(f"\n{BOLD}{CYAN}Press Enter to continue...{RESET}")

if __name__ == "__main__":
    run()
