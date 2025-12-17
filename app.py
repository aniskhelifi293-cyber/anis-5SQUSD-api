import requests, os, sys, jwt, json, time, urllib3, base64, datetime, re, socket, threading
import random
from flask import Flask, request, jsonify
from protobuf_decoder.protobuf_decoder import Parser
from byte import *  # تأكد من وجود هذا الملف
from xHeaders import *  # تأكد من وجود هذا الملف
from google.protobuf.timestamp_pb2 import Timestamp

# إيقاع تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- إعدادات الـ API ---
app = Flask(__name__)

# --- بيانات عامة ---
connected_clients = {}
connected_clients_lock = threading.Lock()

# --- إعدادات أساسية ---
LOG_FILE = 'api_log.txt'

# --- دوال مساعدة ---
def log_action(action, details="", indent_level=0):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    indent = "    " * indent_level
    log_entry = f"[{timestamp}] {action}"
    if details:
        log_entry += f"\n{indent}└─ Details: {details}"
    
    print(log_entry)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry + "\n")

def load_accounts_from_file(filename="accs.txt"):
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                cleaned_line = line.strip()
                if not cleaned_line or cleaned_line.startswith("#"):
                    continue
                if ":" in cleaned_line:
                    parts = cleaned_line.split(":")
                    if len(parts) >= 2:
                        account_id = parts[0].strip()
                        password = parts[1].strip()
                        if account_id and password:
                            accounts.append({'id': account_id, 'password': password})
                        else:
                            log_action("WARNING", f"Skipping invalid line (empty id or password): '{cleaned_line}'")
                    else:
                        log_action("WARNING", f"Skipping malformed line (not enough parts): '{cleaned_line}'")
                else:
                    log_action("WARNING", f"Skipping line without ':' separator: '{cleaned_line}'")
        log_action("ACCOUNTS_LOADED", f"Successfully loaded {len(accounts)} valid accounts from {filename}")
    except FileNotFoundError:
        log_action("ERROR", f"File {filename} not found!")
    except Exception as e:
        log_action("ERROR", f"An error occurred while reading {filename}: {e}")
    
    return accounts

# --- الكلاس الرئيسي للاتصال باللعبة (FF_CLient) ---
class FF_CLient():
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        # استدعاء الدالة من هنا
        self.Get_FiNal_ToKen_0115()     
        
    def Connect_SerVer_OnLine(self, Token, tok, host, port, key, iv, host2, port2):
        try:
            self.AutH_ToKen_0115 = tok    
            self.CliEnts2 = socket.create_connection((host2, int(port2)))
            self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))                  
        except Exception as e:
            log_action("ERROR", f"Connect_SerVer_OnLine for {self.id}: {e}")
            time.sleep(5)
            self.Get_FiNal_ToKen_0115() # إعادة المحاولة
        
        while True:
            try:
                self.DaTa2 = self.CliEnts2.recv(99999)
                if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:	    	    
                    self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                    self.AutH = self.packet['5']['data']['7']['data']
            except Exception as e:
                time.sleep(1)
                try:
                    self.CliEnts2.close()
                except: pass
                self.Get_FiNal_ToKen_0115() # إعادة المحاولة
                                                            
    def Connect_SerVer(self, Token, tok, host, port, key, iv, host2, port2):
        self.AutH_ToKen_0115 = tok    
        self.CliEnts = socket.create_connection((host, int(port)))
        self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
        self.DaTa = self.CliEnts.recv(1024)          	        
        threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token, tok, host, port, key, iv, host2, port2), daemon=True).start()
        
        self.key = key
        self.iv = iv
        
        with connected_clients_lock:
            connected_clients[self.id] = self
            log_action("ACCOUNT_CONNECTED", f"Account {self.id} is now online and ready.")

        while True:      
            try:
                self.DaTa = self.CliEnts.recv(1024)   
                if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):	            		
                    try:            		    
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'):
                            self.CliEnts2.close()
                        self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)                    		                    
                    except Exception:
                        try:
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                        except Exception:
                            self.Get_FiNal_ToKen_0115()

            except Exception:
                try:
                    self.CliEnts.close()
                    if hasattr(self, 'CliEnts2'):
                        self.CliEnts2.close()
                except: pass
                self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                                    
    def GeT_Key_Iv(self, serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp, key, iv = my_message.field21, my_message.field22, my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv    

    def Guest_GeneRaTe(self, uid, password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        self.dataa = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        try:
            if not uid or not password:
                log_action("ERROR", f"Invalid account data for {uid}. UID or password is empty.")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa, timeout=30)
            
            if self.response.status_code != 200:
                log_action("HTTP_ERROR", f"Failed to get access token for {uid}. Status: {self.response.status_code}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            response_data = self.response.json()
            
            if 'access_token' not in response_data or 'open_id' not in response_data:
                log_action("API_ERROR", f"Incomplete response for {uid}. Data: {response_data}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
            
            self.Access_ToKen = response_data['access_token']
            self.Access_Uid = response_data['open_id']
            
            log_action("TOKEN_RECEIVED", f"Successfully got token for account {uid} from Garena servers.")
            time.sleep(0.5)

            return self.ToKen_GeneRaTe(self.Access_ToKen, self.Access_Uid)
            
        except requests.exceptions.RequestException as e:
            log_action("CONNECTION_ERROR", f"Network error while getting token for {uid}.", indent_level=1)
            log_action("EXCEPTION_DETAILS", str(e), indent_level=2)
            time.sleep(5)
            return self.Guest_GeneRaTe(uid, password)
        except Exception as e:
            log_action("UNKNOWN_ERROR", f"An unexpected error occurred for {uid}.", indent_level=1)
            log_action("EXCEPTION_DETAILS", str(e), indent_level=2)
            time.sleep(2)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self, JwT_ToKen, PayLoad):
        self.UrL = 'https://clientbp.ggwhitehawk.com/GetLoginData'
        self.HeadErs = { 'Expect': '100-continue', 'Authorization': f'Bearer {JwT_ToKen}', 'X-Unity-Version': '2018.4.11f1', 'X-GA': 'v1 1', 'ReleaseVersion': 'OB51', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)', 'Host': 'clientbp.ggwhitehawk.com', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate, br' }       
        try:
            self.Res = requests.post(self.UrL, headers=self.HeadErs, data=PayLoad, verify=False, timeout=30)
            if self.Res.content:
                hex_content = self.Res.content.hex()
                self.BesTo_data = json.loads(DeCode_PackEt(hex_content))  
                address = self.BesTo_data['32']['data']; address2 = self.BesTo_data['14']['data']
                ip = address[:len(address) - 6]; ip2 = address2[:len(address2) - 6]
                port = address[len(address) - 5:]; port2 = address2[len(address2) - 5:]             
                return ip, port, ip2, port2
            else:
                log_action("ERROR", "No data in GetLoginData response.")
                return None, None, None, None
        except Exception as e:
            log_action("ERROR", f"Error in GetLoginData: {e}")
            return None, None, None, None
        
    def ToKen_GeneRaTe(self, Access_ToKen, Access_Uid):
        self.UrL = "https://loginbp.ggwhitehawk.com/MajorLogin"
        self.HeadErs = { 'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': 'OB51', 'Content-Type': 'application/x-www-form-urlencoded', 'X-GA': 'v1 1', 'Content-Length': '928', 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)', 'Host': 'clientbp.ggwhitehawk.com', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip' }   
        base_data = '1a13323032352d31302d33312030353a31383a3235220966726565206669726528013a07312e3131382e344232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3133352e3233aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014034653739616666653331343134393031353434656161626562633437303537333866653638336139326464346335656533646233333636326232653936363466f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803ff8502f003af13f803840780048c95028804b5ee0290048c95029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005c466ea05093372645f7061727479f80583e4068806019006019a060134a2060134b2062211541141595f58011f53594c59584056143a5f535a525c6b5c04096e595c3b000e61'
        
        try:
            self.dT = bytes.fromhex(base_data)
            current_time = str(datetime.now())[:-7].encode()
            self.dT = self.dT.replace(b'2025-07-30 14:11:20', current_time)        
            self.dT = self.dT.replace(b'4e79affe31414901544eaabebc4705738fe683a92dd4c5ee3db33662b2e9664f', Access_ToKen.encode())
            self.dT = self.dT.replace(b'4306245793de86da425a52caadf21eed', Access_Uid.encode())
            
            try:
                hex_data = self.dT.hex()
                if all(c in '0123456789abcdef' for c in hex_data):
                    encoded_data = EnC_AEs(hex_data)
                    self.PaYload = bytes.fromhex(encoded_data)
                else:
                    log_action("ERROR", "Invalid data for encryption.")
                    self.PaYload = self.dT
            except Exception as encoding_error:
                log_action("ERROR", f"Encryption error: {encoding_error}")
                self.PaYload = self.dT
        
        except ValueError as e:
            log_action("ERROR", f"Data conversion error: {e}")
            self.PaYload = f"uid={Access_Uid}&token={Access_ToKen}".encode()
        
        try:
            self.ResPonse = requests.post(self.UrL, headers=self.HeadErs, data=self.PaYload, verify=False, timeout=30)
            
            if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
                try:
                    if self.ResPonse.content:
                        hex_content = self.ResPonse.content.hex()
                        self.BesTo_data = json.loads(DeCode_PackEt(hex_content))
                        self.JwT_ToKen = self.BesTo_data['8']['data']           
                        self.combined_timestamp, self.key, self.iv = self.GeT_Key_Iv(self.ResPonse.content)
                        ip, port, ip2, port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen, self.PaYload)            
                        return self.JwT_ToKen, self.key, self.iv, self.combined_timestamp, ip, port, ip2, port2
                    else:
                        log_action("ERROR", "No data in MajorLogin response.")
                        raise Exception("No data in token response")
                except Exception as e:
                    log_action("ERROR", f"Failed to parse MajorLogin response: {e}")
                    time.sleep(2)
                    return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
            else:
                log_action("ERROR", f"MajorLogin response error, status: {self.ResPonse.status_code}")
                time.sleep(60)
                return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
                
        except requests.RequestException as e:
            log_action("ERROR", f"MajorLogin request error: {e}")
            time.sleep(60)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
        except Exception as e:
            log_action("ERROR", f"Unexpected error in MajorLogin: {e}")
            time.sleep(60)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
      
    def Get_FiNal_ToKen_0115(self):
        try:
            result = self.Guest_GeneRaTe(self.id, self.password)
            if not result:
                log_action("ERROR", "Failed to get tokens, retrying...")
                time.sleep(60)
                return self.Get_FiNal_ToKen_0115()
                
            token, key, iv, Timestamp, ip, port, ip2, port2 = result
            
            if not all([ip, port, ip2, port2]):
                log_action("ERROR", "Failed to get ports, retrying...")
                time.sleep(60)
                return self.Get_FiNal_ToKen_0115()
                
            self.JwT_ToKen = token        
            try:
                self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(Timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
            except Exception as e:
                log_action("ERROR", f"JWT decode error: {e}")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.__ = '00000000'
                if length == 9: self.__ = '0000000'
                elif length == 8: self.__ = '00000000'
                elif length == 10: self.__ = '000000'
                elif length == 7: self.__ = '000000000'
                else: log_action("ERROR", "Unexpected account ID length")                
                self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_, key, iv)
            except Exception as e:
                log_action("ERROR", f"Final token error: {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen, self.AutH_ToKen, ip, port, key, iv, ip2, port2)        
            return self.AutH_ToKen, key, iv
            
        except Exception as e:
            log_action("ERROR", f"Get_FiNal_ToKen_0115 error: {e}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

# --- دوال الأوامر ---
def execute_5x_command(client, target_id):
    success = False
    try:
        if hasattr(client, 'CliEnts2') and client.CliEnts2 and hasattr(client, 'key') and client.key and hasattr(client, 'iv') and client.iv:
            account_uid = getattr(client, 'AccounT_Uid', client.id)
            client.CliEnts2.send(OpEnSq(client.key, client.iv))
            time.sleep(0.5)
            client.CliEnts2.send(cHSq(5, account_uid, client.key, client.iv))
            time.sleep(0.5)
            client.CliEnts2.send(SEnd_InV(1, target_id, client.key, client.iv))
            time.sleep(5)
            client.CliEnts2.send(ExitBot('000000', client.key, client.iv))                 
            success = True
            log_action("COMMAND_EXECUTED", f"Sent 5sq invite to {target_id} using account {client.id}")
        else:
            log_action("ERROR", f"Account {client.id} is not ready for command.")
    except Exception as e:
        log_action("ERROR", f"Error executing command with {client.id}: {e}")
    return success

def get_random_accounts(count=1):
    with connected_clients_lock:
        if not connected_clients:
            return []
        available_clients = list(connected_clients.values())
        if count >= len(available_clients):
            return available_clients
        return random.sample(available_clients, count)

# --- نقاط نهاية الـ API ---
@app.route('/')
def index():
    return jsonify({
        "message": "Free Fire 5 Squad API is running!",
        "endpoints": {
            "create_5sq": "GET /create_5sq?uid=PLAYER_ID - Send a 5 squad invite."
        },
        "status": "OK"
    })

@app.route('/create_5sq', methods=['GET'])
def create_5sq():
    target_id = request.args.get('uid')
    
    if not target_id:
        return jsonify({'success': False, 'error': 'Missing uid parameter in the URL. Example: /create_5sq?uid=123456789'}), 400
    
    with connected_clients_lock:
        if not connected_clients:
            return jsonify({'success': False, 'error': 'No accounts are currently connected. Please wait or check logs.'}), 503

    client = get_random_accounts(1)[0]
    
    def run_command():
        execute_5x_command(client, target_id)
    
    threading.Thread(target=run_command, daemon=True).start()
    
    return jsonify({
        'success': True, 
        'message': f'Command to send 5sq invite to {target_id} has been queued using account {client.id}.'
    })

# --- نقطة البداية لتشغيل البرنامج ---
def start_accounts():
    log_action("STARTUP", "Starting account connection threads...")
    ACCOUNTS = load_accounts_from_file()
    if not ACCOUNTS:
        log_action("FATAL_ERROR", "No accounts found in accs.txt. Exiting.")
        sys.exit()
        
    for account in ACCOUNTS:
        log_action("STARTUP", f"Starting thread for account: {account['id']}")
        thread = threading.Thread(target=FF_CLient, args=(account['id'], account['password']), daemon=True)
        thread.start()
        time.sleep(1)

if __name__ == '__main__':
    start_accounts()
    app.run(host='0.0.0.0', port=5000, threaded=True)