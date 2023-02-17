import base64
import json
import sqlite3
from Crypto.Cipher import AES
import win32crypt


class BraveDecrypt:
    def __init__(self, db_login_data, db_cookies, db_encrypted_key):
        self.db_login_data = db_login_data
        self.db_cookies = db_cookies
        self.db_encrypted_key = db_encrypted_key
        self.master_key = ""
        self.cookies = []
        self.logins = []


    def _decrypt_master_key(self):
        with open(self.db_encrypted_key,"r", encoding='utf-8') as file:
            local_state = file.read()
            local_state = json.loads(local_state)

        key_encrypted_decode = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        self.master_key = win32crypt.CryptUnprotectData(key_encrypted_decode)[1]


    def _decrypt_password(self, password_value):
        initialization_vector = password_value[3:15]
        encrypted_password = password_value[15:len(password_value) - 16]
        cipher = AES.new(self.master_key, AES.MODE_GCM, initialization_vector)
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        return decrypted_password 


    def _decrypt_cookie(self, encrypted_value):
        initialization_vector = encrypted_value[3:15]
        encrypted_cookie = encrypted_value[15:len(encrypted_value) - 16]
        cipher = AES.new(self.master_key, AES.MODE_GCM, initialization_vector)
        decrypted_cookie = cipher.decrypt(encrypted_cookie).decode()
        return decrypted_cookie


    def _store_logins(self):
        sqlite_connection = sqlite3.connect(self.db_login_data)
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute("SELECT origin_url, \
                                        action_url, \
                                        username_value, \
                                        password_value from logins"
                              )
        for origin_url, \
                action_url, \
                username_value, \
                password_value in sqlite_cursor.fetchall():
            decrypted_password = self._decrypt_password(password_value)
            login = []
            login.append(origin_url)
            login.append(action_url)
            login.append(username_value)
            login.append(decrypted_password)
            self.logins.append(login)

        sqlite_cursor.close()
        sqlite_connection.close()


    def _store_cookies(self):
        sqlite_connection = sqlite3.connect(self.db_cookies)
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute("SELECT expires_utc, \
                                        host_key, \
                                        name, \
                                        value, \
                                        encrypted_value, \
                                        is_persistent from cookies"
                              )
        for expires_utc, \
                host_key, name, \
                value, \
                encrypted_value, \
                is_persistent in sqlite_cursor.fetchall():
            decrypt_cookie = self._decrypt_cookie(encrypted_value)
            cookie = []
            cookie.append(expires_utc)
            cookie.append(host_key)
            cookie.append(name)
            cookie.append(value)
            cookie.append(decrypt_cookie)
            cookie.append(is_persistent)
            self.cookies.append(cookie)

        sqlite_cursor.close()
        sqlite_connection.close()


    def _generate_logins_file(self):
        self._store_logins()
        with open("logins.txt","w", encoding='utf-8') as file:
            for origin_url, action_url, username_value, decrypted_password in self.logins:
                file.write("origin_url: " + origin_url + ", ")
                file.write("action_url: " + action_url + ", ")
                file.write("username: " + username_value + ", ")
                file.write("password: " + decrypted_password + "\n")


    def _generate_cookies_file(self):
        self._store_cookies()
        with open("cookies.txt","w", encoding='utf-8') as file:
            for expires_utc, \
                    host_key, \
                    name, \
                    value, \
                    encrypted_value, \
                    is_persistent in self.cookies:
                file.write("expires_utc: " + str(expires_utc) + ", ")
                file.write(host_key + ", ")
                file.write(name + ", ")
                file.write(value + ", ")
                file.write(encrypted_value + ", ")
                file.write("is_persistente: " +  str(is_persistent) + "\n")


    def start(self):
        self._decrypt_master_key()
        self._generate_cookies_file()
        self._generate_logins_file()


if __name__ == "__main__":
    brave_decrypt = BraveDecrypt(
        db_login_data="Login Data", #C:\Users\{USERNAME}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data
        db_cookies="Cookies", #C:\Users\{USERNAME}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies
        db_encrypted_key="Local State" #C:\Users\{USERNAME}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State
    )
    
    brave_decrypt.start()
