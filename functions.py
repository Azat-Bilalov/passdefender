import sys, os, random, string, platform
import time
import datetime, time

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import MD5
import sqlite3
import progressbar

import cv2

from colorama import Fore
from pyfiglet import Figlet
from random import randint

class PassDefender():
    def __init__(self):
        super(PassDefender, self).__init__()
        
        # ПЕРЕМЕННЫЕ
        self.lunguage = "ru" # получает язык приложения
        self.sec = .001 # время загрузки (прогрессбара) в секудах 
        self.password = "81dc9bdb52d04dc20036dbd8313ed055" # пароль пользователя (81dc9bdb52d04dc20036dbd8313ed055 == 1234)
        self.publ = """""" # публичный ключ, нужен для шифрования БД
        self.priv = """""" # приватный ключ, нужен для расшифровки БД
        self.tel_name = "0" # имя пользователя в телеграмме (на аккаунт шлёт предупреждение бот)
        self.attempts = 3 # количество попыток пользователя войти до начала тревоги
        self.database = self.Generate(database = True) # имя БД при расшифровке

        self.Welcome()

    # ШИФРОВАНИЕ
    def crypt(self, file, public = False): # шифрование БД 
        if public != False:
            f = open(file, "rb")
            data = f.read(); f.close()
            recipient_key = RSA.import_key(public)
            file_out = open(str(file)+".bin", "wb")
        else:
            f = open(self.database, "rb")
            data = f.read(); f.close()
            recipient_key = RSA.import_key(self.publ)
            file_out = open("database.db.bin", "wb")
        
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        if public != False:
            os.remove(file)
        else:
            os.remove(self.database)

    def decrypt(self, file, private = False): # расшифровка БД 
        if private != False:
            file_in = open(file, "rb")
            private_key = RSA.import_key(private)
        else:
            file_in = open("database.db.bin", "rb")
            private_key = RSA.import_key(self.priv)

        enc_session_key, nonce, tag, ciphertext = \
            [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            session_key = cipher_rsa.decrypt(enc_session_key)
        except ValueError:
            exit("Неверный приватный ключ!")

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        if private != False:
            file_out = open(str(file[:-4]), "wb")
        else:
            file_out = open(self.database, "wb")
        file_out.write(data)
        file_in.close()
        if private != False:
            os.remove(file)
        else:
            os.remove("database.db.bin")

    def new_keys(self): # обновление публичного и приватного ключа
        key = RSA.generate(1024)
        self.priv = key.export_key()
        self.publ = key.publickey().export_key()
        pass

    def hor(self, start = False, end = False, password = False): # шифрование всех пользовательских настроек: lunguage, sec, password
        if start: # начало программы, после удачного ввода пароля (здесь расшифровка всех настроек)
            if not(os.path.isfile("temp.bin")):
                self.Error(error_en = "File 'temp.bin' not exist! Exit", error_ru = "Файл 'temp.bin' не существует! Выход")
                exit()
            if not(os.path.isfile("database.db.bin")):
                self.Error(error_en = "File 'temp.bin' not exist! Exit", error_ru = "Файл 'temp.bin' не существует! Выход")
                exit()
            self.decrypt("temp.bin", private = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCmYhbmpx55jhwFPjVxBSXSfXKOKIoHZ8ssjmxgV9zDNaPKpHOg
PVcFWIVJPiTTk7Js+Jc/unTPR2O9bQ/FqarqeJvM7NAHIUJU6rgCnyhckt8m9CP4
fzzNG32ZRUgU6QMr/CpESqabK3XUcv9AYoc2BMCa8BtD+oQVu8hS1USvDQIDAQAB
AoGAJSthG9aGRZgEdPxkgnLos+kP/CeczFI47qODnRNLz3VOecD6zredVuWjYw0l
u3lxoQv4+ATuvvafFsyEOz9v3bSHhqDLmNlumw1mrlvUubctV0p5C5GXllCG1Ar2
pWCrEmDnUcJl9i6LlzsTcj8mWjByypa4Jq3HLw2TSvM8/7kCQQC8Ge29M5kzUbAU
I6p4gdUUyMuo/bRUtovcr8wxX3cAyvUebD2WbSOhN2uET4YuYqXGghOWkx5AwtjU
pMj3/ZTpAkEA4nE7Tony+uSlEL2feDJfZm20qRjl3nx7bRgYc9FAFD+ygHZ1tN84
A+lWoGaopqc8J55RVAmGIOLp164VgKiChQJAS4INEVpZMWSlTjBTCjT0GHfSaXAO
p8LvuhNH4Ln1x3exlhjVUEFXgCwDGQXjU1N+QIWO328HQe/1osbTddlxoQJATg5Y
Mj+NOX0dhULIOMesaQOCFhQWEPZ6GWYH78x+uTwnzO6IrpuPlJGXod0hX6kgLEv/
nudVi/qMPyOsF9h+fQJAYKhGaPFqoI9M6roAWn8GkKipCK3D717ws+zF3AflqTBH
LO/Z1BBmKSOkwmC4nio4cMZvpedwqZhZt/PcyV/tbQ==
-----END RSA PRIVATE KEY-----""")
            (self.lunguage, self.sec, self.tel_name, self.attempts, self.password) = open("temp", "r").readlines()[-1].split()
            self.sec = float(self.sec)
            self.attempts = int(self.attempts)
            self.priv = b"".join(open("temp", "rb").readlines()[0:15]).strip()
            self.publ = b"".join(open("temp", "rb").readlines()[15:21]).strip()
            os.remove("temp")
            self.decrypt("database.db.bin")
            self.crypt(self.database)
        if end: # окончание программы: шифрование настроек и пароля
            self.decrypt("database.db.bin")
            self.new_keys()
            self.crypt(self.database)
            open("temp", "wb").write(self.priv)
            open("temp", "a").write("\n")
            open("temp", "ab").write(self.publ)
            open("temp", "a").write("\n" + self.lunguage + " " + str(self.sec) + " " + self.tel_name + " " + str(self.attempts) + " " + self.password)
            self.crypt("temp", public = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmYhbmpx55jhwFPjVxBSXSfXKO
KIoHZ8ssjmxgV9zDNaPKpHOgPVcFWIVJPiTTk7Js+Jc/unTPR2O9bQ/FqarqeJvM
7NAHIUJU6rgCnyhckt8m9CP4fzzNG32ZRUgU6QMr/CpESqabK3XUcv9AYoc2BMCa
8BtD+oQVu8hS1USvDQIDAQAB
-----END PUBLIC KEY-----""")
        if password != False: # получение пароля из файла, если верный - вернёт True, иначе - False
            self.decrypt("temp.bin", private = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCmYhbmpx55jhwFPjVxBSXSfXKOKIoHZ8ssjmxgV9zDNaPKpHOg
PVcFWIVJPiTTk7Js+Jc/unTPR2O9bQ/FqarqeJvM7NAHIUJU6rgCnyhckt8m9CP4
fzzNG32ZRUgU6QMr/CpESqabK3XUcv9AYoc2BMCa8BtD+oQVu8hS1USvDQIDAQAB
AoGAJSthG9aGRZgEdPxkgnLos+kP/CeczFI47qODnRNLz3VOecD6zredVuWjYw0l
u3lxoQv4+ATuvvafFsyEOz9v3bSHhqDLmNlumw1mrlvUubctV0p5C5GXllCG1Ar2
pWCrEmDnUcJl9i6LlzsTcj8mWjByypa4Jq3HLw2TSvM8/7kCQQC8Ge29M5kzUbAU
I6p4gdUUyMuo/bRUtovcr8wxX3cAyvUebD2WbSOhN2uET4YuYqXGghOWkx5AwtjU
pMj3/ZTpAkEA4nE7Tony+uSlEL2feDJfZm20qRjl3nx7bRgYc9FAFD+ygHZ1tN84
A+lWoGaopqc8J55RVAmGIOLp164VgKiChQJAS4INEVpZMWSlTjBTCjT0GHfSaXAO
p8LvuhNH4Ln1x3exlhjVUEFXgCwDGQXjU1N+QIWO328HQe/1osbTddlxoQJATg5Y
Mj+NOX0dhULIOMesaQOCFhQWEPZ6GWYH78x+uTwnzO6IrpuPlJGXod0hX6kgLEv/
nudVi/qMPyOsF9h+fQJAYKhGaPFqoI9M6roAWn8GkKipCK3D717ws+zF3AflqTBH
LO/Z1BBmKSOkwmC4nio4cMZvpedwqZhZt/PcyV/tbQ==
-----END RSA PRIVATE KEY-----""")
            h = MD5.new()
            h.update(password.encode("utf-8"))
            password = h.hexdigest()
            code = open("temp", "r").readlines()[-1].split()[-1]
            self.lunguage = open("temp", "r").readlines()[-1].split()[0]
            self.crypt("temp", public = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmYhbmpx55jhwFPjVxBSXSfXKO
KIoHZ8ssjmxgV9zDNaPKpHOgPVcFWIVJPiTTk7Js+Jc/unTPR2O9bQ/FqarqeJvM
7NAHIUJU6rgCnyhckt8m9CP4fzzNG32ZRUgU6QMr/CpESqabK3XUcv9AYoc2BMCa
8BtD+oQVu8hS1USvDQIDAQAB
-----END PUBLIC KEY-----""")
            if password == code:
                return True
            else:
                return False

    # ЗАЩИТА
    def Anxiety(self): # отправка предупреждения пользователю и фото
        if self.tel_name != "0":
            self.Telegram()
        self.Log(error = True)
        self.Error("Number of retries exceeded! ", "Превышено количество попыток! ", end = False)
        self.Photo()
        exit()

    def Telegram(self): # отправляет предупреждению по телеграмму
        pass

    # ВЫВОД ТЕКСТОВОЙ ИНФОРМАЦИИ
    def TPrint(self, text, color = ""): # вывод построчно текста
        text = color + text
        for str in text.split("\n"):
            print(str)
            time.sleep(.05)

    def Progressbar(self): # реализация загрузки 
        print(Fore.CYAN)
        bar = progressbar.ProgressBar().start()
        for t in range(101):
            bar.update(t) 
            time.sleep(self.sec + randint(0, 10) / 1000)
        time.sleep(0.5)
        print()

    def Figlet(self, color = ""): # вывод заголовка (фиглета)
        self.TPrint(color + """
    PPPPPPPPPPPPPPPPP        DDDDDDDDDDDDD             RRRRRRRRRRRRRRRRR
    P::::::::::::::::P       D::::::::::::DDD          R::::::::::::::::R
    P::::::PPPPPP:::::P      D:::::::::::::::DD        R::::::RRRRRR:::::R
    PP:::::P     P:::::P     DDD:::::DDDDD:::::D       RR:::::R     R:::::R
      P::::P     P:::::P       D:::::D    D:::::D        R::::R     R:::::R
      P::::P     P:::::P       D:::::D     D:::::D       R::::R     R:::::R
      P::::PPPPPP:::::P        D:::::D     D:::::D       R::::RRRRRR:::::R
      P:::::::::::::PP         D:::::D     D:::::D       R:::::::::::::RR
      P::::PPPPPPPPP           D:::::D     D:::::D       R::::RRRRRR:::::R
      P::::P                   D:::::D     D:::::D       R::::R     R:::::R
      P::::P                   D:::::D     D:::::D       R::::R     R:::::R
      P::::P                   D:::::D    D:::::D        R::::R     R:::::R
    PP::::::PP               DDD:::::DDDDD:::::D       RR:::::R     R:::::R
    P::::::::P               D:::::::::::::::DD        R::::::R     R:::::R
    P::::::::P               D::::::::::::DDD          R::::::R     R:::::R
    PPPPPPPPPP               DDDDDDDDDDDDD             RRRRRRRR     RRRRRRR""")

    # МЕНЮ
    def Welcome(self, n = 0): # первый вход пользователя
        self.Clear()
        self.Figlet(Fore.YELLOW)
        self.Log(read = True)  
        code = self.Insert(menu = False, en_text = "CODE", ru_text = "CODE")
        self.Progressbar()
        if self.hor(password = code):
            self.Log()
            self.hor(start = True)
        else:
            self.Error(error_en = "Wrong code. Try again", error_ru = "Неверный код. Повторите попытку")
            n += 1
            if n >= self.attempts:
                self.Anxiety()
            self.Welcome(n = n)

    def Menu(self): # главное меню
        self.Clear()
        self.Figlet(Fore.BLUE)
        if self.lunguage == "en":
            self.TPrint("""
[1] Search account
[2] Add new account
[3] Delete account
[4] Generate password
[5] Settings
[0] Exit""", Fore.GREEN)
        elif self.lunguage == "ru":
            self.TPrint("""
[1] Найти аккаунт
[2] Добавить аккаунт
[3] Удалить аккаунт
[4] Сгенерировать пароль
[5] Настройки
[0] Выход""", Fore.GREEN)
        n = self.Insert(num_list = [i for i in range(0, 6)])
        if n == 0:
            self.hor(end = True)
            self.Text("Exit", "Выход", color = Fore.RED)
            exit()
        elif n == 1:
            self.Search_DB()
        elif n == 2:
            self.Save_DB()
        elif n == 3:
            self.Delete_DB()
        elif n == 4:
            self.Generate()
        elif n == 5:
            code = self.Insert(menu = False, en_text = "Enter code again", ru_text = "Введите код повторно")
            h = MD5.new(); h.update(code.encode("utf-8"))
            self.Progressbar()
            if h.hexdigest() == self.password:
                self.Settings()
            else:
                self.hor(end = True)
                self.Error("Incorrectly code. Exit", "Неверный код. Выход", end = False)
                exit()

    def Settings(self): # меню настроек
        self.Clear()
        self.Figlet(Fore.CYAN)
        if self.lunguage == "en":
            self.TPrint("""
[1] Reload code
[2] Choose lunguage
[3] Set loading time
[4] Output logs
[5] Enter passphrase
[0] Back""", Fore.GREEN)
        elif self.lunguage == "ru":
            self.TPrint("""
[1] Изменить код
[2] Выбрать язык
[3] Установить время загрузки
[4] Вывод журнала посещений
[5] Ввести кодовую фразу
[0] Назад""", Fore.GREEN)
        n = self.Insert(num_list = [i for i in range(0, 6)])
        if n == 0:
            self.Error("Back", "Назад")
            self.Menu()
        elif n == 1:
            pr = self.Generate(database = True)[:-3]
            if pr == self.Insert(menu = False, en_text = f"Enter chars ({pr})", ru_text = f"Введите символы ({pr})"):
                code = self.Insert(menu = False, en_text = "Enter new code", ru_text = "Введите новый код")
                h = MD5.new(); h.update(code.encode("utf-8"))
                self.password = h.hexdigest()
                self.Progressbar()
                self.Success()
                self.Settings()
            else:
                self.Error("Incorrectly entered chars", "Неверно введены символы")
                self.Menu()
        elif n == 2:
            l = self.Insert(menu = False, en_text = "Choose lunguage ([1] english, [2] russia)", ru_text = "Выберете язык ([1] английский, [2] русский)", num_out = True, num_list = [1, 2])
            if l == 1:
                self.lunguage = "en"
            elif l == 2:
                self.lunguage = "ru"
            self.Progressbar()
            self.Success()
            self.Settings()
        elif n == 3:
            self.sec = self.Insert(menu = False, en_text = "Set loading time (milliseconds)", ru_text = "Установите время загрузки (в миллисекундах)", num_out = True, num_fixed = False) / 1000
            self.Progressbar()
            self.Success()
            self.Settings()
        elif n == 4:
            self.Progressbar()
            if not(os.path.isfile("log.txt")):
                self.Error("'Log.txt' not exist", "'Log.txt' не существует")
            else:
                try:
                    self.TPrint(f"""
{" ".join(open("log.txt", "r").readlines()[-5].split()[:2])}
{" ".join(open("log.txt", "r").readlines()[-4].split()[:2])}
{" ".join(open("log.txt", "r").readlines()[-3].split()[:2])}
{" ".join(open("log.txt", "r").readlines()[-2].split()[:2])}
{" ".join(open("log.txt", "r").readlines()[-1].split()[:2])}""", color = Fore.GREEN)
                except IndexError:
                    print(Fore.GREEN + "\n" + f"""{" ".join(open("log.txt", "r").readlines()[-1].split()[:2])}""")
                self.Success()
            self.Settings()
        elif n == 5:
            phrase = self.Insert(menu = False, en_text = "Enter passphrase", ru_text = "Введите секретную фразу")
            self.Progressbar()
            if phrase.lower() == "hello" or phrase.lower() == "привет":
                self.Text("Hi, username!", "Привет, пользователь!")
                input()
            else:
                self.Error("Passphrase not found", "Секретная фраза с этим именем не найдена")
            self.Settings()

    # РАБОТА С БАЗОЙ ДАННЫХ И ПАРОЛЯМИ
    def Search_DB(self): # получения данных пользователя из БД
        service = self.Insert(menu = False, en_text = "Enter service name", ru_text = "Введите название сервиса")
        self.Progressbar()
        self.decrypt("database.db.bin")
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        cursor.execute(f"""SELECT * FROM accounts WHERE services="{service.upper()}" """)
        res = cursor.fetchone()
        conn.close()
        self.crypt(self.database)
        print()
        if res != None:
            if self.lunguage == "en":
                print(Fore.YELLOW + f"Service: {service}\nUsername: {res[2]}\nPassword: {res[3]}")
                input(Fore.YELLOW + "\nPress 'Enter' to continue... ")
            elif self.lunguage == "ru":
                print(Fore.YELLOW + f"Сервис: {service}\nИмя пользователя: {res[2]}\nПароль: {res[3]}")
                input(Fore.YELLOW + "\nНажмите 'Enter' для продолжения... ")
        else:
            if self.lunguage == "en":
                print(Fore.RED + "Service not found")
                input(Fore.YELLOW + "\nPress 'Enter' to continue... ")
            elif self.lunguage == "ru":
                print(Fore.RED + "Сервис не найден")
                input(Fore.YELLOW + "\nНажмите 'Enter' для продолжения... ")

    def Save_DB(self): # сохранение аккаунта в БД
        service = self.Insert(menu = False, en_text = "Enter new service name", ru_text = "Введите название нового сервиса")
        username = self.Insert(menu = False, en_text = "Enter the usernamename", ru_text = "Введите имя пользователя", group = True)
        password = self.Insert(menu = False, en_text = "Enter the password", ru_text = "Введите пароль", group = True)

        self.Progressbar()
        self.decrypt("database.db.bin")

        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()      
        cursor.execute(f"""SELECT * FROM accounts WHERE services="{service.upper()}" """)
        res = cursor.fetchone()

        if res != None:
            self.Text("Service with this name exist. Reload?\n[1] Reload\n[0] Change name", "Сервис с этим именем существует. Перезаписать?\n[1] Перезаписать\n[0] Изменить имя")
            num = self.Insert()

            if num == 1:
                cursor.execute(f"""DELETE FROM accounts WHERE services="{service.upper()}";""")
                conn.commit()
                cursor.execute(f"""INSERT INTO accounts VALUES (Null, "{service.upper()}", "{username}", "{password}");""")
                conn.commit()
            elif num == 0:
                while True:
                    service = self.Insert(menu = False, en_text = "Enter new service name again", ru_text = "Введите название нового сервиса снова")
                    cursor.execute(f"""SELECT * FROM accounts WHERE services="{service.upper()}" """)
                    res = cursor.fetchone()
                    if res != None:
                        self.Error("Service with this name exist", "Сервис с этим именем существует", end = False)
                    else:
                        cursor.execute(f"""INSERT INTO accounts VALUES (Null, "{service.upper()}", "{username}", "{password}");""")
                        conn.commit()
                        break
        else:
            cursor.execute(f"""INSERT INTO accounts VALUES (Null, "{service.upper()}", "{username}", "{password}");""")
            conn.commit()

        conn.close()
        self.crypt(self.database)
        self.Success()

    def Delete_DB(self): # удаление аккаунта из БД
        service = self.Insert(menu = False, en_text = "Enter service name", ru_text = "Введите название сервиса")
        
        self.decrypt("database.db.bin")

        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()

        cursor.execute(f"""SELECT * FROM accounts WHERE services="{service.upper()}" """)
        res = cursor.fetchone()

        self.Progressbar()

        if res == None:
            self.Error("Service not found", "Сервис не найден")
        else:
            cursor.execute(f"""DELETE FROM accounts WHERE services="{service.upper()}";""")
            conn.commit()
            self.Success()
        conn.close()
        self.crypt(self.database)

    def Generate(self, database = False): # сгенерировать пароль
        result = ""
        if database:
            for i in range(randint(5, 13)):
                result += random.choice(string.ascii_letters+'012345678901234567890123456789')
            return result + ".db"
        lenght = self.Insert(menu = False, en_text = "Enter password lenght", ru_text = "Введите длину пароля", num_out = True, num_fixed = True, num_list = [i for i in range(1, 10001)])
        if self.Insert(menu = False, en_text = "Use: all chars [1] or some chars [0]", ru_text = "Использовать: все символы [1] или некоторые [0]", num_out = True, group = True) == 1:
            g = 1
            while True:
                for i in range(lenght):
                    result += random.choice(string.ascii_letters+'012345678901234567890123456789!@$%^&*()_+=-?:;№"!')
                print(Fore.CYAN + "\n" + result)
                if self.Insert(menu = False, en_text = "Regenerate [1] or Back to menu [0]", ru_text = "Сгенирировать снова [1] или Вернуться в меню [0]", num_out = True) == 0:
                    break
                result = ""
        else:
            g = 1
            while True:
                for i in range(lenght):
                    result += random.choice(string.ascii_letters+'012345678901234567890123456789')
                print(Fore.CYAN + "\n" + result)
                if self.Insert(menu = False, en_text = "Regenerate [1] or Back to menu [0]", ru_text = "Сгенирировать снова [1] или Вернуться в меню [0]", num_out = True) == 0:
                    break
                result = ""
        self.Success()

    # ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ
    def Insert(self, menu = True, en_text = "", ru_text = "", color = Fore.BLUE, num_out = False, num_fixed = True, num_list = [0, 1], space = True, group = False): # обрабатывание пользовательского ввода
        if not(group): print()
        if menu:
            out = input(color + "> ")
            # self.Progressbar()
            if not(out.isdigit()):
                print()
                if self.lunguage == "en":
                    print(Fore.RED + "No number entered! Enter again")
                elif self.lunguage == "ru":
                    print(Fore.RED + "Введено не число! Повторите попытку")
                input()
                return False
            elif not(int(out) in num_list):
                print()
                if self.lunguage == "en":
                    print(Fore.RED + "This menu item doesn't exist! Enter again")
                elif self.lunguage == "ru":
                    print(Fore.RED + "Такого пункта не существует! Повторите попытку")
                input()
                return False
            return int(out)

        if self.lunguage == "en": 
            out = input(color + en_text + ": ")
        elif self.lunguage == "ru":
            out = input(color + ru_text + ": ")

        num_list = [str(i) for i in num_list]

        while (space and out == "") or (num_out and not(out.isdigit())) or (num_out and num_fixed and not(out in num_list)):
            if not(group): print()
            if space and out == "": # если пользователь ввёл пустую строку
                if self.lunguage == "en":
                    out = input(Fore.RED + "Empty string entered! " + color + "Enter again: ")
                elif self.lunguage == "ru":
                    out = input(Fore.RED + "Ведена пустая строка! " + color + "Сделайте ввод повторно: ")
            if num_out and not(out.isdigit()) and out != "": # если пользователь ввёл буквы, а нужно число
                if self.lunguage == "en":
                    out = input(Fore.RED + "Letters entered! " + color + "Enter number: ")
                elif self.lunguage == "ru":
                    out = input(Fore.RED + "Ведены символы! " + color + "Ведите число: ")
            if out.isdigit():
                if num_out and num_fixed and not(out in num_list): # если пользователь ввёл число, но не из диапазона
                    if self.lunguage == "en":
                        out = input(Fore.RED + "This menu item doesn't exist! " + color + en_text + ": ")
                    elif self.lunguage == "ru":
                        out = input(Fore.RED + "Такого пункта не существует! " + color + ru_text + ": ")

        if num_out: out = int(out)
        
        return out

    def Text(self, en_text, ru_text, color = Fore.YELLOW): # вывод текста
        print()
        if self.lunguage == "en":
            print(color + en_text)
        elif self.lunguage == "ru":
            print(color + ru_text)

    def Success(self, color = Fore.YELLOW): # вывод успеха операции
        print()
        if self.lunguage == "en":
            input(color + "Success! Press 'Enter' to continue...")
        elif self.lunguage == "ru":
            input(color + "Успех! Нажмите 'Enter' для продолжения...")

    def Error(self, error_en, error_ru, end = True): # вывод ошибки
        print()
        if self.lunguage == "en":
            if end:
                input(Fore.RED + error_en)
            else:
                print(Fore.RED + error_en)
        elif self.lunguage == "ru":
            if end:
                input(Fore.RED + error_ru)
            else:
                print(Fore.RED + error_ru)

    def Photo(self): # делает фото
        t = datetime.datetime.today().strftime("%d-%m %H.%M.%S")
        cap = cv2.VideoCapture(0)

        for i in range(30):
            cap.read()

        ret, frame = cap.read()
        cv2.imwrite(f"img/{t}.png", frame)
        cap.release()
        cv2.destroyAllWindows()

    def Clear(sefl): # очищает консоль
        if platform.system() == "Windows": os.system("cls") 
        elif platform.system() == "Linux": os.system("clear")

    def Log(self, read = False, error = False): # запись в файл логи входов пользователей
        t = datetime.datetime.today().strftime("%d.%m.%Y %H:%M:%S")
        if not(os.path.isfile("log.txt")):
            open("log.txt", "w").write(f"{t}\n")
        if read:
            # if len(open("log.txt", "r").readlines()[-1].split()) == 3:
            if open("log.txt", "r").readlines()[-1][-2] == " ":
                if datetime.datetime.now().hour < int(open("log.txt", "r").readlines()[-1].split()[1].split(':')[0]) + 3:
                    self.Error("Sleeping mode. Exit", "Sleeping mode. Exit")
                    exit()
                else:
                    pass
        elif error:
            open("log.txt", "a").write(f"{t} \n")
        else:
            open("log.txt", "a").write(f"{t}\n")

