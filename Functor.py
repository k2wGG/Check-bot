#!/usr/bin/env python3

import os
import time
import json
import base64
import asyncio
from datetime import datetime, timedelta, timezone

import pytz
from aiohttp import ClientSession, ClientResponseError, ClientTimeout
from fake_useragent import FakeUserAgent
from colorama import init, Fore, Style

# Инициализация цветного вывода
init(autoreset=True)

MOSCOW_TZ = pytz.timezone("Europe/Moscow")


class FunctorChecker:
    """
    Класс, который:
    - Читает accounts.txt, определяет формат строки (JWT или email:pass).
    - Для JWT-токена проверяет срок exp, если не истёк – выполняет check-in.
    - Для email:pass логинится и делает check-in по полученному токену.
    - Повторяет процедуру каждые 12 часов.
    """

    def __init__(self) -> None:
        # Общие заголовки
        self.common_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9",
            "Connection": "keep-alive",
            "Host": "node.securitylabs.xyz",
            "Referer": "https://node.securitylabs.xyz/?from=extension&type=signin&referralCode=cm6rjma6p4lbrlj1b1qoeq0vp",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": FakeUserAgent().random,
        }

    # ========== Вспомогательные методы ==========

    @staticmethod
    def clear_screen():
        """
        Очищает терминал (cls для Windows, clear для Unix).
        """
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def styled_log(message: str) -> None:
        """
        Лог с локальным временем (MSK).
        """
        now_local = datetime.now().astimezone(MOSCOW_TZ)
        date_str = now_local.strftime("%d-%m-%Y %H:%M:%S %Z")
        print(
            f"{Fore.CYAN}{Style.BRIGHT}[ {date_str} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{message}",
            flush=True
        )

    @staticmethod
    def short_banner():
        """
        Короткий ASCII-баннер, с небольшим отступом слева.
        """
        FunctorChecker.clear_screen()
        left_pad = " " * 15
        print(
            f"{Fore.GREEN}{Style.BRIGHT}"
            f"{left_pad}==========================================\n"
            f"{left_pad}  FUNCTOR PROTOCOL - АВТОФАРМ НОД (MOD)\n"
            f"{left_pad}==========================================\n"
            f"{Style.RESET_ALL}"
        )

    @staticmethod
    def format_seconds(sec: int) -> str:
        """
        Форматируем секунды в ЧЧ:ММ:СС.
        """
        h, remainder = divmod(sec, 3600)
        m, s = divmod(remainder, 60)
        return f"{h:02}:{m:02}:{s:02}"

    @staticmethod
    def partial_hide(text: str) -> str:
        """
        Маскируем часть email/токена для логов.
        """
        if "@" in text:
            # это email
            local, domain = text.split("@", 1)
            return local[:3] + "***" + local[-3:] + "@" + domain
        else:
            # считаем, что это JWT
            return text[:4] + "*****" + text[-4:]

    # ========== Проверка токена ==========

    @staticmethod
    def check_token_status(now_utc: int, exp_utc: int, exp_str_msk: str):
        """
        Логируем статус: просрочен или активен (до exp).
        """
        if now_utc > exp_utc:
            FunctorChecker.styled_log(
                f"{Fore.CYAN + Style.BRIGHT}Токен :{Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT} ПРОСРОЧЕН{Style.RESET_ALL}"
            )
        else:
            FunctorChecker.styled_log(
                f"{Fore.CYAN + Style.BRIGHT}Токен :{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT} АКТИВЕН{Style.RESET_ALL}"
                f"{Fore.MAGENTA + Style.BRIGHT} (Истекает: {exp_str_msk}){Style.RESET_ALL}"
            )

    # ========== Разбор JWT ==========

    @staticmethod
    def extract_jwt_data(entry: str):
        """
        Пытаемся распарсить токен (header.payload.signature).
        Возвращаем (email, sub, exp) или (None, None, None) если ошибка.
        """
        try:
            parts = entry.split(".")
            if len(parts) != 3:
                return None, None, None
            payload_enc = parts[1]
            decoded_bytes = base64.urlsafe_b64decode(payload_enc + "==")
            payload_str = decoded_bytes.decode("utf-8")
            payload_json = json.loads(payload_str)
            user_email = payload_json.get("email")
            user_sub = payload_json.get("sub")
            exp_time = payload_json.get("exp")
            return user_email, user_sub, exp_time
        except Exception:
            return None, None, None

    # ========== Запросы: email+pass / userInfo / checkIn ==========

    async def attempt_email_signin(self, email: str, password: str, attempts=5) -> str:
        """
        Пытаемся залогиниться по email+pass, возвращаем accessToken или None.
        """
        url_login = "https://node.securitylabs.xyz/api/v1/auth/signin-user"
        data_json = json.dumps({"email": email, "password": password})
        heads = {
            **self.common_headers,
            "Content-Length": str(len(data_json)),
            "Content-Type": "application/json"
        }
        for i in range(attempts):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as sess:
                    async with sess.post(url_login, headers=heads, data=data_json) as resp:
                        resp.raise_for_status()
                        res = await resp.json()
                        return res.get("accessToken")
            except (ClientResponseError, Exception):
                if i < attempts - 1:
                    await asyncio.sleep(3)
        return None

    async def request_user_info(self, token: str) -> dict:
        """
        GET /api/v1/users чтобы узнать баланс, dipInitMineTime, etc.
        """
        link = "https://node.securitylabs.xyz/api/v1/users"
        heads = {
            **self.common_headers,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        for _ in range(5):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as s:
                    async with s.get(link, headers=heads) as resp:
                        resp.raise_for_status()
                        return await resp.json()
            except (ClientResponseError, Exception):
                await asyncio.sleep(3)
        return {}

    async def perform_checkin(self, token: str, user_id: str) -> dict:
        """
        Вызов check-in по user_id.
        """
        url_checkin = f"https://node.securitylabs.xyz/api/v1/users/earn/{user_id}"
        heads = {
            **self.common_headers,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        for _ in range(5):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as s:
                    async with s.get(url_checkin, headers=heads) as resp:
                        resp.raise_for_status()
                        return await resp.json()
            except (ClientResponseError, Exception):
                await asyncio.sleep(3)
        return {}

    # ========== Логика check-in ==========

    async def manage_checkin(self, token: str, user_id: str):
        """
        Узнаём баланс, last_checkin. Если не делалось — делаем.
        Если делалось, проверяем, прошли ли 24ч.
        """
        info = await self.request_user_info(token)
        if not info:
            self.styled_log(f"{Fore.RED}Не удалось получить данные пользователя.{Style.RESET_ALL}")
            return

        bal = info.get("dipTokenBalance", "N/A")
        last_c_str = info.get("dipInitMineTime")
        self.styled_log(f"{Fore.CYAN}Баланс:{Style.RESET_ALL} {bal} points")

        if not last_c_str:
            # первый check-in
            c_res = await self.perform_checkin(token, user_id)
            if c_res:
                got_award = c_res.get("tokensToAward", "N/A")
                self.styled_log(
                    f"{Fore.CYAN}Чек-ин:{Style.RESET_ALL} {Fore.GREEN}Успешно!{Style.RESET_ALL} | "
                    f"Награда: {got_award} points"
                )
            else:
                self.styled_log(
                    f"{Fore.CYAN}Чек-ин:{Style.RESET_ALL} {Fore.RED}Не выполнен{Style.RESET_ALL}"
                )
        else:
            # check-in уже был, проверяем 24ч
            dt_now_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
            dt_parsed = datetime.strptime(last_c_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            dt_next = dt_parsed + timedelta(hours=24)
            next_str = dt_next.astimezone(MOSCOW_TZ).strftime("%d-%m-%Y %H:%M:%S %Z")

            if dt_now_utc >= dt_next:
                # делаем повторный
                c2 = await self.perform_checkin(token, user_id)
                if c2:
                    prize = c2.get("tokensToAward", "N/A")
                    self.styled_log(
                        f"{Fore.CYAN}Чек-ин:{Style.RESET_ALL} {Fore.GREEN}Повтор успешно{Style.RESET_ALL} | "
                        f"Награда: {prize} points"
                    )
                else:
                    self.styled_log(
                        f"{Fore.CYAN}Чек-ин:{Style.RESET_ALL} {Fore.RED}Не сработало повторно{Style.RESET_ALL}"
                    )
            else:
                self.styled_log(
                    f"{Fore.CYAN}Чек-ин:{Style.RESET_ALL} Уже сделан. Следующий после: {next_str}"
                )

    # ========== Основной 12-часовой цикл ==========

    async def main_cycle(self):
        """
        1) Читаем accounts.txt (строка на аккаунт).
        2) Если '@' нет – JWT, иначе email:pass
        3) После прохода – ждём 12 часов, повторяем.
        """
        try:
            with open("accounts.txt", "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except FileNotFoundError:
            self.styled_log(f"{Fore.RED}Файл 'accounts.txt' не найден.{Style.RESET_ALL}")
            return

        while True:
            self.short_banner()
            self.styled_log(f"{Fore.GREEN}Всего аккаунтов: {len(lines)}{Style.RESET_ALL}")

            for line in lines:
                # проверяем, нет ли '@'
                if "@" not in line:
                    # считаем JWT
                    now_int = int(time.time())
                    user_n, user_s, user_e = self.extract_jwt_data(line)
                    if user_n and user_s and user_e:
                        # лог
                        masked_n = self.partial_hide(user_n)
                        self.styled_log(
                            f"{Fore.MAGENTA}---------------------- [{masked_n}] ----------------------{Style.RESET_ALL}"
                        )
                        # проверка exp
                        ex_str = datetime.fromtimestamp(user_e, timezone.utc)\
                                        .astimezone(MOSCOW_TZ)\
                                        .strftime("%d-%m-%Y %H:%M:%S %Z")
                        self.check_token_status(now_int, user_e, ex_str)

                        if now_int <= user_e:
                            # выполняем check-in
                            await self.manage_checkin(line, user_s)
                            await asyncio.sleep(3)
                else:
                    # email:password
                    try:
                        mail, passwd = line.split(":", 1)
                    except ValueError:
                        self.styled_log(f"{Fore.RED}Неверный формат (email:pass): {line}{Style.RESET_ALL}")
                        continue

                    masked_mail = self.partial_hide(mail)
                    self.styled_log(
                        f"{Fore.MAGENTA}---------------------- [{masked_mail}] ----------------------{Style.RESET_ALL}"
                    )
                    tok = await self.attempt_email_signin(mail, passwd)
                    if tok:
                        nm_j, s_j, e_j = self.extract_jwt_data(tok)
                        if s_j:
                            await self.manage_checkin(tok, s_j)
                            await asyncio.sleep(3)

            # пауза 12ч
            self.styled_log(f"{Fore.CYAN}Все аккаунты обработаны. Ждём 12 часов...{Style.RESET_ALL}")
            remainder = 12 * 3600
            while remainder > 0:
                frmt = self.format_seconds(remainder)
                print(
                    f"{Fore.CYAN}[ Ожидание {frmt} ]{Style.RESET_ALL} | "
                    f"{Fore.BLUE}Автофарм активен{Style.RESET_ALL}",
                    end="\r"
                )
                await asyncio.sleep(1)
                remainder -= 1

    async def run_final(self):
        """
        Запускаем основной цикл в асинхронном режиме, 
        обрабатываем любые исключения.
        """
        try:
            await self.main_cycle()
        except Exception as ex:
            self.styled_log(f"{Fore.RED}Ошибка: {ex}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        app = FunctorChecker()
        asyncio.run(app.run_final())
    except KeyboardInterrupt:
        now_s = datetime.now().astimezone(MOSCOW_TZ).strftime("%d-%m-%Y %H:%M:%S %Z")
        print(
            f"{Fore.CYAN}{Style.BRIGHT}[ {now_s} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} |{Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT} [ Завершено ] Авточекер {Style.RESET_ALL}"
        )
