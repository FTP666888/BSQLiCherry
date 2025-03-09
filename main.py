#!/usr/bin/env python3
import os
import sys
import time
import random
import argparse
import concurrent.futures
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup  # Asegúrate de tener beautifulsoup4 instalado

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class BSQLI:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
    ]

    def __init__(self):
        self.vulnerabilities_found = 0
        self.total_tests = 0
        self.verbose = False
        self.vulnerable_urls = []
        self.timeout = 15  # Timeout para requests (valor máximo de espera)
        self.vuln_threshold = None  # Umbral de respuesta para detectar vulnerabilidad

    def get_random_user_agent(self):
        """Retorna un user-agent aleatorio."""
        return random.choice(self.USER_AGENTS)

    def perform_request(self, url, payload, cookie, method='GET', post_field='input'):
        """
        Realiza una petición HTTP (GET o POST) con el payload inyectado.
        Si la URL contiene el marcador [INJECT], se reemplaza; de lo contrario, se concatena en GET.
        Retorna: success (bool), injected_url (str), response_time (float),
                 status_code (int) y error_message (str)
        """
        # Inyección: usar [INJECT] si se detecta en la URL
        if "[INJECT]" in url:
            injected_url = url.replace("[INJECT]", payload)
        else:
            if method.upper() == 'GET':
                injected_url = url + payload
            else:
                injected_url = url

        start_time = time.time()
        headers = {'User-Agent': self.get_random_user_agent()}
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    injected_url,
                    headers=headers,
                    cookies={'cookie': cookie} if cookie else None,
                    timeout=self.timeout
                )
            elif method.upper() == 'POST':
                data = {post_field: payload}
                response = requests.post(
                    injected_url,
                    headers=headers,
                    cookies={'cookie': cookie} if cookie else None,
                    data=data,
                    timeout=self.timeout
                )
            else:
                raise ValueError("Método HTTP no soportado.")
            response.raise_for_status()
            response_time = time.time() - start_time
            return True, injected_url, response_time, response.status_code, None
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return False, injected_url, response_time, None, str(e)

    def read_file(self, path):
        """Lee un archivo y retorna una lista de líneas no vacías."""
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{Color.RED}Error al leer el archivo {path}: {e}{Color.RESET}")
            return []

    def read_payloads_from_directory(self, dir_path):
        """Lee todos los archivos de texto en un directorio y retorna una lista combinada de payloads."""
        all_payloads = []
        try:
            for file_name in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_name)
                if os.path.isfile(file_path):
                    payloads = self.read_file(file_path)
                    all_payloads.extend(payloads)
            return all_payloads
        except Exception as e:
            print(f"{Color.RED}Error al leer payloads del directorio {dir_path}: {e}{Color.RESET}")
            return []

    def save_vulnerable_urls(self, filename):
        """Guarda la lista de URLs vulnerables en un archivo."""
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                for url in self.vulnerable_urls:
                    file.write(f"{url}\n")
            print(f"{Color.GREEN}URLs vulnerables guardadas en {filename}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error al guardar las URLs vulnerables: {e}{Color.RESET}")

    def crawl_links(self, seed_url):
        """
        Realiza crawling en la URL semilla y extrae los links encontrados.
        Se normalizan los enlaces relativos usando urljoin.
        """
        links = set()
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(seed_url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    full_link = urljoin(seed_url, a['href'])
                    links.add(full_link)
            return list(links)
        except Exception as e:
            print(f"{Color.RED}Error al hacer crawling en {seed_url}: {e}{Color.RESET}")
            return []

    def generate_targets_from_url(self, url):
        """
        Dada una URL, si tiene parámetros, genera versiones con [INJECT] en cada parámetro.
        Si no tiene parámetros, se le concatena el marcador [INJECT].
        """
        parsed = urlparse(url)
        if parsed.query:
            query_dict = parse_qs(parsed.query)
            targets = []
            for param in query_dict:
                new_query = query_dict.copy()
                # Reemplazamos el valor del parámetro por el marcador [INJECT]
                new_query[param] = "[INJECT]"
                new_query_str = urlencode(new_query, doseq=True)
                new_url = parsed._replace(query=new_query_str).geturl()
                targets.append(new_url)
            return targets
        else:
            return [url + "[INJECT]"]

    def get_baseline(self, url, cookie, method, post_field):
        """
        Mide el tiempo de respuesta base de una URL (sin inyección) para usarlo en el ajuste del umbral.
        """
        headers = {'User-Agent': self.get_random_user_agent()}
        try:
            start = time.time()
            if method.upper() == 'GET':
                r = requests.get(url, headers=headers, cookies={'cookie': cookie} if cookie else None, timeout=self.timeout)
            else:
                r = requests.post(url, headers=headers, cookies={'cookie': cookie} if cookie else None,
                                  data={post_field: 'baseline'}, timeout=self.timeout)
            return time.time() - start
        except Exception:
            return self.timeout

    def run(self, url, threads=0, method="GET", crawl=False, payloads_path="/home/hack4chxrry/BSQLiCherry/payloads",
            cookie="", verbose=False, timeout=None):
        """Modo no interactivo mediante línea de comandos."""
        self.verbose = verbose
        method = method.upper()
        post_field = "input"  # Campo por defecto para POST

        # Cargar payloads desde el directorio (o archivo) especificado
        if os.path.isdir(payloads_path):
            payloads = self.read_payloads_from_directory(payloads_path)
        else:
            payloads = self.read_file(payloads_path)

        if not payloads:
            print(f"{Color.RED}No se encontraron payloads válidos en: {payloads_path}{Color.RESET}")
            return

        # Generar objetivos: si se activa crawling, se recogen links adicionales
        targets = set()
        if crawl:
            crawled = self.crawl_links(url)
            for link in crawled:
                targets.update(self.generate_targets_from_url(link))
            targets.update(self.generate_targets_from_url(url))
        else:
            targets.update(self.generate_targets_from_url(url))
        targets = list(targets)

        if not targets:
            print(f"{Color.RED}No se pudieron generar objetivos a partir de la URL proporcionada.{Color.RESET}")
            return

        # Ajuste automático del umbral de vulnerabilidad basado en la respuesta base,
        # si no se proporcionó un timeout específico para el umbral.
        if timeout is None:
            baseline = self.get_baseline(targets[0].replace("[INJECT]", ""), cookie, method, post_field)
            margin = 3  # margen de segundos a sumar
            self.vuln_threshold = baseline + margin
            print(f"{Color.YELLOW}Tiempo base: {baseline:.2f}s. Umbral de vulnerabilidad ajustado a: {self.vuln_threshold:.2f}s{Color.RESET}")
        else:
            self.vuln_threshold = timeout

        print(f"{Color.CYAN}Iniciando escaneo en {len(targets)} objetivo(s) con {len(payloads)} payloads...{Color.RESET}")
        # Realizar los tests (secuencial o concurrente)
        if threads <= 0:
            for target in targets:
                for payload in payloads:
                    self.total_tests += 1
                    success, injected_url, response_time, status_code, error_message = self.perform_request(
                        target, payload, cookie, method, post_field
                    )
                    if success and status_code and response_time >= self.vuln_threshold:
                        self.vulnerabilities_found += 1
                        self.vulnerable_urls.append(injected_url)
                        if self.verbose:
                            print(f"{Color.GREEN}✓ Vulnerable: {injected_url} - {response_time:.2f}s - Código: {status_code}{Color.RESET}")
                        else:
                            print(f"{Color.GREEN}✓ {injected_url}{Color.RESET}")
                    elif self.verbose:
                        print(f"{Color.RED}✗ No vulnerable: {injected_url} - {response_time:.2f}s - Código: {status_code} - Error: {error_message}{Color.RESET}")
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for target in targets:
                    for payload in payloads:
                        futures.append(executor.submit(self.perform_request, target, payload, cookie, method, post_field))
                for future in concurrent.futures.as_completed(futures):
                    self.total_tests += 1
                    success, injected_url, response_time, status_code, error_message = future.result()
                    if success and status_code and response_time >= self.vuln_threshold:
                        self.vulnerabilities_found += 1
                        self.vulnerable_urls.append(injected_url)
                        if self.verbose:
                            print(f"{Color.GREEN}✓ Vulnerable: {injected_url} - {response_time:.2f}s - Código: {status_code}{Color.RESET}")
                        else:
                            print(f"{Color.GREEN}✓ {injected_url}{Color.RESET}")
                    elif self.verbose:
                        print(f"{Color.RED}✗ No vulnerable: {injected_url} - {response_time:.2f}s - Código: {status_code} - Error: {error_message}{Color.RESET}")

        print(f"\n{Color.BLUE}Escaneo completo.{Color.RESET}")
        print(f"{Color.YELLOW}Total de pruebas: {self.total_tests}{Color.RESET}")
        print(f"{Color.GREEN}Vulnerabilidades encontradas: {self.vulnerabilities_found}{Color.RESET}")
        if self.vulnerabilities_found > 0:
            print(f"{Color.GREEN}✓ Se encontraron {self.vulnerabilities_found} vulnerabilidades.{Color.RESET}")
        else:
            print(f"{Color.RED}✗ No se encontraron vulnerabilidades.{Color.RESET}")

    def interactive(self):
        """Modo interactivo (tal como la versión original)."""
        print(Color.CYAN + r"""
    _____               __ __
    |   __ \.-----.-----.|  |__|
    |   __ <|__ --|  _  ||  |  |
    |______/|_____|__   ||__|__|
                    |__|
    
    Hecho por Coffinxp & hexsh1dow
    YOUTUBE: Lostsec
        """ + Color.RESET)

        verbose_input = input(Color.PURPLE + "¿Habilitar modo verbose? (s/n): " + Color.RESET).strip().lower()
        self.verbose = verbose_input in ['s', 'si', 'y', 'yes']

        method = input(Color.CYAN + "Ingrese el método HTTP a usar (GET/POST, por defecto GET): " + Color.RESET).strip().upper() or "GET"
        if method not in ['GET', 'POST']:
            method = "GET"

        post_field = "input"
        if method == "POST":
            post_field_input = input(Color.CYAN + "Ingrese el nombre del campo para la inyección (por defecto 'input'): " + Color.RESET).strip()
            if post_field_input:
                post_field = post_field_input

        timeout_input = input(Color.CYAN + "Ingrese el tiempo de espera en segundos para las peticiones (por defecto 15): " + Color.RESET).strip()
        if timeout_input:
            try:
                self.timeout = float(timeout_input)
            except ValueError:
                print(f"{Color.YELLOW}Tiempo inválido, usando 15 segundos por defecto.{Color.RESET}")
                self.timeout = 15

        input_url = input(Color.PURPLE + "Ingrese la URL: " + Color.RESET).strip()
        if not input_url:
            print(f"{Color.RED}No se proporcionó URL.{Color.RESET}")
            return

        crawl_input = input(Color.CYAN + "¿Desea activar crawling? (s/n, por defecto n): " + Color.RESET).strip().lower()
        crawl = crawl_input in ['s', 'si', 'y', 'yes']

        payload_path = input(Color.CYAN + "Ingrese la ruta al directorio/archivo de payloads (por defecto /home/hack4chxrry/BSQLiCherry/payloads): " + Color.RESET).strip() or "/home/hack4chxrry/BSQLiCherry/payloads"
        cookie = input(Color.CYAN + "Ingrese la cookie para la petición (deje en blanco si no hay): " + Color.RESET).strip()
        threads_input = input(Color.CYAN + "Ingrese el número de hilos concurrentes (0-10, por defecto 0): " + Color.RESET).strip()
        try:
            threads = int(threads_input) if threads_input else 0
        except ValueError:
            print(f"{Color.RED}Número de hilos inválido, usando 0.{Color.RESET}")
            threads = 0

        self.run(url=input_url, threads=threads, method=method, crawl=crawl, payloads_path=payload_path, cookie=cookie, verbose=self.verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramienta BSQLi con crawling y param spider.")
    parser.add_argument("-u", "--url", help="URL objetivo", required=False)
    parser.add_argument("--threads", type=int, help="Número de hilos concurrentes", default=0)
    parser.add_argument("--method", help="Método HTTP a usar (GET/POST)", default="GET")
    parser.add_argument("--crawl", action="store_true", help="Activar crawling para obtener más URLs")
    parser.add_argument("--payloads", help="Ruta al directorio o archivo de payloads",
                        default="/home/hack4chxrry/BSQLiCherry/payloads")
    parser.add_argument("--cookie", help="Cookie para las peticiones", default="")
    parser.add_argument("--verbose", action="store_true", help="Activar modo verbose")
    parser.add_argument("--timeout", type=float, help="Timeout (umbral) para detectar vulnerabilidad (opcional)", default=None)
    args = parser.parse_args()

    scanner = BSQLI()
    if args.url:
        # Modo línea de comandos (no interactivo)
        scanner.run(url=args.url,
                    threads=args.threads,
                    method=args.method,
                    crawl=args.crawl,
                    payloads_path=args.payloads,
                    cookie=args.cookie,
                    verbose=args.verbose,
                    timeout=args.timeout)
    else:
        # Modo interactivo si no se pasa URL por argumento
        scanner.interactive()
