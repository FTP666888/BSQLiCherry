import os
import requests
import time
import concurrent.futures
import random

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
        self.timeout = 15  # Tiempo de espera por defecto en segundos

    def get_random_user_agent(self):
        """
        Retorna un user-agent aleatorio de la lista.
        """
        return random.choice(self.USER_AGENTS)

    def perform_request(self, url, payload, cookie, method='GET', post_field='input'):
        """
        Realiza una petición HTTP (GET o POST) con el payload inyectado.
        Si la URL contiene el marcador [INJECT], se reemplaza por el payload;
        de lo contrario, en GET se concatena y en POST se envía en el cuerpo.
        
        Retorna una tupla:
            - success (bool): True si la petición fue exitosa.
            - injected_url (str): La URL (o endpoint) con el payload inyectado.
            - response_time (float): Tiempo de respuesta.
            - status_code (int): Código HTTP obtenido.
            - error_message (str): Mensaje de error en caso de fallo.
        """
        # Determinar el punto de inyección
        if "[INJECT]" in url:
            injected_url = url.replace("[INJECT]", payload)
        else:
            if method.upper() == 'GET':
                injected_url = url + payload
            else:
                injected_url = url  # En POST, el payload irá en el cuerpo
        
        start_time = time.time()
        headers = {'User-Agent': self.get_random_user_agent()}
        try:
            if method.upper() == 'GET':
                response = requests.get(injected_url, headers=headers, cookies={'cookie': cookie} if cookie else None, timeout=self.timeout)
            elif method.upper() == 'POST':
                # En POST, si no se usa marcador, se envía el payload en el campo especificado.
                data = {post_field: payload}
                response = requests.post(injected_url, headers=headers, cookies={'cookie': cookie} if cookie else None, data=data, timeout=self.timeout)
            else:
                raise ValueError("Método HTTP no soportado.")
            
            response.raise_for_status()
            response_time = time.time() - start_time
            return True, injected_url, response_time, response.status_code, None
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return False, injected_url, response_time, None, str(e)

    def read_file(self, path):
        """
        Lee un archivo y retorna una lista de líneas no vacías.
        """
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{Color.RED}Error al leer el archivo {path}: {e}{Color.RESET}")
            return []

    def save_vulnerable_urls(self, filename):
        """
        Guarda la lista de URLs vulnerables en un archivo.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                for url in self.vulnerable_urls:
                    file.write(f"{url}\n")
            print(f"{Color.GREEN}URLs vulnerables guardadas en {filename}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error al guardar las URLs vulnerables: {e}{Color.RESET}")

    def main(self):
        print(Color.CYAN + r"""
    _____               __ __
    |   __ \.-----.-----.|  |__|
    |   __ <|__ --|  _  ||  |  |
    |______/|_____|__   ||__|__|
                    |__|
    
    Hecho por Coffinxp & hexsh1dow
    YOUTUBE: Lostsec
        """ + Color.RESET)

        # Configurar modo verbose
        verbose_input = input(Color.PURPLE + "¿Habilitar modo verbose? (s/n): " + Color.RESET).strip().lower()
        if verbose_input in ['s', 'si', 'y', 'yes']:
            self.verbose = True

        # Selección del método HTTP (GET o POST)
        method = input(Color.CYAN + "Ingrese el método HTTP a usar (GET/POST, por defecto GET): " + Color.RESET).strip().upper()
        if method not in ['GET', 'POST']:
            method = 'GET'

        post_field = 'input'
        if method == 'POST':
            post_field_input = input(Color.CYAN + "Ingrese el nombre del campo para la inyección (por defecto 'input'): " + Color.RESET).strip()
            if post_field_input:
                post_field = post_field_input

        # Configurar timeout
        timeout_input = input(Color.CYAN + "Ingrese el tiempo de espera en segundos para las peticiones (por defecto 15): " + Color.RESET).strip()
        if timeout_input:
            try:
                self.timeout = float(timeout_input)
            except ValueError:
                print(f"{Color.YELLOW}Tiempo de espera inválido, usando valor por defecto de 15 segundos.{Color.RESET}")
                self.timeout = 15

        # Obtener URL o archivo de URLs
        input_url_or_file = input(Color.PURPLE + "Ingrese la URL o la ruta al archivo con la lista de URLs: " + Color.RESET).strip()
        if not input_url_or_file:
            print(f"{Color.RED}No se proporcionó ninguna URL o archivo.{Color.RESET}")
            return

        urls = [input_url_or_file] if not os.path.isfile(input_url_or_file) else self.read_file(input_url_or_file)
        if not urls:
            print(f"{Color.RED}No se proporcionaron URLs válidas.{Color.RESET}")
            return

        # Obtener archivo de payloads
        payload_path = input(Color.CYAN + "Ingrese la ruta completa al archivo de payloads (e.g., payloads/xor.txt): " + Color.RESET).strip()
        payloads = self.read_file(payload_path)
        if not payloads:
            print(f"{Color.RED}No se encontraron payloads válidos en el archivo: {payload_path}{Color.RESET}")
            return

        # Obtener cookie si se desea
        cookie = input(Color.CYAN + "Ingrese la cookie para incluir en la petición (deje en blanco si no hay): " + Color.RESET).strip()

        # Configurar número de hilos concurrentes
        threads_input = input(Color.CYAN + "Ingrese el número de hilos concurrentes (0-10, deje vacío para 0): " + Color.RESET).strip()
        try:
            threads = int(threads_input) if threads_input else 0
            if threads < 0 or threads > 10:
                raise ValueError("El número de hilos debe estar entre 0 y 10.")
        except ValueError as e:
            print(f"{Color.RED}Número de hilos inválido: {e}{Color.RESET}")
            return

        print(f"\n{Color.PURPLE}Iniciando escaneo...{Color.RESET}")

        try:
            if threads == 0:
                # Ejecución secuencial
                for url in urls:
                    for payload in payloads:
                        self.total_tests += 1
                        success, injected_url, response_time, status_code, error_message = self.perform_request(
                            url, payload, cookie, method, post_field)
                        # Se considera vulnerable si la respuesta supera el timeout (esto se puede ajustar según el criterio)
                        if success and status_code and response_time >= self.timeout:
                            self.vulnerabilities_found += 1
                            self.vulnerable_urls.append(injected_url)
                            if self.verbose:
                                print(f"{Color.GREEN}✓ SQLi Encontrado! URL: {injected_url} - Tiempo de respuesta: {response_time:.2f} s - Código: {status_code}{Color.RESET}")
                            else:
                                print(f"{Color.GREEN}✓ URL Vulnerable: {injected_url}{Color.RESET}")
                        else:
                            if self.verbose:
                                print(f"{Color.RED}✗ No vulnerable: {injected_url} - Tiempo de respuesta: {response_time:.2f} s - Código: {status_code} - Error: {error_message}{Color.RESET}")
            else:
                # Ejecución concurrente
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = []
                    for url in urls:
                        for payload in payloads:
                            futures.append(executor.submit(self.perform_request, url, payload, cookie, method, post_field))
                    for future in concurrent.futures.as_completed(futures):
                        self.total_tests += 1
                        success, injected_url, response_time, status_code, error_message = future.result()
                        if success and status_code and response_time >= self.timeout:
                            self.vulnerabilities_found += 1
                            self.vulnerable_urls.append(injected_url)
                            if self.verbose:
                                print(f"{Color.GREEN}✓ SQLi Encontrado! URL: {injected_url} - Tiempo de respuesta: {response_time:.2f} s - Código: {status_code}{Color.RESET}")
                            else:
                                print(f"{Color.GREEN}✓ URL Vulnerable: {injected_url}{Color.RESET}")
                        else:
                            if self.verbose:
                                print(f"{Color.RED}✗ No vulnerable: {injected_url} - Tiempo de respuesta: {response_time:.2f} s - Código: {status_code} - Error: {error_message}{Color.RESET}")
        except KeyboardInterrupt:
            print(f"{Color.YELLOW}Escaneo interrumpido por el usuario.{Color.RESET}")

        print(f"\n{Color.BLUE}Escaneo completo.{Color.RESET}")
        print(f"{Color.YELLOW}Total de pruebas: {self.total_tests}{Color.RESET}")
        print(f"{Color.GREEN}SQLi encontrados: {self.vulnerabilities_found}{Color.RESET}")
        if self.vulnerabilities_found > 0:
            print(f"{Color.GREEN}✓ Se encontraron {self.vulnerabilities_found} vulnerabilidades!{Color.RESET}")
        else:
            print(f"{Color.RED}✗ No se encontraron vulnerabilidades. ¡Mejor suerte la próxima vez!{Color.RESET}")

        # Guardar URLs vulnerables en un archivo (opcional)
        save_file = input(Color.PURPLE + "Ingrese el nombre del archivo para guardar las URLs vulnerables (deje vacío para omitir): " + Color.RESET).strip()
        if save_file:
            self.save_vulnerable_urls(save_file)

        print(f"{Color.CYAN}¡Gracias por usar la herramienta BSQLi!{Color.RESET}")

if __name__ == "__main__":
    scanner = BSQLI()
    scanner.main()
