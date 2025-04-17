import grpc
from concurrent import futures
import time
import random
import threading
import logging
import argparse
import socket
import struct
import json
import os
from collections import OrderedDict
import uuid
import sensor_pb2
import sensor_pb2_grpc
from multicast_config import MCAST_GRP, MCAST_PORT, MCAST_TTL, LOCAL_IP

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# config logging
LOG_FORMAT = '%(asctime)s [%(threadName)s] [%(sensorId)s] %(levelname)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("SensorServerLogger")
logger.setLevel(logging.INFO)  # nivel inicial eh INFO


# adaptador para adicionar sensorId aos logs
class SensorLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        if 'extra' not in kwargs: kwargs['extra'] = {}
        kwargs['extra']['sensorId'] = self.extra.get('sensorId', 'N/A')
        return msg, kwargs

# variavel global para o adapter (sera inicializada no main)
sensor_id_adapter = None

PEER_TIMEOUT = 45; ELECTION_TIMEOUT = 5; COORDINATOR_TIMEOUT = PEER_TIMEOUT * 1.5
HEARTBEAT_INTERVAL = 10; ANNOUNCE_INTERVAL = 10; MUTEX_LOCK_TIMEOUT = 30
CHECKPOINT_INTERVAL = 60; CHECKPOINT_DIR = "checkpoints"
PRIVATE_KEY_FILE = "server_private.pem"; PUBLIC_KEY_FILE = "server_public.pem"

# Variaveis Globais de Estado
discovered_peers = OrderedDict(); discovery_lock = threading.Lock()
current_coordinator_id = None; coordinator_lock = threading.Lock()
election_in_progress = False; election_lock = threading.Lock(); election_timer = None
failed_nodes = set(); failed_nodes_lock = threading.Lock()
replicated_data_store = {}; replication_store_lock = threading.Lock()  # So no Coord
resource_lock_state = { "resource_id": "global_alert_lock", "locked": False, "holder": None, "timestamp": 0}; mutex_lock_state_lock = threading.Lock()  # So no Coord
checkpoint_thread = None; stop_checkpoint_event = threading.Event()

# Estado de Seguranca
server_private_key = None  # carregado no inicio
server_public_key_pem = None  # PEM da chave publica para enviar aos clientes
active_sessions = {}; session_lock = threading.Lock()  # {token: {'aes_key': bytes, 'client_id': str}}


def get_peers():
    # retorna copia segura dos peers ativos
    with discovery_lock:
        now = time.time(); active_peers = OrderedDict()
        # itera sobre copia das chaves para seguranca em concorrencia
        for peer_id in list(discovered_peers.keys()):
            info = discovered_peers.get(peer_id)  # Pega info atual
            # verifica se info nao e None antes de usa-lo na condicao composta
            if info and (now - info.get("last_seen", 0) < PEER_TIMEOUT):
                active_peers[peer_id] = info.copy()
        return active_peers


def update_peer(sensor_id, host, port):
    # adiciona ou atualiza peer na lista, ignorando a si mesmo usando o adapter global
    my_id = sensor_id_adapter.extra.get('sensorId') if sensor_id_adapter else None;
    if sensor_id == my_id: return
    with discovery_lock:
        now = time.time(); is_new = sensor_id not in discovered_peers
        if is_new: logger.info(f"Novo peer: {sensor_id} @ {host}:{port}")
        discovered_peers[sensor_id] = {"host": host, "port": port, "last_seen": now}
        discovered_peers.move_to_end(sensor_id)  # mantem na ordem por ultimo visto


def mark_node_failed(sensor_id):
     # marca um no como falho e o coordenador anuncia via multicast
     my_id = sensor_id_adapter.extra.get('sensorId') if sensor_id_adapter else None;
     if sensor_id == my_id: return
     with failed_nodes_lock:
         if sensor_id not in failed_nodes:
             sensor_id_adapter.warning(f"Marcando no {sensor_id} como FALHO.")
             failed_nodes.add(sensor_id)
             # somente o coordenador anuncia a falha
             is_coord = False
             with coordinator_lock:
                 is_coord = (current_coordinator_id == my_id)
             if is_coord:
                 alert_msg = {
                     "type": "alert",
                     "alert_type": "NODE_FAILED",
                     "sensor_id": my_id,  # quem detectou
                     "failed_node_id": sensor_id,
                     "timestamp": time.time()
                 }
                 send_multicast_message(alert_msg, sensor_id_adapter)


def is_node_failed(sensor_id):
    # verifica se um no esta marcado como falho
    with failed_nodes_lock:
        return sensor_id in failed_nodes

def clear_failed_node(sensor_id):
    # remove no da lista de falhos
    with failed_nodes_lock:
        if sensor_id in failed_nodes:
             sensor_id_adapter.info(f"No {sensor_id} parece ter voltado. Removendo da lista de falhos.")
             failed_nodes.discard(sensor_id)

def make_grpc_call(target_id, target_host, target_port, method_name, request, timeout=3):
    # funcao para fazer chamadas gRPC para outros sensores
    global sensor_id_adapter  # usa o adapter global
    target = f"{target_host}:{target_port}"
    my_id = sensor_id_adapter.extra.get('sensorId')
    if target_id == my_id:
        sensor_id_adapter.error(f"Bloqueada chamada gRPC para si mesmo ({target_id})")
        return None

    sensor_id_adapter.debug(f"Tentando chamar {method_name} em {target_id}@{target}")
    try:
        # cria canal e stub dentro do try
        with grpc.insecure_channel(target) as channel:
            stub = sensor_pb2_grpc.SensorServiceStub(channel)
            method_to_call = getattr(stub, method_name)
            # executa a chamada RPC
            response = method_to_call(request, timeout=timeout)
        # se a chamada foi bem sucedida
        sensor_id_adapter.debug(f"Chamada {method_name} para {target_id} bem-sucedida.")
        clear_failed_node(target_id)  # limpa status de falha se sucesso
        return response
    # captura erros especificos do gRPC
    except grpc.RpcError as e:
        sensor_id_adapter.error(f"Erro gRPC [{method_name}] para {target_id}@{target}: {e.code()}")
        # marca como falho apenas em erros de conexao/disponibilidade/timeout
        if e.code() in [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED]:
             mark_node_failed(target_id)
        return None
    # captura qualquer outro erro inesperado
    except Exception as e:
        sensor_id_adapter.error(f"Erro inesperado [{method_name}] -> {target_id}@{target}: {e}", exc_info=True)
        mark_node_failed(target_id)  # marca como falho tambem
        return None  # retorna None indicando falha


# Logica de Eleicao Bully
def start_election():
    global election_in_progress, election_timer, sensor_id_adapter, current_coordinator_id;
    if not sensor_id_adapter: logger.error("Adapter log nao inicializado!"); return
    my_id = sensor_id_adapter.extra.get('sensorId')
    with election_lock:
        if election_in_progress: sensor_id_adapter.info("Eleicao ja em progresso."); return
        sensor_id_adapter.info("***** Iniciando Eleicao Bully *****"); election_in_progress = True
        if election_timer and election_timer.is_alive(): election_timer.cancel()
        election_timer = None;
        with coordinator_lock: current_coordinator_id = None
    higher_peers = []; active_peers = get_peers()
    for peer_id, info in active_peers.items():
        if peer_id > my_id and not is_node_failed(peer_id): higher_peers.append((peer_id, info['host'], info['port']))
    if not higher_peers: sensor_id_adapter.info("Nenhum peer maior. Declaro-me Coordenador!"); announce_self_as_coordinator()
    else:
        sensor_id_adapter.info(f"Enviando ELECTION p/ peers maiores: {[p[0] for p in higher_peers]}"); election_message = sensor_pb2.BullyMessage(type=sensor_pb2.BullyMessage.ELECTION, sender_id=my_id)
        ok_received_from = None
        for peer_id, host, port in higher_peers: response = make_grpc_call(peer_id, host, port, "ProcessBullyMessage", election_message)
        if response and response.type == sensor_pb2.BullyMessage.OK: sensor_id_adapter.info(f"Recebido OK de {response.sender_id}."); ok_received_from = response.sender_id
        with election_lock:
             if not election_in_progress: sensor_id_adapter.info("Eleicao cancelada durante envio."); return
             if ok_received_from: sensor_id_adapter.info(f"OK recebido. Timer ({ELECTION_TIMEOUT * 2}s) p/ COORDINATOR."); election_timer = threading.Timer(ELECTION_TIMEOUT * 2, handle_election_timeout, args=[True]); election_timer.start()
             else: sensor_id_adapter.info(f"Nenhum OK. Timer ({ELECTION_TIMEOUT}s) p/ me declarar."); election_timer = threading.Timer(ELECTION_TIMEOUT, handle_election_timeout, args=[False]); election_timer.start()


def handle_election_timeout(ok_was_received):
    # Callback do timer da eleicao chamado se nao recebermos OK ou COORDINATOR a tempo
    global election_in_progress, sensor_id_adapter, election_timer

    # obtem o ID deste no de forma segura
    my_id = None
    if sensor_id_adapter:
        my_id = sensor_id_adapter.extra.get('sensorId')
    # se nao tem adapter nao continuar
    if not my_id:
        logger.critical("handle_election_timeout: sensor_id_adapter nao disponivel!")
        return

    # verifica o estado da eleicao de forma segura
    with election_lock:
        # se a eleicao ja terminou ou foi cancelada enquanto o timer rodava, nao faz nada
        if not election_in_progress:
            sensor_id_adapter.info("Timeout da eleicao, mas ela nao esta mais ativa.")
            # garante que a referencia ao timer antigo seja limpa
            if election_timer and not election_timer.is_alive():
                 election_timer = None
            return

        # Se chegou aqui, a eleicao estava ativa e o timer expirou.
        # Marca a eleicao como finalizada antes de decidir o proximo passo.

    if ok_was_received:
        # se recebe OK, mas o timer expirou, significa que o no maior que enviou OK falhou em se tornar coordenador a tempo.
        sensor_id_adapter.warning("Timeout apos receber OK! Nenhum COORDINATOR anunciado. Reiniciando eleicao.")
        # finaliza o estado de eleicao atual antes de iniciar uma nova
        with election_lock:
             election_in_progress = False
             if election_timer and election_timer.is_alive(): election_timer.cancel()  # garante cancelamento
             election_timer = None
        # pequeno delay para diminuir chance de colisao com outros nos
        time.sleep(random.uniform(0.1, 0.5))
        # inicia uma nova eleicao
        start_election()
    else:
        # se nao recebe nenhum OK, este no e o maior ativo e deve ser o coordenador.
        sensor_id_adapter.info("Timeout sem receber OK! Declaro-me Coordenador!")
        # esta funcao define election_in_progress = False e cancela timers
        announce_self_as_coordinator()


def announce_self_as_coordinator():
    global current_coordinator_id, sensor_id_adapter, election_in_progress, election_timer, replicated_data_store, resource_lock_state; my_id = sensor_id_adapter.extra.get('sensorId')
    with coordinator_lock:
        if current_coordinator_id == my_id: sensor_id_adapter.info("Ja sou coord. Reanunciando.")
        else: sensor_id_adapter.info(f"***** ANUNCIANDO {my_id} COMO COORDENADOR *****")
        current_coordinator_id = my_id;
        with failed_nodes_lock: failed_nodes.clear()
        with replication_store_lock: replicated_data_store.clear()
        with mutex_lock_state_lock: resource_lock_state.update({"locked": False, "holder": None, "timestamp": 0}); sensor_id_adapter.info("Estado replicacao/lock resetado.")
    with election_lock:
        if election_timer and election_timer.is_alive(): election_timer.cancel()
        election_timer = None; election_in_progress = False
    active_peers = get_peers(); coord_message = sensor_pb2.BullyMessage(type=sensor_pb2.BullyMessage.COORDINATOR, sender_id=my_id)
    for peer_id, info in active_peers.items():
        if peer_id != my_id: make_grpc_call(peer_id, info['host'], info['port'], "ProcessBullyMessage", coord_message)
    start_coordinator_heartbeat_thread()


# Logica de Heartbeat (Coordenador)
coordinator_heartbeat_thread = None; stop_heartbeat_event = threading.Event()


def coordinator_heartbeat_task():
    global sensor_id_adapter, current_coordinator_id; my_id = sensor_id_adapter.extra.get('sensorId'); sensor_id_adapter.info(">> Thread HB Coordenador iniciada.")
    while not stop_heartbeat_event.is_set():
        coord_id = None;
        with coordinator_lock: coord_id = current_coordinator_id
        if coord_id != my_id: sensor_id_adapter.info("<< Nao sou Coordenador. Parando HB."); break
        active_peers = get_peers()
        if not active_peers: sensor_id_adapter.debug("HB: Nenhum outro peer ativo.")
        else:
            ping_request = sensor_pb2.PingRequest(sender_id=my_id)
            for peer_id, info in active_peers.copy().items():  # itera sobre copia
                if peer_id != my_id and not is_node_failed(peer_id): make_grpc_call(peer_id, info['host'], info['port'], "Ping", ping_request, timeout=HEARTBEAT_INTERVAL * 0.4)
        stop_heartbeat_event.wait(HEARTBEAT_INTERVAL)
    sensor_id_adapter.info(">> Thread HB Coordenador finalizada.")


def start_coordinator_heartbeat_thread():
    global coordinator_heartbeat_thread, stop_heartbeat_event, sensor_id_adapter; my_id = sensor_id_adapter.extra.get('sensorId');
    with coordinator_lock:
        if current_coordinator_id != my_id: return
    if coordinator_heartbeat_thread and coordinator_heartbeat_thread.is_alive(): return
    sensor_id_adapter.info("Iniciando thread HB Coordenador..."); stop_heartbeat_event.clear(); coordinator_heartbeat_thread = threading.Thread(target=coordinator_heartbeat_task, daemon=True, name="CoordinatorHeartbeat"); coordinator_heartbeat_thread.start()


def stop_coordinator_heartbeat_thread():
    global coordinator_heartbeat_thread, stop_heartbeat_event;
    if coordinator_heartbeat_thread and coordinator_heartbeat_thread.is_alive(): sensor_id_adapter.info("Parando thread HB Coordenador..."); stop_heartbeat_event.set(); coordinator_heartbeat_thread.join(timeout=1); coordinator_heartbeat_thread = None; sensor_id_adapter.info("Thread HB parada.")


# Funcoes de Checkpoint
def save_checkpoint(service_instance):
    # salva o estado relevante do servico em um arquivo JSON
    global current_coordinator_id, replicated_data_store, resource_lock_state
    # obtem o logger e ID da instancia do servico passada como argumento
    adapter = service_instance.adapter
    sensor_id = service_instance.sensor_id

    adapter.info("Iniciando salvamento de checkpoint...")
    # Dicionario para guardar o estado a ser salvo
    state_to_save = {}
    was_coordinator_when_saving = False  # Flag para log

    # Coleta estado local do sensor usando o lock interno da instancia para acesso seguro
    with service_instance.lock:
        state_to_save['lamport_clock'] = service_instance.lamport_clock
        state_to_save['last_data'] = service_instance.last_data
        state_to_save['state_recorded_snapshot_id'] = service_instance.state_recorded_snapshot_id

    # Coleta estado de coordenador
    current_coord_id_local = None
    with coordinator_lock:
        current_coord_id_local = current_coordinator_id

    # verifica se este no (sensor_id) e o coordenador
    if current_coord_id_local == sensor_id:
        was_coordinator_when_saving = True
        state_to_save['was_coordinator'] = True
        with replication_store_lock:
            state_to_save['replicated_data_store'] = replicated_data_store.copy()
        with mutex_lock_state_lock:
            state_to_save['resource_lock_state'] = resource_lock_state.copy()
    else:
        state_to_save['was_coordinator'] = False

    # define os nomes dos arquivos e diretorio
    if CHECKPOINT_DIR and not os.path.exists(CHECKPOINT_DIR):
        try:
            os.makedirs(CHECKPOINT_DIR)
            adapter.info(f"Diretorio de checkpoint criado: {CHECKPOINT_DIR}")
        except OSError as e:
            adapter.error(f"Erro ao criar diretorio de checkpoint {CHECKPOINT_DIR}: {e}")
            return # Aborta

    filename = f"checkpoint_{sensor_id}.json"
    filepath = os.path.join(CHECKPOINT_DIR, filename) if CHECKPOINT_DIR else filename
    tmp_filepath = filepath + ".tmp"

    # salva em arquivo temporario e renomeia
    try:
        # escreve no arquivo temporario e fecha o arquivo
        with open(tmp_filepath, 'w') as f:
            json.dump(state_to_save, f, indent=4)
        # tenta renomear atomicamente
        os.replace(tmp_filepath, filepath)
        adapter.info(f"Checkpoint salvo: {filepath} (Coord: {was_coordinator_when_saving})")
    except Exception as e:
        adapter.error(f"Erro ao salvar checkpoint em {filepath}: {e}", exc_info=True)
        # tenta remover o temporario
        if os.path.exists(tmp_filepath):
            try:
                os.remove(tmp_filepath)
            except OSError:
                pass  # Ignora erro na remocao do temp


def checkpoint_task(service_instance, interval):
    adapter = service_instance.adapter; adapter.info(f">> Thread Checkpoint iniciada (intervalo: {interval}s).")
    while not stop_checkpoint_event.wait(interval):
        if stop_checkpoint_event.is_set(): break
        try: save_checkpoint(service_instance)
        except Exception as e: adapter.error(f"Erro tarefa checkpoint: {e}", exc_info=True)
    adapter.info(">> Thread Checkpoint finalizada.")


def start_checkpoint_thread(service_instance, interval=CHECKPOINT_INTERVAL):
    global checkpoint_thread, stop_checkpoint_event;
    if checkpoint_thread and checkpoint_thread.is_alive(): return
    adapter = service_instance.adapter; adapter.info(f"Iniciando thread Checkpoint...")
    stop_checkpoint_event.clear(); checkpoint_thread = threading.Thread( target=checkpoint_task, args=(service_instance, interval), daemon=True, name="CheckpointThread" ); checkpoint_thread.start()


def stop_checkpoint_thread():
    global checkpoint_thread, stop_checkpoint_event;
    if checkpoint_thread and checkpoint_thread.is_alive(): adapter = sensor_id_adapter; adapter.info("Parando thread Checkpoint..."); stop_checkpoint_event.set(); checkpoint_thread.join(timeout=2); checkpoint_thread = None; adapter.info("Thread Checkpoint parada.")


# Funcoes de Criptografia
def load_private_key(filename=PRIVATE_KEY_FILE, password=None):
    try:
        with open(filename, "rb") as key_file: private_key = serialization.load_pem_private_key(key_file.read(), password=password, backend=default_backend())
        logger.info(f"Chave privada RSA carregada de {filename}"); return private_key
    except Exception as e: logger.error(f"Falha ao carregar chave privada {filename}: {e}"); return None


def load_public_key_pem(filename=PUBLIC_KEY_FILE):
    try:
        with open(filename, "rb") as key_file: pem_data = key_file.read()
        logger.info(f"Chave publica PEM carregada de {filename}"); return pem_data
    except Exception as e: logger.error(f"Falha ao carregar chave publica PEM {filename}: {e}"); return None


def decrypt_with_rsa(private_key, encrypted_data):
    try: return private_key.decrypt( encrypted_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None) )
    except Exception as e: logger.error(f"Falha decriptografia RSA: {e}"); return None


def encrypt_with_aes_gcm(key, iv, plaintext, associated_data=None):
    # criptografia de dados usando AES-GCM
    try:
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        if associated_data: encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize(); return ciphertext, encryptor.tag
    except Exception as e: logger.error(f"Falha na criptografia AES-GCM: {e}", exc_info=True); return None, None


# Funcoes Multicast
def send_multicast_message(message_dict, adapter, ttl=MCAST_TTL):
    # envia mensagem para o grupo multicast
    try:
        my_id = adapter.extra.get('sensorId')
        is_coord = False
        with coordinator_lock:
            is_coord = (current_coordinator_id == my_id)

        if is_coord and message_dict.get("type") == "announce":
            message_dict["is_coordinator"] = True

        message_json = json.dumps(message_dict)
        message_bytes = message_json.encode('utf-8')

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.sendto(message_bytes, (MCAST_GRP, MCAST_PORT))
            adapter.debug(f"Multicast enviado: {message_json}")

    except Exception as e:
        adapter.error(f"Erro ao enviar mensagem multicast: {e}", exc_info=True)


def send_multicast_message(message_dict, adapter, ttl=MCAST_TTL):
    # envia mensagem para o grupo multicast
    try:
        my_id = adapter.extra.get('sensorId')
        is_coord = False
        with coordinator_lock:
            is_coord = (current_coordinator_id == my_id)

        if is_coord and message_dict.get("type") == "announce":
            message_dict["is_coordinator"] = True

        message_json = json.dumps(message_dict)
        message_bytes = message_json.encode('utf-8')

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.sendto(message_bytes, (MCAST_GRP, MCAST_PORT))
            adapter.debug(f"Multicast enviado: {message_json}")

    except Exception as e:
        adapter.error(f"Erro ao enviar mensagem multicast: {e}", exc_info=True)


def multicast_listener_thread(adapter):
    # Thread que faz o listener multicast (anuncios, alertas)
    global current_coordinator_id, election_in_progress, election_timer
    my_id = adapter.extra.get('sensorId'); adapter.info("Listener Multicast iniciado.")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(('', MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY); sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq); adapter.info(f"Escutando multicast {MCAST_GRP}:{MCAST_PORT}")

        while True:
            try:
                sock.settimeout(2.0)  # Timeout util para evitar bloqueio total
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue  # Volta ao inicio do while True
            except Exception as e:
                adapter.error(f"Erro no recvfrom do socket multicast: {e}", exc_info=True)
                time.sleep(1); continue  # Espera e continua

            try:  # Try para processar mensagem
                message_json = data.decode('utf-8'); message = json.loads(message_json)
                msg_type = message.get("type"); sender_id = message.get("sensor_id")
                adapter.debug(f"Multicast recebido de {addr}: {message_json}")
                if not sender_id or sender_id == my_id: continue

                # Processa Anuncio
                if msg_type == "announce":
                    host = message.get("grpc_host"); port = message.get("grpc_port"); is_sender_coord = message.get("is_coordinator", False)
                    if host and port is not None:
                        update_peer(sender_id, host, port); clear_failed_node(sender_id)
                        old_coord = None;
                        with coordinator_lock: old_coord = current_coordinator_id
                        if is_sender_coord and sender_id != old_coord:
                             adapter.info(f"Novo Coordenador via anuncio: {sender_id}")
                             with election_lock:
                                 if election_in_progress: adapter.info("Cancelando eleicao local (coord via multicast).");
                                 if election_timer and election_timer.is_alive(): election_timer.cancel(); election_timer=None
                                 election_in_progress = False  # Atribuicao segura
                             # Atribuicao segura
                             current_coordinator_id = sender_id
                             if my_id != sender_id: stop_coordinator_heartbeat_thread()
                             if my_id == sender_id: start_coordinator_heartbeat_thread()
                        elif not is_sender_coord and sender_id == old_coord:
                             adapter.warning(f"Anuncio do Coordenador {sender_id} sem flag.")
                    else: adapter.warning(f"Anuncio invalido de {addr}")
                # Processa Alerta
                elif msg_type == "alert":
                    alert_type = message.get("alert_type", "GENERIC")
                    if alert_type == "NODE_FAILED":
                         failed_node_id = message.get("failed_node_id")
                         if failed_node_id:
                              adapter.warning(f"ALERTA: No {failed_node_id} FALHO (anunc por {sender_id}).")
                              mark_node_failed(failed_node_id)
                              coord_id = None
                              with coordinator_lock: coord_id = current_coordinator_id
                              if failed_node_id == coord_id: adapter.warning(f"Coordenador falhou! Iniciando eleicao."); start_election()
                    elif alert_type == "GLOBAL_HIGH_TEMP": adapter.critical(f"*** ALERTA GLOBAL TEMP ALTA [{sender_id}]: {message.get('message','')} ***")
                    else: adapter.warning(f"ALERTA [{alert_type}] de [{sender_id}]: {message.get('message','')} (Valor: {message.get('value','N/A')})")
            except json.JSONDecodeError: adapter.warning(f"Msg multicast JSON invalida de {addr}")
            except Exception as e: adapter.error(f"Erro ao processar msg multicast de {addr}: {e}", exc_info=True)

    except socket.error as se: adapter.error(f"Erro Socket Listener Multicast (porta {MCAST_PORT}?): {se}")
    except Exception as e: adapter.error(f"Erro fatal listener: {e}", exc_info=True)
    finally: adapter.info("Listener Multicast encerrado.");
    if sock: sock.close()  # Garante fechamento


def multicast_announcer_thread(sensor_id, grpc_port, adapter, interval=ANNOUNCE_INTERVAL):
    adapter.info(f"Announcer Multicast iniciado (intervalo: {interval}s).")
    while True:
        time.sleep(interval)  # espera o intervalo
        announcement = { "type": "announce", "sensor_id": sensor_id, "grpc_host": LOCAL_IP, "grpc_port": grpc_port, "timestamp": time.time() };
        send_multicast_message(announcement, adapter)  # adiciona a flag 'is_coordinator' se necessário
        check_coordinator_liveness(adapter)  # chama a verificação de liveness do coordenador


# verificacao liveness (se ta vivo) coordenador
last_coordinator_seen_time = 0


def check_coordinator_liveness(adapter):
    # verifica se o coordenador esta ativo
    global current_coordinator_id, last_coordinator_seen_time, election_in_progress
    my_id = adapter.extra.get('sensorId'); coord_id = None;
    with coordinator_lock: coord_id = current_coordinator_id
    if coord_id is None or coord_id == my_id: return;
    with election_lock:
        if election_in_progress: return
    coord_info = None; last_seen = 0;
    with discovery_lock: coord_info = discovered_peers.get(coord_id)
    if coord_info: last_seen = coord_info.get("last_seen", 0)
    effective_last_seen = max(last_seen, last_coordinator_seen_time)  # considera o ultimo timestamp visto

    needs_election = False
    if effective_last_seen == 0 and coord_id is not None: adapter.warning(f"Coord {coord_id} nunca visto. Iniciando eleicao."); needs_election = True
    elif time.time() - effective_last_seen > COORDINATOR_TIMEOUT:
        last_seen_str = time.strftime('%H:%M:%S', time.localtime(effective_last_seen)) if effective_last_seen > 0 else 'nunca'
        adapter.warning(f"Coord {coord_id} nao visto (> {COORDINATOR_TIMEOUT}s, ultimo: {last_seen_str}). Iniciando eleicao."); needs_election = True
    if needs_election: start_election(); last_coordinator_seen_time = time.time()  # reseta o timer local
    elif coord_info: last_coordinator_seen_time = coord_info.get("last_seen", last_coordinator_seen_time)  # atualiza global se viu no dict


# Classe ServiceImpl (Implementacao dos RPCs)
class SensorServiceImpl(sensor_pb2_grpc.SensorServiceServicer):
    def __init__(self, sensor_id):
        global sensor_id_adapter
        self.sensor_id = sensor_id
        self.adapter = sensor_id_adapter if sensor_id_adapter else SensorLogAdapter(logging.getLogger("FallbackLogger"), {'sensorId': sensor_id})
        self.lamport_clock = 0; self.lock = threading.Lock(); self.last_data = {}
        self.state_recorded_snapshot_id = -1; self.recorded_state_for_snapshot = None
        self.adapter.info(f"Instanciando Servico gRPC...")
        if not self._load_checkpoint(): self.adapter.info("Inicializando estado padrao."); self._generate_initial_data(); self.lamport_clock = 0
        self.adapter.info(f"Servico gRPC inicializado (LC inicial: {self.lamport_clock})")

    def _update_lc(self, received_lc=None):
        with self.lock:
            if received_lc is not None: self.lamport_clock = max(self.lamport_clock, received_lc) + 1
            else: self.lamport_clock += 1; return self.lamport_clock

    def _generate_initial_data(self):
         with self.lock: self.last_data = { "timestamp": time.time(), "temperatura": round(random.uniform(15.0, 35.0), 2), "umidade": round(random.uniform(40.0, 90.0), 2), "pressao": round(random.uniform(980.0, 1050.0), 2) }; self.adapter.debug("Estado inicial padrao gerado.")

    def _load_checkpoint(self):
        global current_coordinator_id, replicated_data_store, resource_lock_state
        filename = f"checkpoint_{self.sensor_id}.json"; filepath = os.path.join(CHECKPOINT_DIR, filename) if CHECKPOINT_DIR else filename
        if not os.path.exists(filepath): self.adapter.info(f"Checkpoint nao encontrado: {filepath}"); return False
        self.adapter.info(f"Tentando carregar checkpoint de {filepath}...")
        try:
            with open(filepath, 'r') as f: loaded_state = json.load(f)
            with self.lock: self.lamport_clock = loaded_state.get('lamport_clock', 0); self.last_data = loaded_state.get('last_data', {}); self.state_recorded_snapshot_id = loaded_state.get('state_recorded_snapshot_id', -1); self.adapter.info(f"Estado local restaurado (LC={self.lamport_clock}).")
            if loaded_state.get('was_coordinator', False):
                self.adapter.warning("Restaurando estado como COORDENADOR!");
                with coordinator_lock: current_coordinator_id = self.sensor_id
                with replication_store_lock: loaded_store = loaded_state.get('replicated_data_store', {}); replicated_data_store.clear(); replicated_data_store.update(loaded_store); self.adapter.info(f"Store replicacao restaurado ({len(replicated_data_store)}).")
                with mutex_lock_state_lock: loaded_lock = loaded_state.get('resource_lock_state', {}); resource_lock_state.update(loaded_lock); self.adapter.info(f"Estado Lock Mutex restaurado (Locked: {resource_lock_state.get('locked')}).")
                threading.Thread(target=start_coordinator_heartbeat_thread, daemon=True).start()
            else: self.adapter.info("Checkpoint indicou NaO era coordenador.")
            return True
        except (json.JSONDecodeError, KeyError, Exception) as e: self.adapter.error(f"Erro carregar checkpoint {filepath}: {e}", exc_info=True);
        with self.lock: self.lamport_clock = 0; self.last_data = {}; self.state_recorded_snapshot_id = -1; return False


    # Implementacao dos RPCs
    def GetServerPublicKey(self, request, context):
        global server_public_key_pem
        self.adapter.info(f"Recebido GetServerPublicKey de {context.peer()}")
        if server_public_key_pem: return sensor_pb2.PublicKeyResponse(public_key_pem=server_public_key_pem)
        else: context.set_code(grpc.StatusCode.INTERNAL); context.set_details("Chave publica nao carregada."); self.adapter.error("Chave publica nao disponivel."); return sensor_pb2.PublicKeyResponse()

    def EstablishSession(self, request, context):
        global server_private_key, active_sessions, session_lock
        client_id = request.client_id; encrypted_bundle = request.encrypted_key_bundle
        self.adapter.info(f"Recebido EstablishSession de {client_id} ({context.peer()})")
        if not server_private_key: self.adapter.error("Chave privada nao carregada."); return sensor_pb2.SessionResponse(success=False, message="Erro interno (chave)")
        decrypted_bundle = decrypt_with_rsa(server_private_key, encrypted_bundle)
        if not decrypted_bundle or len(decrypted_bundle) != 48: self.adapter.error(f"Falha decriptografar bundle de {client_id}. Tam: {len(decrypted_bundle) if decrypted_bundle else 'None'}"); return sensor_pb2.SessionResponse(success=False, message="Falha decriptografia (tam/cont)")
        aes_key = decrypted_bundle[:32]; iv_from_client = decrypted_bundle[32:]
        session_token = f"session_{uuid.uuid4().hex}"
        with session_lock: active_sessions[session_token] = { 'aes_key': aes_key, 'client_id': client_id, 'created': time.time() }
        self.adapter.info(f"Sessao estabelecida p/ {client_id}. Token: {session_token[:8]}...")
        return sensor_pb2.SessionResponse(success=True, session_token=session_token, message="Sessao estabelecida")

    def GetData(self, request, context):
        global current_coordinator_id, active_sessions, session_lock
        peer_info = context.peer(); session_token = request.session_token
        session_info = None;
        with session_lock: session_info = active_sessions.get(session_token)
        if not session_info:
            self.adapter.warning(f"GetData negado: Token invalido de {peer_info}.")
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Token invalido")
            return sensor_pb2.SensorData(sensor_id=self.sensor_id, lamport_timestamp=self._update_lc())

        aes_key = session_info['aes_key']; client_id_from_session = session_info['client_id']; self.adapter.debug(f"GetData: Sessao valida p/ token {session_token[:8]} (Cli: {client_id_from_session})")

        current_lc = self._update_lc(); temp_reading = 0.0; data_to_encrypt = None
        with self.lock:  # protege o estado interno
            temp_reading = round(random.uniform(15.0, 45.0), 2); self.last_data = { "timestamp": time.time(), "temperatura": temp_reading, "umidade": round(random.uniform(40.0, 90.0), 2), "pressao": round(random.uniform(980.0, 1050.0), 2) }
            data_to_encrypt = { "t": self.last_data["temperatura"], "u": self.last_data["umidade"], "p": self.last_data["pressao"], "ts": self.last_data["timestamp"] }
        self.adapter.info(f"LC:{current_lc} - GetData req de {peer_info} (Sessao: {session_token[:8]}...).")

        # tenta Alerta Global com Mutex
        if temp_reading > 42.0:
            self.adapter.warning(f"Alta temp ({temp_reading}°C). Tentando lock ...")

        #Criptografia do Payload
        encrypted_payload = None; iv = os.urandom(12); auth_tag = None
        try:
            plaintext = json.dumps(data_to_encrypt).encode('utf-8'); associated_data = None
            encrypted_payload, auth_tag = encrypt_with_aes_gcm(aes_key, iv, plaintext, associated_data)
        except Exception as e:
            self.adapter.error(f"Erro ao criptografar payload p/ {session_token}: {e}")
            context.set_code(grpc.StatusCode.INTERNAL); context.set_details("Erro de criptografia.")
            return sensor_pb2.SensorData(sensor_id=self.sensor_id, lamport_timestamp=current_lc)
        if encrypted_payload is None or auth_tag is None:
            context.set_code(grpc.StatusCode.INTERNAL); context.set_details("Falha ao gerar payload/tag criptografado.")
            return sensor_pb2.SensorData(sensor_id=self.sensor_id, lamport_timestamp=current_lc)

        # monta e retorna resposta criptografada
        response = sensor_pb2.SensorData(
            sensor_id=self.sensor_id,
            lamport_timestamp=current_lc,
            encrypted_payload=encrypted_payload,
            iv=iv,
            auth_tag=auth_tag
        )
        return response

    # outros RPCs
    def ProcessMarker(self, request_marker, context):
        self.adapter.debug(f"ProcessMarker chamado por {context.peer()}"); peer_info = context.peer(); received_lc = request_marker.sender_lamport_clock; current_lc = self._update_lc(received_lc); self.adapter.info(f"LC:{current_lc} - Recebido Marker SnapID:{request_marker.snapshot_id} de {request_marker.source_id}"); response_state_proto = None
        with self.lock:
            if request_marker.snapshot_id > self.state_recorded_snapshot_id: self.adapter.info(f"LC:{current_lc} - Primeiro marker SnapID:{request_marker.snapshot_id}. Gravando estado."); self.recorded_state_for_snapshot = { "state_lamport_clock": current_lc, "last_timestamp_physical": self.last_data.get("timestamp", 0),"last_temperatura": self.last_data.get("temperatura", 0.0),"last_umidade": self.last_data.get("umidade", 0.0),"last_pressao": self.last_data.get("pressao", 0.0) }; self.state_recorded_snapshot_id = request_marker.snapshot_id; response_state_proto = sensor_pb2.SensorState(sensor_id=self.sensor_id, state_lamport_clock=current_lc, last_timestamp_physical=self.recorded_state_for_snapshot["last_timestamp_physical"], last_temperatura=self.recorded_state_for_snapshot["last_temperatura"], last_umidade=self.recorded_state_for_snapshot["last_umidade"], last_pressao=self.recorded_state_for_snapshot["last_pressao"])
            else: self.adapter.info(f"LC:{current_lc} - Ja gravei estado p/ SnapID:{request_marker.snapshot_id}."); response_state_proto = None
        response_lc = self._update_lc(); ack_marker = sensor_pb2.SnapshotMarker(snapshot_id=request_marker.snapshot_id, initiator_id=request_marker.initiator_id, source_id=self.sensor_id, sender_lamport_clock=response_lc, is_ack=True, recorded_state=response_state_proto ); self.adapter.info(f"LC:{response_lc} - Enviando ACK Marker SnapID:{request_marker.snapshot_id} para {peer_info}."); return ack_marker

    def ProcessBullyMessage(self, request_bully, context):
        self.adapter.debug(f"ProcessBullyMessage chamado por {context.peer()}"); global election_in_progress, election_timer, current_coordinator_id; my_id = self.sensor_id; sender_id = request_bully.sender_id; msg_type = request_bully.type; response_type = None; process_election = False
        if msg_type == sensor_pb2.BullyMessage.ELECTION:
            self.adapter.info(f"Recebido ELECTION de {sender_id}");
            if sender_id < my_id:
                 if not is_node_failed(sender_id): self.adapter.info(f"Respondendo OK p/ {sender_id} e iniciando eleicao."); response_type = sensor_pb2.BullyMessage.OK; process_election = True
                 else: self.adapter.warning(f"ELEICAO de no falho ({sender_id}). Ignorando.")
        elif msg_type == sensor_pb2.BullyMessage.OK:
             self.adapter.info(f"Recebido OK de {sender_id}");
             with election_lock:
                 if election_in_progress: self.adapter.info("Cancelando timer eleicao, aguardando coordenador.");
                 if election_timer and election_timer.is_alive(): election_timer.cancel()
                 election_timer = threading.Timer(ELECTION_TIMEOUT * 2, handle_election_timeout, args=[True]); election_timer.start()
        elif msg_type == sensor_pb2.BullyMessage.COORDINATOR:
            self.adapter.info(f"***** Recebido anuncio COORDENADOR de {sender_id} *****")
            with election_lock:
                if election_in_progress: self.adapter.info("Cancelando eleicao local (novo coordenador).");
                if election_timer and election_timer.is_alive(): election_timer.cancel(); election_timer = None
                election_in_progress = False
            with coordinator_lock:
                if current_coordinator_id != sender_id: current_coordinator_id = sender_id; self.adapter.info(f"Novo coordenador: {current_coordinator_id}"); clear_failed_node(sender_id)
                if my_id != sender_id: stop_coordinator_heartbeat_thread()
            if my_id == sender_id: start_coordinator_heartbeat_thread()
        response_bully = sensor_pb2.BullyMessage(sender_id=my_id, type=sensor_pb2.BullyMessage.OK)
        if process_election: threading.Thread(target=start_election, daemon=True).start()
        if response_type == sensor_pb2.BullyMessage.OK: self.adapter.info(f"Enviando OK para {sender_id}"); return response_bully
        else: return sensor_pb2.BullyMessage(sender_id=my_id, type=sensor_pb2.BullyMessage.OK) # Default gRPC

    def Ping(self, request, context):
        self.adapter.debug(f"Ping recebido de {request.sender_id}")
        response = sensor_pb2.PingResponse(responder_id=self.sensor_id)
        return response

    def ReplicateData(self, request_data, context):
        global current_coordinator_id, replicated_data_store; my_id = self.sensor_id; sender_id = request_data.sensor_id; coord_id = None;
        with coordinator_lock: coord_id = current_coordinator_id
        if coord_id != my_id: msg = "Nao sou o coordenador."; self.adapter.warning(f"ReplicateData de {sender_id}, mas nao sou coord ({coord_id})."); return sensor_pb2.ReplicationAck(success=False, message=msg)
        self.adapter.warning(f"ReplicateData recebido de {sender_id}. Dados nao descriptografados.")
        return sensor_pb2.ReplicationAck(success=False, message="Replicacao insegura nao implementada.")

    def RequestLock(self, request_lock, context):
        self.adapter.debug(f"RequestLock recebido de {request_lock.requester_id}")
        global current_coordinator_id, resource_lock_state; my_id = self.sensor_id; requester_id = request_lock.requester_id; resource_id = request_lock.resource_id
        coord_id = None
        with coordinator_lock: coord_id = current_coordinator_id
        if coord_id != my_id: msg = f"Nao sou o coordenador ({coord_id})."; self.adapter.warning(f"RequestLock de {requester_id}, mas nao sou coord."); return sensor_pb2.LockResponse(granted=False, message=msg)
        with mutex_lock_state_lock:
            holder = resource_lock_state["holder"]; locked = resource_lock_state["locked"]; lock_time = resource_lock_state["timestamp"]; now = time.time()
            if locked and (now - lock_time > MUTEX_LOCK_TIMEOUT): self.adapter.warning(f"Lock '{resource_id}' expirou (holder: {holder}). Liberando."); locked = False; holder=None
            if not locked: resource_lock_state.update({"locked": True, "holder": requester_id, "timestamp": now}); msg = f"Lock '{resource_id}' concedido a {requester_id}."; self.adapter.info(msg); return sensor_pb2.LockResponse(granted=True, message=msg)
            else: msg = f"Lock '{resource_id}' negado. Detido por {holder}."; self.adapter.info(f"RequestLock de {requester_id} negado."); return sensor_pb2.LockResponse(granted=False, message=msg, current_holder=holder)

    def ReleaseLock(self, release_request, context):
        self.adapter.debug(f"ReleaseLock recebido de {release_request.requester_id}")
        global current_coordinator_id, resource_lock_state; my_id = self.sensor_id; requester_id = release_request.requester_id; resource_id = release_request.resource_id
        coord_id = None
        with coordinator_lock: coord_id = current_coordinator_id
        if coord_id != my_id: msg = f"Nao sou o coordenador ({coord_id})."; self.adapter.warning(f"ReleaseLock de {requester_id}, mas nao sou coord."); return sensor_pb2.LockResponse(granted=False, message=msg)
        with mutex_lock_state_lock:
            holder = resource_lock_state["holder"]; locked = resource_lock_state["locked"]
            if locked and holder == requester_id: resource_lock_state.update({"locked": False, "holder": None, "timestamp": 0}); msg = f"Lock '{resource_id}' liberado por {requester_id}."; self.adapter.info(msg); return sensor_pb2.LockResponse(granted=True, message=msg)
            elif locked: msg = f"Falha: {requester_id} tentou liberar lock detido por {holder}."; self.adapter.warning(msg); return sensor_pb2.LockResponse(granted=False, message=msg, current_holder=holder)
            else: msg = f"Falha: Recurso '{resource_id}' ja livre."; self.adapter.warning(f"{requester_id} tentou liberar lock livre."); return sensor_pb2.LockResponse(granted=False, message=msg)


# Funcoes Multicast
def send_multicast_message(message_dict, adapter, ttl=MCAST_TTL):
    # envia mensagem para o grupo multicast
    try:
        my_id = adapter.extra.get('sensorId'); is_coord = False
        with coordinator_lock: is_coord = (current_coordinator_id == my_id)
        if is_coord and message_dict.get("type") == "announce": message_dict["is_coordinator"] = True
        message_json = json.dumps(message_dict); message_bytes = message_json.encode('utf-8')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.sendto(message_bytes, (MCAST_GRP, MCAST_PORT))
            adapter.debug(f"Multicast enviado: {message_json}")
    except Exception as e: adapter.error(f"Erro ao enviar mensagem multicast: {e}", exc_info=True)


def multicast_listener_thread(adapter):
    # Thread que faz o listener multicast (anuncios, alertas)
    global current_coordinator_id, election_in_progress, election_timer
    my_id = adapter.extra.get('sensorId'); adapter.info("Listener Multicast iniciado.")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(('', MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY); sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq); adapter.info(f"Escutando multicast {MCAST_GRP}:{MCAST_PORT}")
        while True:  # loop principal
            try: data, addr = sock.recvfrom(1024); message_json = data.decode('utf-8'); message = json.loads(message_json); msg_type = message.get("type"); sender_id = message.get("sensor_id")
            except (socket.timeout, json.JSONDecodeError, UnicodeDecodeError) as e: adapter.warning(f"Erro ao receber/decodificar multicast: {e}"); continue  # pula iteracao
            except Exception as e: adapter.error(f"Erro inesperado no loop listener: {e}", exc_info=True); time.sleep(1); continue  # espera e continua

            if not sender_id or sender_id == my_id: continue
            if msg_type == "announce":
                host = message.get("grpc_host"); port = message.get("grpc_port"); is_sender_coord = message.get("is_coordinator", False)
                if host and port is not None:
                    update_peer(sender_id, host, port); clear_failed_node(sender_id)
                    old_coord = None;
                    with coordinator_lock: old_coord = current_coordinator_id
                    if is_sender_coord and sender_id != old_coord: adapter.info(f"Novo Coordenador via anuncio: {sender_id}");
                    with election_lock:
                        if election_in_progress: adapter.info("Cancelando eleicao local (coord via multicast).");
                        if election_timer and election_timer.is_alive(): election_timer.cancel(); election_timer=None
                        election_in_progress = False
                    current_coordinator_id = sender_id;
                    if my_id != sender_id: stop_coordinator_heartbeat_thread()
                    if my_id == sender_id: start_coordinator_heartbeat_thread()
                    elif not is_sender_coord and sender_id == old_coord: adapter.warning(f"Anuncio do Coord {sender_id} sem flag.")
                else: adapter.warning(f"Anuncio invalido de {addr}")
            elif msg_type == "alert":
                alert_type = message.get("alert_type", "GENERIC")
                if alert_type == "NODE_FAILED": failed_node_id = message.get("failed_node_id")
                if failed_node_id: adapter.warning(f"ALERTA: No {failed_node_id} FALHO (anunc por {sender_id})."); mark_node_failed(failed_node_id); coord_id = None
                with coordinator_lock: coord_id = current_coordinator_id
                if failed_node_id == coord_id: adapter.warning(f"Coordenador falhou! Iniciando eleicao."); start_election()
                elif alert_type == "GLOBAL_HIGH_TEMP": adapter.critical(f"*** ALERTA GLOBAL TEMP ALTA [{sender_id}]: {message.get('message','')} ***")
                else: adapter.warning(f"ALERTA [{alert_type}] de [{sender_id}]: {message.get('message','')} (Valor: {message.get('value','N/A')})")

    except socket.error as se: adapter.error(f"Erro Socket Listener Multicast (porta {MCAST_PORT}?): {se}")
    except Exception as e: adapter.error(f"Erro fatal listener: {e}", exc_info=True)
    finally: adapter.info("Listener Multicast encerrado."); sock.close()


def multicast_announcer_thread(sensor_id, grpc_port, adapter, interval=ANNOUNCE_INTERVAL):
    adapter.info(f"Announcer Multicast iniciado (intervalo: {interval}s).")
    while True: time.sleep(interval); announcement = { "type": "announce", "sensor_id": sensor_id, "grpc_host": LOCAL_IP, "grpc_port": grpc_port, "timestamp": time.time() }; send_multicast_message(announcement, adapter); check_coordinator_liveness(adapter)


# verificacao liveness (se ta vivo) coordenador
last_coordinator_seen_time = 0


def check_coordinator_liveness(adapter):
    # verifica se o coordenador esta ativo
    global current_coordinator_id, last_coordinator_seen_time, election_in_progress
    my_id = adapter.extra.get('sensorId'); coord_id = None;
    with coordinator_lock: coord_id = current_coordinator_id
    if coord_id is None or coord_id == my_id: return;
    with election_lock:
        if election_in_progress: return
    coord_info = None; last_seen = 0;
    with discovery_lock: coord_info = discovered_peers.get(coord_id)
    if coord_info: last_seen = coord_info.get("last_seen", 0)
    effective_last_seen = max(last_seen, last_coordinator_seen_time)

    needs_election = False
    if effective_last_seen == 0 and coord_id is not None: adapter.warning(f"Coord {coord_id} nunca visto. Iniciando eleicao."); needs_election = True
    elif time.time() - effective_last_seen > COORDINATOR_TIMEOUT:
        last_seen_str = time.strftime('%H:%M:%S', time.localtime(effective_last_seen)) if effective_last_seen > 0 else 'nunca'
        adapter.warning(f"Coord {coord_id} nao visto (> {COORDINATOR_TIMEOUT}s, ultimo: {last_seen_str}). Iniciando eleicao."); needs_election = True
    if needs_election: start_election(); last_coordinator_seen_time = time.time()
    elif coord_info: last_coordinator_seen_time = coord_info.get("last_seen", last_coordinator_seen_time)


# Funcao Principal
def serve_sensor(sensor_id, grpc_port, adapter):
    # configura e inicia o servidor gRPC e threads
    global server_private_key, server_public_key_pem
    server_private_key = load_private_key()
    server_public_key_pem = load_public_key_pem()
    if not server_private_key or not server_public_key_pem: adapter.critical("Falha carregar chaves RSA. Encerrando."); return

    service_instance = SensorServiceImpl(sensor_id)  # instancia o servico
    listener = threading.Thread(target=multicast_listener_thread, args=(adapter,), daemon=True, name="MulticastListener")
    listener.start()
    announcer = threading.Thread(target=multicast_announcer_thread, args=(sensor_id, grpc_port, adapter), daemon=True, name="MulticastAnnouncer")
    announcer.start()
    start_checkpoint_thread(service_instance)  # inicia o checkpoint
    adapter.info("Aguardando para descoberta de peers...")
    time.sleep(random.uniform(4, 8))  # Delay inicial
    coord_id = None;
    with coordinator_lock: coord_id = current_coordinator_id
    if coord_id is None: adapter.info("Nenhum coordenador. Iniciando eleicao."); start_election()
    else: adapter.info(f"Coordenador inicial conhecido: {coord_id}")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    sensor_pb2_grpc.add_SensorServiceServicer_to_server(service_instance, server)
    server_started = False; grpc_bind_address = f'[::]:{grpc_port}'
    try:
        server.add_insecure_port(grpc_bind_address)  # canal gRPC inseguro
        server.start(); server_started = True
        adapter.info(f"--> Servidor gRPC [{sensor_id}] iniciado. Escutando em {grpc_bind_address}")
        while True: time.sleep(3600)  # mantem a thread principal viva
    except KeyboardInterrupt: adapter.info("Ctrl+C recebido.")
    except OSError as e: adapter.error(f"!!! Erro OS servidor gRPC {grpc_bind_address}: {e}.")
    except Exception as e: adapter.error(f"!!! Erro inesperado servidor gRPC: {e}", exc_info=True)
    finally:
        adapter.info(f"Servidor gRPC [{sensor_id}] encerrando...")
        stop_coordinator_heartbeat_thread()  # aara o HB
        stop_checkpoint_thread()  # para o checkpoint
        if server_started: server.stop(grace=1)  # para o gRPC


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor Sensor gRPC com Seguranca Basica")
    parser.add_argument("--id", type=str, required=True, help="ID unico (ex: sensor_cl_01)")
    parser.add_argument("--port", type=int, required=True, help="Porta gRPC (ex: 65400)")
    args = parser.parse_args()
    sensor_id_adapter = SensorLogAdapter(logger, {'sensorId': args.id})  # inicializa o adapter
    threading.current_thread().name = "MainThread"  # nomeia a thread principal
    sensor_id_adapter.info(f"Iniciando sensor ID: {args.id} | Porta gRPC: {args.port}")
    sensor_id_adapter.info(f"IP local: {LOCAL_IP} | Multicast: {MCAST_GRP}:{MCAST_PORT}")
    serve_sensor(args.id, args.port, sensor_id_adapter)  # funcao principal
    sensor_id_adapter.info("Programa principal do sensor encerrado.")
