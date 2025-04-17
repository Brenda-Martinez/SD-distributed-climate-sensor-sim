import grpc
import time
import os
import sys
import logging
import threading
import collections
from collections import OrderedDict
import uuid
import socket
import struct
import json
import sensor_pb2
import sensor_pb2_grpc
from multicast_config import MCAST_GRP, MCAST_PORT

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# config logging
LOG_FORMAT = '%(asctime)s [ClienteCL-%(threadName)s] %(levelname)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("ClientLogger")
logger.setLevel(logging.INFO)  # nivel inicial eh INFO

POLL_INTERVAL = 10
SNAPSHOT_INTERVAL_CYCLES = 3
SENSOR_TIMEOUT = 45
CLIENT_CHECKPOINT_HISTORY_SIZE = 5
CLIENT_CHECKPOINT_DIR = "checkpoints_client"
CLIENT_CHECKPOINT_FILENAME_PREFIX = "checkpoint_client_"
CLIENT_ID_FILENAME = "client_id.txt"
SERVER_PUBLIC_KEY_FILE = "server_public.pem"  # o cliente precisa deste arquivo

# Estado Global do Cliente
CLIENT_ID = None  # definido no inicio
client_lamport_clock = 0; client_lock = threading.Lock()
# Dicionario de sensores inclui informaçoes da sessao
# { "sensor_id": {"host": ip, "port": port, "last_seen": ts, "is_coord": bool, "is_failed": bool,
#                 "session": {"token": str, "aes_key": bytes, "established_at": ts} ou None }}
discovered_sensors = {}; discovery_lock = threading.Lock()
current_coordinator_id_client = None
current_snapshot_data = None; snapshot_lock = threading.Lock(); active_snapshot_id = -1
verbose_mode = False; stop_event = threading.Event()
historical_data = collections.deque(maxlen=CLIENT_CHECKPOINT_HISTORY_SIZE)
# chave publica do servidor
server_public_key = None


def get_persistent_client_id(filename=CLIENT_ID_FILENAME):
    # carrega/gera e salva um ID de cliente persistente
    client_id = None
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f: client_id = f.read().strip()
            if client_id: logger.debug(f"ID Cliente carregado: {client_id}")
            else: logger.warning(f"{filename} vazio. Gerando novo."); client_id = None
        if not client_id:
            client_id = f"client_{uuid.uuid4().hex[:6]}"
            logger.info(f"Gerado novo ID Cliente: {client_id}. Salvando...")
            try:
                with open(filename, 'w') as f: f.write(client_id)
            except IOError as e: logger.error(f"Erro ao salvar ID: {e}")
    except Exception as e:
        logger.error(f"Erro ao obter/gerar ID: {e}. Gerando temporario...")
        if not client_id: client_id = f"client_{uuid.uuid4().hex[:6]}_temp"
    return client_id


def update_client_clock(received_lc=None):
    global client_lamport_clock;
    with client_lock:
        if received_lc is not None: client_lamport_clock = max(client_lamport_clock, received_lc) + 1
        else: client_lamport_clock += 1; logger.debug(f"Clock logico do cliente (LC): {client_lamport_clock}"); return client_lamport_clock


# Funçoes de Estado/Descoberta
def update_sensor_list(sensor_id, host, port, is_coord=False, is_failed=None):
    with discovery_lock:
        now = time.time(); current_info = discovered_sensors.get(sensor_id, {}); was_new = sensor_id not in discovered_sensors
        was_failed = current_info.get('is_failed', False)
        logger.debug(f"Update/Add Sensor: ID={sensor_id}@{host}:{port}, coord={is_coord}, failed={is_failed}")
        if was_new: logger.info(f"Sensor DESCOBERTO: {sensor_id} @ {host}:{port}"); discovered_sensors[sensor_id] = {'session': None}  # inicia sessao
        if not was_new and (current_info.get('host') != host or current_info.get('port') != port): logger.info(f"Sensor ATUALIZADO: {sensor_id} -> {host}:{port}")
        if 'is_failed' not in current_info: current_info['is_failed'] = False
        # garante que 'session' existe se a entrada ja existia
        if 'session' not in discovered_sensors.get(sensor_id, {}): discovered_sensors[sensor_id]['session'] = None

        discovered_sensors[sensor_id].update({ 'host': host, 'port': port, 'last_seen': now,'is_coord': (sensor_id == current_coordinator_id_client),'is_failed': current_info['is_failed']})
        if is_failed is not None:
            if was_failed and not is_failed: logger.info(f"Sensor RECUPERADO: {sensor_id}")
            discovered_sensors[sensor_id]['is_failed'] = is_failed
            if is_failed: discovered_sensors[sensor_id]['session'] = None  # reseta sessao se falhar
        elif was_failed: logger.info(f"Sensor RECUPERADO: {sensor_id}"); discovered_sensors[sensor_id]['is_failed'] = False


def mark_sensor_failed(sensor_id, failed_status=True):
     global current_coordinator_id_client;
     with discovery_lock:
         if sensor_id in discovered_sensors: current_info = discovered_sensors[sensor_id]
         if current_info.get('is_failed') != failed_status:
             log_level = logging.WARNING if failed_status else logging.INFO; logger.log(log_level, f"Cliente marcando {sensor_id} como {'FALHO' if failed_status else 'ATIVO'}.")
             current_info['is_failed'] = failed_status; current_info['session'] = None  # reseta sessao
             if failed_status and current_info.get('is_coord'): logger.debug(f"Coord {sensor_id} falho."); current_coordinator_id_client = None;
             for sid, info in discovered_sensors.items(): info['is_coord'] = False


def set_client_coordinator_view(coord_id):
    global current_coordinator_id_client;
    with discovery_lock:
        if current_coordinator_id_client != coord_id: logger.debug(f"Cliente visao Coord -> {coord_id if coord_id else 'Nenhum'}")
        current_coordinator_id_client = coord_id
        for sid, info in discovered_sensors.items(): is_now_coord = (sid == coord_id); info['is_coord'] = is_now_coord
        if is_now_coord and info.get('is_failed'): logger.debug(f"Novo coord {sid} ativo."); info['is_failed'] = False


def prune_stale_sensors():
    global current_coordinator_id_client;
    with discovery_lock:
        now = time.time(); stale_sensors = [ sid for sid, info in discovered_sensors.items() if now - info.get("last_seen", 0) > SENSOR_TIMEOUT ]
        if stale_sensors: logger.debug(f"Verificando expirados: {stale_sensors}")
        for sensor_id in stale_sensors:
            logger.warning(f"Sensor {sensor_id} expirou. Removendo.");
            if sensor_id == current_coordinator_id_client:
                set_client_coordinator_view(None)
            if sensor_id in discovered_sensors:
                del discovered_sensors[sensor_id]


def get_discovered_sensors(include_failed=True):
    with discovery_lock:
        if include_failed: return {sid: info.copy() for sid, info in discovered_sensors.items()}
        else: return {sid: info.copy() for sid, info in discovered_sensors.items() if not info.get('is_failed', False)}


# Funçoes de Criptografia
def load_server_public_key(filename=SERVER_PUBLIC_KEY_FILE):
    # carrega a chave publica RSA do servidor do arquivo PEM
    try:
        with open(filename, "rb") as key_file: public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        logger.info(f"Chave publica do servidor carregada de {filename}")
        return public_key
    except Exception as e: logger.error(f"Falha ao carregar a chave publica servidor {filename}: {e}"); return None


def encrypt_with_rsa(public_key, data):
    # criptografa dados usando chave publica RSA (OAEP)
    try:
        return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except Exception as e: logger.error(f"Falha na criptografia RSA: {e}"); return None


def decrypt_with_aes_gcm(key, iv, ciphertext, tag, associated_data=None):
    # descriptografa dados usando AES-GCM
    try:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        if associated_data: decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidSignature: logger.error("Falha na descriptografia AES-GCM: Tag invalida!"); return None
    except Exception as e: logger.error(f"Falha na descriptografia AES-GCM: {e}"); return None


# Funçoes gRPC
def establish_session_with_sensor(sensor_id, host, port):
    # estabelece uma sessao AES segura com o sensor
    global server_public_key, CLIENT_ID, discovered_sensors  # acessa variaveis globais
    target = f"{host}:{port}"
    logger.info(f"Tentando estabelecer sessao segura com {sensor_id}@{target}...")

    if not server_public_key: logger.error("Chave publica servidor nao carregada."); return None

    try:
        with grpc.insecure_channel(target) as channel:
            stub = sensor_pb2_grpc.SensorServiceStub(channel)
            # gerar chave AES e IV (IV aqui e so para o bundle)
            aes_key = os.urandom(32)  # AES-256 key
            iv_dummy = os.urandom(16)  # IV para completar o bundle
            key_bundle = aes_key + iv_dummy  # envia chave concatenada com IV dummy

            # criptografa o bundle com RSA publica do servidor
            encrypted_bundle = encrypt_with_rsa(server_public_key, key_bundle)
            if not encrypted_bundle: logger.error(f"Falha criptografar bundle p/ {sensor_id}"); return None

            # chama a funcao EstablishSession
            request = sensor_pb2.EncryptedSessionKeyRequest( client_id=CLIENT_ID, encrypted_key_bundle=encrypted_bundle )
            response = stub.EstablishSession(request, timeout=7)

            # processa a resposta
            if response and response.success and response.session_token:
                session_info = { "token": response.session_token, "aes_key": aes_key, "established_at": time.time() }
                logger.info(f"Sessao segura estabelecida com {sensor_id}. Token: {response.session_token[:8]}...")
                # atualiza o dicionario de sensores com a sessao
                with discovery_lock:
                    if sensor_id in discovered_sensors: discovered_sensors[sensor_id]['session'] = session_info
                    else: logger.warning(f"Sensor {sensor_id} desapareceu durante handshake?")
                return session_info
            else: logger.error(f"Falha ao estabelecer sessao com {sensor_id}: {response.message if response else 'Sem resposta'}"); return None
    except grpc.RpcError as e: logger.error(f"Erro gRPC [EstablishSession] com {sensor_id}@{target}: {e.code()}"); mark_sensor_failed(sensor_id, True); return None
    except Exception as e: logger.error(f"Erro inesperado [EstablishSession] com {sensor_id}@{target}: {e}"); mark_sensor_failed(sensor_id, True); return None


def get_sensor_data_grpc(sensor_id, host, port):
    # obtem dados criptografados, estabelecendo sessao
    global discovered_sensors # acessa o dict global
    target = f"{host}:{port}"; session_info = None; data_dict = None

    # verifica/obtem sessao
    with discovery_lock:
        sensor_info = discovered_sensors.get(sensor_id)
        if sensor_info: session_info = sensor_info.get('session')
    if not session_info:
        session_info = establish_session_with_sensor(sensor_id, host, port)
        if not session_info: logger.error(f"Nao foi possivel obter/estabelecer sessao com {sensor_id}."); return None  # Retorna None (dict vazio) se falhar sessao

    # tenta chamar GetData com o token de sessao
    logger.debug(f"Usando sessao {session_info['token'][:8]} p/ GetData de {sensor_id}@{target}")
    try:
        with grpc.insecure_channel(target) as channel:
            stub = sensor_pb2_grpc.SensorServiceStub(channel)
            request = sensor_pb2.SensorRequest(sensor_id_requested=sensor_id, session_token=session_info['token'])
            response = stub.GetData(request, timeout=5)  # resposta tem payload criptografado

            # descriptografa Payload
            decrypted_payload_bytes = decrypt_with_aes_gcm( key=session_info['aes_key'], iv=response.iv,
                                                            ciphertext=response.encrypted_payload, tag=response.auth_tag)
            if decrypted_payload_bytes:
                try:
                    decrypted_data = json.loads(decrypted_payload_bytes.decode('utf-8'))
                    current_client_lc = update_client_clock(response.lamport_timestamp)
                    logger.info(f"LC:{current_client_lc} - Dados descriptografados de {response.sensor_id}@{target} (LC:{response.lamport_timestamp}): T={decrypted_data.get('t'):.1f}°, U={decrypted_data.get('u'):.1f}%, P={decrypted_data.get('p'):.1f} ATM")
                    # monta o dicionario de retorno com dados descriptografados
                    data_dict = { "sensor_id": response.sensor_id, "timestamp": decrypted_data.get('ts'), "temperatura": decrypted_data.get('t'),
                                  "umidade": decrypted_data.get('u'), "pressao": decrypted_data.get('p'), "lamport_timestamp": response.lamport_timestamp }
                    if response.sensor_id != sensor_id: logger.warning(f"ID recebido ({response.sensor_id}) diferente do esperado ({sensor_id})!")
                    mark_sensor_failed(sensor_id, False)  # sucesso
                except (json.JSONDecodeError, KeyError) as e: logger.error(f"Erro ao processar payload descriptografado de {sensor_id}: {e}"); data_dict = None
            else: logger.error(f"Falha ao descriptografar dados de {sensor_id}."); data_dict = None
    except grpc.RpcError as e:
        logger.error(f"Erro gRPC [GetData] {sensor_id}@{target}: {e.code()}")
        if e.code() == grpc.StatusCode.UNAUTHENTICATED: logger.warning(f"Erro na autenticaçao com {sensor_id}. Resetando sessao...");
        with discovery_lock:  # reseta sessao local para tentar reautenticar
            if sensor_id in discovered_sensors: discovered_sensors[sensor_id]['session'] = None
        mark_sensor_failed(sensor_id, True); return None
    except Exception as e: logger.error(f"Erro inesperado [GetData] {sensor_id}@{target}: {e}"); mark_sensor_failed(sensor_id, True); return None
    return data_dict  # retorna dicionario com dados descriptografados ou None


def send_marker_to_sensor(sensor_id, host, port, snapshot_id):
    target = f"{host}:{port}"; ack_marker_result = None; logger.debug(f"[Snapshot ID:{snapshot_id}] Enviando Marker p/ {sensor_id}@{target}...")
    try:
        with grpc.insecure_channel(target) as channel: stub = sensor_pb2_grpc.SensorServiceStub(channel); marker_lc = update_client_clock(); marker_to_send = sensor_pb2.SnapshotMarker( snapshot_id=snapshot_id, initiator_id=CLIENT_ID, source_id=CLIENT_ID, sender_lamport_clock=marker_lc, is_ack=False ); ack_marker_result = stub.ProcessMarker(marker_to_send, timeout=7); received_ack_lc = ack_marker_result.sender_lamport_clock; current_client_lc_after_ack = update_client_clock(received_ack_lc); logger.debug(f"[Snapshot ID:{snapshot_id}] Recebido ACK de {ack_marker_result.source_id} (LC:{received_ack_lc}). Cliente LC:{current_client_lc_after_ack}"); mark_sensor_failed(sensor_id, False)
    except grpc.RpcError as e: logger.error(f"[Snapshot ID:{snapshot_id}] Erro gRPC [ProcessMarker] {sensor_id}@{target}: {e.code()}"); mark_sensor_failed(sensor_id, True); return {"error": f"gRPC Error: {e.code()}"}
    except Exception as e: logger.error(f"[Snapshot ID:{snapshot_id}] Erro inesperado [ProcessMarker] {sensor_id}@{target}: {e}"); mark_sensor_failed(sensor_id, True); return {"error": f"Unexpected Error: {e}"}
    return ack_marker_result


def initiate_chandy_lamport_snapshot():
    global current_snapshot_data, active_snapshot_id, client_lamport_clock; sensors_to_snapshot = get_discovered_sensors(include_failed=False)
    if not sensors_to_snapshot: logger.warning("Nenhum sensor ativo p/ snapshot."); return
    with snapshot_lock:
        if active_snapshot_id != -1: logger.warning(f"Snapshot {active_snapshot_id} ja ativo."); return
        current_lc = update_client_clock(); snapshot_id = time.time_ns(); active_snapshot_id = snapshot_id; logger.info(f"*** INICIANDO Snapshot CL (INSEGURO) (ID: {snapshot_id}, LC: {current_lc}) p/ {len(sensors_to_snapshot)} sensores ***")
        client_state = {"lamport_clock": current_lc}; snapshot_results = OrderedDict(); snapshot_results[CLIENT_ID] = {"state": client_state, "is_initiator": True}; pending_acks = set(sensors_to_snapshot.keys())
        for sensor_id, sensor_info in sensors_to_snapshot.items(): host = sensor_info['host']; port = sensor_info['port']; ack_result = send_marker_to_sensor(sensor_id, host, port, snapshot_id)
        final_lc = update_client_clock(); logger.info(f"*** SNAPSHOT CL CONCLUiDO (ID: {snapshot_id}, LC final: {final_lc}) ***")
        current_snapshot_data = snapshot_results; active_snapshot_id = -1


def multicast_listener_thread():
    # escuta anuncios de sensores, alertas, e detecta coordenador
    # declara globais que serao modificados dentro desta funçao
    global current_coordinator_id_client
    # obtem o ID do cliente para evitar processar proprias mensagens

    logger.info(f"Listener Multicast iniciado.")
    # cria o socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        # configuraçoes do Socket para Multicast Receive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # faz o bind na porta multicast em todas as interfaces
        sock.bind(('', MCAST_PORT))
        # prepara a requisiçao para entrar no grupo multicast
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        # pede ao kernel para adicionar o socket ao grupo
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        logger.debug(f"Escutando multicast {MCAST_GRP}:{MCAST_PORT}")  # DEBUG

        # loop principal para receber mensagens
        while not stop_event.is_set():  # Verifica evento de parada a cada iteraçao
            try:
                # define um timeout curto para o recvfrom para que o loop verifique stop_event periodicamente
                sock.settimeout(1.0)
                # tenta receber dados (ate 1024 bytes)
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                # se deu timeout, continua para a proxima iteraçao (verifica stop_event)
                continue
            except Exception as e:
                # outros erros de socket
                logger.error(f"Erro no recvfrom do socket multicast: {e}", exc_info=True)
                time.sleep(2) # Espera um pouco antes de tentar novamente
                continue

            # se recebeu dados, processa
            try:
                message_json = data.decode('utf-8')
                message = json.loads(message_json)
                msg_type = message.get("type")
                sender_id = message.get("sensor_id")
                logger.debug(f"Multicast recebido de {addr}: {message_json}")  # DEBUG

                # ignora mensagens sem ID de remetente
                if not sender_id:
                    logger.warning(f"Mensagem multicast sem sender_id de {addr}")
                    continue
                # ignora mensagens do proprio cliente

                # processa mensagem de anuncio
                if msg_type == "announce":
                    host = message.get("grpc_host")
                    port = message.get("grpc_port")
                    is_sender_coord = message.get("is_coordinator", False)
                    # verifica se os campos essenciais estao presentes
                    if host and port is not None:
                        # atualiza a lista de peers
                        update_sensor_list(sender_id, host, port, is_coord=is_sender_coord, is_failed=False)
                        # verifica se o anuncio e de um novo coordenador
                        current_coord = None
                        with discovery_lock:
                            current_coord = current_coordinator_id_client
                        # se o anunciante se diz coordenador E ele nao e quem ja conhecemos
                        if is_sender_coord and sender_id != current_coord:
                            set_client_coordinator_view(sender_id)  # atualiza a visao
                        # se quem conheciamos como coordenador anuncia SEM a flag
                        elif not is_sender_coord and sender_id == current_coord:
                            logger.debug(f"Anuncio do Coordenador {sender_id} sem flag 'is_coordinator'. Limpando visao.")
                            set_client_coordinator_view(None)  # reseta a visao
                    else:
                        # loga anuncio invalido
                        logger.warning(f"Anuncio multicast invalido recebido de {addr}: Faltando host/port.")

                # processa mensagem de alerta
                elif msg_type == "alert":
                    alert_type = message.get("alert_type", "GENERIC")
                    # alerta de No Falho
                    if alert_type == "NODE_FAILED":
                         failed_node_id = message.get("failed_node_id")
                         if failed_node_id:
                              logger.warning(f"ALERTA MULTICAST: No {failed_node_id} marcado como FALHO (anunciado por {sender_id}).")
                              # marca o no como falho na visao do cliente
                              mark_sensor_failed(failed_node_id, True) # loga WARN interno
                    # Alerta de Temperatura Global (enviado por quem obteve o lock)
                    elif alert_type == "GLOBAL_HIGH_TEMP":
                         logger.critical(f"*** ALERTA GLOBAL TEMP ALTA [{sender_id}]: {message.get('message','')} ***") # CRITICAL
                    else:
                        logger.warning(f"ALERTA MULTICAST [{alert_type}] de [{sender_id}]: {message.get('message','')} (Valor: {message.get('value','N/A')})") # WARN

            # Tratamento de Erros no Loop Interno
            except json.JSONDecodeError:
                logger.warning(f"Mensagem multicast nao e JSON valido de {addr}")
            except Exception as e:
                # captura outros erros no processamento da mensagem
                logger.error(f"Erro ao processar mensagem multicast de {addr}: {e}", exc_info=True)

    # Tratamento de Erros na Configuraçao do Socket
    except socket.error as se:
         logger.error(f"Erro de Socket no Listener Multicast (verifique se a porta {MCAST_PORT} esta livre ou se o endereço {MCAST_GRP} e valido): {se}")
         stop_event.set()  # sinaliza para a thread principal parar se o listener falhar no inicio
    except Exception as e:
        logger.error(f"Erro fatal inesperado no Listener Multicast: {e}", exc_info=True)
        stop_event.set()  # sinaliza para a thread principal parar
    finally:
        # limpeza ao sair do loop (ou por erro)
        logger.info("Listener Multicast encerrado.")
        # tenta remover a inscriçao do grupo multicast (best effort)
        try:
            if 'mreq' in locals() and sock: # verifica se mreq foi definido
                 sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                 logger.debug("Removida inscriçao do grupo multicast.")
        except Exception as e:
             logger.debug(f"Erro ao remover inscriçao multicast (pode ser normal ao fechar): {e}")
        # fecha o socket
        if sock:
            sock.close()


# Funçao para alternar modo Verbose
def toggle_verbose_mode():
    global verbose_mode; verbose_mode = not verbose_mode; new_level = logging.DEBUG if verbose_mode else logging.INFO; logger.setLevel(new_level)
    print(f"\n*** Modo Verbose {'ATIVADO (DEBUG)' if verbose_mode else 'DESATIVADO (INFO)'} ***"); logger.info(f"Nivel log alterado: {logging.getLevelName(new_level)}")

# Thread para interacao do usuario
def user_input_thread():
    global stop_event; time.sleep(1); print("\n-------------------------------------------"); print("Comandos: 'v' (Verbose) | 'q' (Sair)"); print("-------------------------------------------")
    while not stop_event.is_set():
        try: command = input("Comando: ").strip().lower()
        except EOFError: logger.info("EOF recebido. Encerrando."); stop_event.set(); break
        except Exception as e: logger.error(f"Erro input usuario: {e}"); stop_event.set(); break
        if command == 'v': toggle_verbose_mode()
        elif command == 'q': logger.info("Comando 'q' recebido. Saindo..."); stop_event.set(); break
    logger.info("Thread de input finalizada.")


# checkpoint do cliente
def save_client_checkpoint(clock_value, history_deque):
    # salva o estado do cliente (clock e historico) em JSON
    global CLIENT_ID  # Garante que use o ID correto (persistente)
    state_to_save = {
        'client_lamport_clock': clock_value,
        'data_history': list(history_deque)  # Converte deque para lista
    }

    # garante que o diretorio de checkpoint exista
    if CLIENT_CHECKPOINT_DIR and not os.path.exists(CLIENT_CHECKPOINT_DIR):
        try:
            os.makedirs(CLIENT_CHECKPOINT_DIR)
            logger.info(f"Diretorio de checkpoint do cliente criado: {CLIENT_CHECKPOINT_DIR}")
        except OSError as e:
            logger.error(f"Erro ao criar diretorio de checkpoint {CLIENT_CHECKPOINT_DIR}: {e}")
            return  # aborta se nao conseguir criar

    # define nome dos arquivos
    filename = f"{CLIENT_CHECKPOINT_FILENAME_PREFIX}{CLIENT_ID}.json"  # Usa CLIENT_ID global
    filepath = os.path.join(CLIENT_CHECKPOINT_DIR, filename) if CLIENT_CHECKPOINT_DIR else filename
    tmp_filepath = filepath + ".tmp"

    logger.debug(f"Salvando checkpoint do cliente em {filepath}...")
    try:
        # escreve no arquivo temporario e FECHA o arquivo (fim do 'with')
        with open(tmp_filepath, 'w') as f:
            json.dump(state_to_save, f, indent=4)

        # so depois tenta renomear atomicamente
        os.replace(tmp_filepath, filepath)
        logger.debug(f"Checkpoint do cliente salvo com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao salvar checkpoint do cliente em {filepath}: {e}", exc_info=True)
        # tenta remover o temporario se a escrita falhou
        if os.path.exists(tmp_filepath):
            try:
                os.remove(tmp_filepath)
            except OSError:
                pass  # Ignora erro na remoçao do temp


def load_client_checkpoint(history_deque):
    global client_lamport_clock, CLIENT_ID; filename = f"{CLIENT_CHECKPOINT_FILENAME_PREFIX}{CLIENT_ID}.json"; filepath = os.path.join(CLIENT_CHECKPOINT_DIR, filename) if CLIENT_CHECKPOINT_DIR else filename
    if not os.path.exists(filepath): logger.info(f"Checkpoint do cliente nao encontrado: {filepath}"); return False
    logger.info(f"Carregando checkpoint do cliente de {filepath}...")
    try:
        with open(filepath, 'r') as f: loaded_state = json.load(f);
        with client_lock: client_lamport_clock = loaded_state.get('client_lamport_clock', 0)
        loaded_history = loaded_state.get('data_history', []); history_deque.clear(); history_deque.extend(loaded_history); logger.info(f"Estado cliente restaurado (LC={client_lamport_clock}, Historico={len(history_deque)}).")
        print("\n*** DADOS RESTAURADOS DO CHECKPOINT ***")
        if not history_deque: print("  (Nenhum historico)")
        else:
            for i, cycle_data in enumerate(history_deque): cycle_ts = cycle_data.get('cycle_timestamp', 0); cycle_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cycle_ts)) if cycle_ts else "N/A"; print(f" Ciclo #{i+1} ({cycle_time_str}):")
            sensor_readings = cycle_data.get('sensor_readings', {})
            if not sensor_readings: print("    (Sem leituras)")
            else:
                for sensor_id, data in sensor_readings.items(): phys_ts = data.get('timestamp', 0); phys_time_str = time.strftime('%H:%M:%S', time.localtime(phys_ts)) if phys_ts else 'N/A'; print(f"    {sensor_id}: T={data.get('temperatura','N/A'):.1f}, U={data.get('umidade','N/A'):.1f}, P={data.get('pressao','N/A'):.1f} (LC_S: {data.get('lamport_timestamp','N/A')}, TS_F: {phys_time_str})")
        print("----------------------------------------\n")
        logger.debug(f"Historico restaurado: {list(history_deque)}"); return True
    except (json.JSONDecodeError, KeyError, Exception) as e: logger.error(f"Erro ao carregar o checkpoint {filepath}: {e}", exc_info=True);
    with client_lock: client_lamport_clock = 0; history_deque.clear(); return False


# Main Loop do Cliente
if __name__ == "__main__":
    # obtem ou gera o ID persistente
    CLIENT_ID = get_persistent_client_id()
    if not CLIENT_ID: sys.exit("ERRO FATAL: Nao foi possivel obter/gerar ID de cliente.")

    # carrega a chave publica do servidor antes de iniciar threads
    server_public_key = load_server_public_key()
    if not server_public_key:
        logger.critical(f"Nao foi possivel carregar a chave publica do servidor ({SERVER_PUBLIC_KEY_FILE}). Encerrando...")
        sys.exit(1)

    threading.current_thread().name = "MainThread"
    logger.info(f"Cliente CL [ID: {CLIENT_ID}] iniciado.")
    logger.info(f"Modo Verbose Inicial: {'ATIVADO' if verbose_mode else 'DESATIVADO'}")

    # carrega o checkpoint
    load_client_checkpoint(historical_data)

    # inicia thread de interacao do usuario
    listener = threading.Thread(target=multicast_listener_thread, daemon=True, name="MulticastListener")
    listener.start()
    input_thread = threading.Thread(target=user_input_thread, daemon=True, name="UserInputThread")
    input_thread.start()

    logger.info(f"Aguardando descoberta inicial...")
    time.sleep(7)  # espera inicial

    polling_cycle_count = 0
    try:
        while not stop_event.is_set():
            polling_cycle_count += 1
            current_lc = update_client_clock()
            logger.debug(f"[ Ciclo Polling #{polling_cycle_count} | Cliente LC: {current_lc} ]")
            prune_stale_sensors()
            current_active_sensors = get_discovered_sensors(include_failed=False)
            results_this_cycle = {'cycle_timestamp': time.time(), 'sensor_readings': {}}

            if not current_active_sensors: logger.warning("Nenhum sensor ativo.")
            else:
                 active_ids = list(current_active_sensors.keys()); coord_id_view = "N/A";
                 with discovery_lock: coord_id_view = current_coordinator_id_client or "Nenhum"
                 logger.debug(f"Sensores ativos: {active_ids} | Coordenador: {coord_id_view}")
                 # inicia o snapshot
                 if polling_cycle_count % SNAPSHOT_INTERVAL_CYCLES == 0:
                     initiate_chandy_lamport_snapshot() # TODO: Securize this?
                     current_lc = update_client_clock(); logger.debug(f"*** Retornando ao polling (LC: {current_lc}) ***")

                 # coleta dados usando get_sensor_data_grpc seguro
                 logger.info("Iniciando coleta de dados dos sensores ativos...")
                 successful_reads = 0
                 for sensor_id, sensor_info in current_active_sensors.items():
                     # tenta obter sessao e dados descriptografados
                     sensor_data_dict = get_sensor_data_grpc(sensor_id, sensor_info['host'], sensor_info['port'])
                     if sensor_data_dict is not None:
                         successful_reads += 1
                         results_this_cycle['sensor_readings'][sensor_id] = sensor_data_dict  # armazena dict descriptografado
                     if stop_event.is_set(): break
                     sys.stdout.flush(); time.sleep(0.1)
                 if stop_event.is_set(): break
                 logger.info(f"Coleta concluida ({successful_reads}/{len(current_active_sensors)} ativos responderam).")
                 if results_this_cycle['sensor_readings']: historical_data.append(results_this_cycle); logger.debug(f"Resultados adicionados ao historico ({len(historical_data)}).")

            # salva checkpoint do cliente
            save_client_checkpoint(client_lamport_clock, historical_data)

            logger.debug(f"*** [ Ciclo Polling #{polling_cycle_count} Concluido | Cliente LC: {client_lamport_clock} ] ***")
            logger.debug(f"Aguardando {POLL_INTERVAL} segundos...")
            stop_event.wait(POLL_INTERVAL)

    except KeyboardInterrupt: logger.info("\nCtrl+C recebido. Sinalizando para sair..."); stop_event.set()
    finally: logger.info("Cliente Encerrado."); time.sleep(0.5)