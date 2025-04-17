import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

MCAST_GRP = '224.1.1.1' # endereço multicast
MCAST_PORT = 5007      # porta para comunicacao multicast
MCAST_TTL = 2          # TTL >1 - pode cruzar roteadores

# funçao para obter o IP local principal
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # conecta-se ao DNS da google para descobrir qual interface sera usada
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
    except OSError as e:
        logging.warning(f"Nao foi possivel determinar o IP local automaticamente via socket.connect: {e}. Usando fallback '127.0.0.1'.")
        # metodo alternativo
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            if ip_address == '127.0.0.1':  # se ainda for localhost, tenta getaddrinfo
                 addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
                 ip_address = addr_info[0][4][0] # pega o primeiro endereço IPv4
        except Exception as inner_e:
             logging.error(f"Falha no metodo alternativo de detecçao de IP: {inner_e}. Usando '127.0.0.1'.")
             ip_address = '127.0.0.1' # fallback final
    except Exception as e:
        logging.error(f"Erro inesperado ao obter IP local: {e}. Usando '127.0.0.1'.")
        ip_address = '127.0.0.1'  # fallback final
    finally:
        s.close()
    return ip_address


LOCAL_IP = get_local_ip()   # armazena o ip local detectado na constante

if __name__ == "__main__":
    print(f"Endereço Multicast: {MCAST_GRP}:{MCAST_PORT}")
    print(f"TTL Multicast: {MCAST_TTL}")
    print(f"IP Local Detectado: {LOCAL_IP}")
