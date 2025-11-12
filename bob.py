# bob_protocol4.py
import socket, argparse, logging, json, random

# ===== 전송/수신 =====
def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\r\n").encode("utf-8"))

def recv_json(sock, timeout=10.0):
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            if buf:
                return json.loads(buf.decode("utf-8", "ignore"))
            return None
        buf += chunk
        if b"\n" in buf or b"\r\n" in buf:
            line = buf.splitlines()[0]
            try:
                return json.loads(line.decode("utf-8"))
            except Exception:
                continue

# ===== DH 파라미터 생성 =====
def generate_dh_params():
    """
    p, g, B를 간단히 생성 (테스트용)
    Protocol IV에서는 일부러 잘못된 값도 내보내 테스트할 수 있음.
    """
    # 400~500 사이의 임의 p 선택
    p = random.randint(400, 500)
    g = random.randint(2, p - 2)
    a = random.randint(2, p - 2)  # Bob의 비밀키
    B = pow(g, a, p)
    return p, g, B

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", required=True, type=int)
    ap.add_argument("-l", "--log", default="INFO")
    ap.add_argument("--mode", choices=["valid", "invalid"], default="invalid",
                    help="valid=올바른 p,g / invalid=일부러 잘못된 값")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", args.port))
    server.listen(1)
    logging.info(f"[Bob] Listening on port {args.port}")

    conn, addr = server.accept()
    logging.info(f"[Bob] Connected by {addr}")

    try:
        # Alice 요청 대기
        req = recv_json(conn)
        logging.info(f"[Bob] Received: {req}")

        if not req or req.get("opcode") != 0 or req.get("type", "").upper() != "DH":
            send_json(conn, {"opcode": 3, "error": "invalid opcode or type"})
            logging.info("[Bob] sent error: invalid request")
            return

        # Diffie-Hellman 파라미터 생성
        p, g, B = generate_dh_params()

        # invalid 모드에서는 일부러 잘못된 값(예: p를 소수가 아닌 수) 전송
        if args.mode == "invalid":
            if p % 2 == 0:  # 짝수라 소수 아님
                bad_p = p
            else:
                bad_p = p + 1  # 일부러 소수 아님으로 변경
            p = bad_p

        msg = {
            "opcode": 1,
            "type": "DH",
            "public": B,
            "parameter": {"p": p, "g": g}
        }
        send_json(conn, msg)
        logging.info(f"[Bob] Sent DH parameters p={p}, g={g}, B={B}")

        # Alice 응답 (error or success)
        resp = recv_json(conn, timeout=5.0)
        if resp:
            logging.info(f"[Bob] Got from Alice: {resp}")
            if resp.get("opcode") == 3:
                logging.info(f"[Bob] Alice rejected parameters: {resp.get('error')}")
            else:
                logging.info("[Bob] Alice accepted parameters.")
        else:
            logging.info("[Bob] No response from Alice (timeout)")

    except Exception as e:
        logging.exception(f"[Bob] error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        server.close()
        logging.info("[Bob] connection closed")

if __name__ == "__main__":
    main()
