# alice_protocol4.py
import socket, argparse, logging, json, time, base64


# ============== 수론 유틸 ==============
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def prime_factors(n: int):
    fac = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            fac.add(d)
            n //= d
        d += 1
    if n > 1:
        fac.add(n)
    return fac


def is_generator(g: int, p: int) -> bool:
    if not is_prime(p):
        return False
    order = p - 1
    for q in prime_factors(order):
        if pow(g, order // q, p) == 1:
            return False
    return True


# ============== 전송/수신 ==============
def send_json(sock, obj):
    # CRLF 사용(호환성 ↑)
    sock.sendall((json.dumps(obj) + "\r\n").encode("utf-8"))


def recv_json_lenient(sock, total_timeout=30.0, max_bytes=1_000_000):
    """
    - 개행 유무/배너/조각난 JSON 모두 커버
    - total_timeout 동안 반복 수신
    """
    deadline = time.time() + total_timeout
    buf = b""
    braces = 0
    started = False
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                if not buf.strip():
                    return None
                t = buf.decode("utf-8", "ignore").strip()
                i, j = t.find("{"), t.rfind("}")
                if i != -1 and j != -1 and j > i:
                    return json.loads(t[i : j + 1])
                return None

            buf += chunk
            if len(buf) > max_bytes:
                raise RuntimeError("response too large")

            # 줄 단위 먼저
            while b"\n" in buf or b"\r\n" in buf:
                line, sep, rest = buf.partition(b"\n")
                if sep == b"":
                    line, sep, rest = buf.partition(b"\r\n")
                buf = rest
                t = line.decode("utf-8", "ignore").strip()
                if not t:
                    continue
                i, j = t.find("{"), t.rfind("}")
                if i != -1 and j != -1 and j > i:
                    return json.loads(t[i : j + 1])

            # 개행 없이 중괄호 균형으로 완결 감지
            for bch in chunk:
                if bch == ord("{"):
                    braces += 1
                    started = True
                elif bch == ord("}"):
                    braces -= 1
                    if started and braces == 0:
                        t = buf.decode("utf-8", "ignore")
                        i, j = t.find("{"), t.rfind("}")
                        if i != -1 and j != -1 and j > i:
                            return json.loads(t[i : j + 1])

        except socket.timeout:
            continue
    return None


# ============== 메시지 정규화/필터 ==============
def _normalize_params_key(msg: dict):
    """
    'parameter', 'parameters', 'Parameter', 'Params' 등 허용.
    최상위에 p,g가 있으면 그것도 허용.
    """
    if not isinstance(msg, dict):
        return None
    for k in ["parameter", "parameters", "Parameter", "Parameters", "params", "Params"]:
        if k in msg and isinstance(msg[k], dict):
            return msg[k]
    if "p" in msg and "g" in msg:
        return {"p": msg["p"], "g": msg["g"]}
    return None


def is_dh_params(msg):
    try:
        if not (msg.get("opcode") == 1 and str(msg.get("type", "")).upper() == "DH"):
            return False
        if "public" not in msg:
            return False
        params = _normalize_params_key(msg)
        if not params:
            return False
        return "p" in params and "g" in params
    except Exception:
        return False


def read_until(sock, want_fn, total_timeout):
    """원하는 형태의 JSON이 올 때까지 계속 읽기"""
    deadline = time.time() + total_timeout
    while time.time() < deadline:
        m = recv_json_lenient(
            sock, total_timeout=min(5.0, max(0.5, deadline - time.time()))
        )
        if not m:
            continue
        logging.info(f"[Alice] recv: {m}")
        if isinstance(m, dict) and m.get("opcode") == 3:
            raise RuntimeError(f"Bob error: {m.get('error')}")
        if want_fn(m):
            return m
    raise TimeoutError("did not receive expected message in time")


# ============== 공개키(Base64/정수) 파서 ==============
def parse_public_any(v):
    """
    공개키가 int, 숫자 문자열, Base64(빅엔디언 바이트) 중 무엇이든 int로 변환.
    """
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        # 숫자 문자열?
        try:
            return int(v)
        except ValueError:
            pass
        # Base64?
        try:
            raw = base64.b64decode(v, validate=True)
            return int.from_bytes(raw if raw else b"\x00", "big")
        except Exception:
            pass
    raise ValueError("unsupported public key format")


# ============== 메인 ==============
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", required=True, type=int)
    ap.add_argument("-l", "--log", default="INFO")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(10.0)
        s.connect((args.addr, args.port))
        logging.info(f"[Alice] connected to {args.addr}:{args.port}")

        # 서버-먼저 전송 케이스 먼저 한 번 시도
        first = recv_json_lenient(s, total_timeout=3.0)
        if first and is_dh_params(first):
            resp1 = first
        else:
            # 표준 시작 요청
            send_json(s, {"opcode": 0, "type": "DH"})
            # 정확한 DH 파라미터가 올 때까지 필터링
            resp1 = read_until(s, is_dh_params, args.timeout)

        # ----- 파싱 (키명 유연) -----
        params = _normalize_params_key(resp1)
        p = int(params["p"])
        g = int(params["g"])
        B = parse_public_any(resp1["public"])
        logging.info(f"[Alice] DH params <- p={p}, g={g}, B={B}")

        # ----- Protocol IV-I / IV-II 요구: 검증 실패 시 에러 응답 후 즉시 종료 -----
        if not (400 <= p <= 500):
            send_json(s, {"opcode": 3, "error": "incorrect prime range"})
            logging.info("[Alice] sent error: incorrect prime range")
            return
        if not is_prime(p):
            send_json(s, {"opcode": 3, "error": "incorrect prime number"})
            logging.info("[Alice] sent error: incorrect prime number")
            return
        if not (2 <= g <= p - 2) or not is_generator(g, p):
            send_json(s, {"opcode": 3, "error": "incorrect generator"})
            logging.info("[Alice] sent error: incorrect generator")
            return

        # ※ Protocol IV는 '에러 시 종료' 시나리오 검증용.
        # 정상 케이스가 오더라도 여기서는 추가 동작 없이 종료해도 무방.
        # (과제에서 정상 흐름까지 요구한다면, 프로토콜3과 동일하게 DH→AES 단계 이어서 구현 가능)
        logging.info(
            "[Alice] parameters look valid (Protocol IV requires only error handling)."
        )

    except Exception as e:
        logging.exception(f"[Alice] error: {e}")
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    main()
