import csv, io, ipaddress
from .constants import MAX_TARGETS

def _expand(token):
    try:
        if "/" in token:
            net=ipaddress.ip_network(token, strict=False)
            if not isinstance(net, ipaddress.IPv4Network): raise ValueError("IPv4 only")
            return list(net.hosts()) if net.prefixlen < 31 else list(net)
        if "-" in token:
            left,right=[x.strip() for x in token.split("-",1)]
            a=ipaddress.IPv4Address(left)
            if "." not in right: b=ipaddress.IPv4Address(".".join(left.split(".")[:3]+[right]))
            else: b=ipaddress.IPv4Address(right)
            if int(b)<int(a): raise ValueError("range end before start")
            return [ipaddress.IPv4Address(i) for i in range(int(a),int(b)+1)]
        return [ipaddress.IPv4Address(token)]
    except ValueError as exc: raise ValueError(f"توکن نامعتبر: {token} ({exc})") from exc

def parse_targets(text, max_targets=MAX_TARGETS):
    if not isinstance(text,str) or not text.strip(): raise ValueError("فهرست هدف‌ها خالی است")
    tokens=[c.strip() for row in csv.reader(io.StringIO(text)) for c in row if c.strip()]
    result=[]; seen=set()
    for token in tokens:
        for a in _expand(token):
            value=str(a)
            if value not in seen:
                seen.add(value); result.append(value)
                if len(result)>max_targets: raise ValueError(f"تعداد هدف‌ها از سقف {max_targets} بیشتر است")
    return result
