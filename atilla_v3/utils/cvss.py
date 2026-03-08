from core.models import Severity, InjectionContext, CvssScore

_SCOPE_CTX = {InjectionContext.HTML_TEXT, InjectionContext.HTML_ATTRIBUTE_DQ,
              InjectionContext.HTML_ATTRIBUTE_SQ}

def compute_cvss(severity: Severity, context: InjectionContext) -> CvssScore:
    sc = context in _SCOPE_CTX
    AV, AC, PR, UI = 0.85, 0.77, 0.85, 0.62
    if severity == Severity.CRITICAL: C, I, A = 0.56, 0.56, 0.56
    elif severity == Severity.HIGH:   C, I, A = 0.56, 0.56, 0.22
    elif severity == Severity.MEDIUM: C, I, A = 0.22, 0.56, 0.00
    else:                             C, I, A = 0.22, 0.22, 0.00
    iss     = 1 - ((1-C)*(1-I)*(1-A))
    exploit = 8.22 * AV * AC * PR * UI
    if sc:
        impact = 7.52*(iss-0.029) - 3.25*((iss-0.02)**15)
        base   = min(10.0, 1.08*(impact+exploit))
    else:
        impact = 6.42*iss
        base   = min(10.0, impact+exploit) if impact > 0 else 0.0
    score  = round(base, 1)
    rating = "CRITICAL" if score>=9 else "HIGH" if score>=7 else "MEDIUM" if score>=4 else "LOW" if score>0 else "NONE"
    vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:{'C' if sc else 'U'}/C:{'H' if C==0.56 else 'L'}/I:{'H' if I==0.56 else 'L'}/A:{'H' if A==0.56 else 'N'}"
    return CvssScore(vector=vector, base_score=score, rating=rating)
