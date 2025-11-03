#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Calcola il CVSS Base Score partendo da una vector string.
- Supporto completo per CVSS v3.1 (formule ufficiali FIRST).
- Supporto per CVSS v4.0 tramite il pacchetto 'cvss' (che include il lookup ufficiale).
  Se non presente, viene mostrato come installarlo.

Riferimenti:
- CVSS v3.1 formule e pesi: FIRST "CVSS v3.1 Specification" (sez. 7) .
- CVSS v4.0: FIRST "CVSS v4.0 Specification" (sez. 8, lookup ufficiale in cvss_lookup.js).

Uso:
  python cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"
  python cvss_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
"""

import math
import sys
import re

# -----------------------------
# Parser generico della vector
# -----------------------------
def parse_vector(vector: str):
    vector = vector.strip()
    if not vector.startswith("CVSS:"):
        raise ValueError("La stringa deve iniziare con 'CVSS:'")

    # estrae versione
    m = re.match(r"^CVSS:(?P<ver>[0-9.]+)\/", vector)
    if not m:
        raise ValueError("Versione CVSS non trovata nella stringa")
    ver = m.group("ver")

    # mappa metrica -> valore abbreviato (es. {'AV':'N', 'AC':'L', ...})
    parts = vector.split("/")[1:]  # skip "CVSS:x.y"
    metrics = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        metrics[k] = v
    return ver, metrics


# -----------------------------
# CVSS v3.1 - implementazione
# (Base Score)
# -----------------------------
# Pesi ufficiali (FIRST v3.1 spec)
V31_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
V31_AC = {"L": 0.77, "H": 0.44}
# PR dipende da Scope
V31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
V31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
V31_UI = {"N": 0.85, "R": 0.62}
V31_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

def roundup_1_dec(x: float) -> float:
    # "Roundup" come da spec: arrotonda verso l’alto alla prima cifra decimale
    return math.ceil(x * 10.0) / 10.0

def cvss31_base(metrics: dict) -> float:
    # Metriche obbligatorie: AV, AC, PR, UI, S, C, I, A
    try:
        av = V31_AV[metrics["AV"]]
        ac = V31_AC[metrics["AC"]]
        scope = metrics["S"]  # 'U' or 'C'
        pr = (V31_PR_C if scope == "C" else V31_PR_U)[metrics["PR"]]
        ui = V31_UI[metrics["UI"]]
        c = V31_CIA[metrics["C"]]
        i = V31_CIA[metrics["I"]]
        a = V31_CIA[metrics["A"]]
    except KeyError as e:
        raise ValueError(f"Valore metrica non valido o mancante (v3.1): {e}")

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:  # S:C
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    else:
        if scope == "U":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)

    return roundup_1_dec(base)


# -----------------------------
# CVSS v4.0 - via libreria 'cvss'
# -----------------------------
def cvss40_base(metrics: dict) -> float:
    """
    Per CVSS v4.0 il Base Score è definito tramite MacroVectors + lookup.
    Usiamo il pacchetto 'cvss' che incorpora i dati ufficiali.

    pip install cvss
    """
    try:
        from cvss import CVSS4  # pacchetto: https://pypi.org/project/cvss/
    except Exception as e:
        raise RuntimeError(
            "Per calcolare CVSS 4.0 installa il pacchetto 'cvss':\n"
            "    pip install cvss\n"
            f"Dettaglio errore import: {e}"
        )

    # Ricostruisce la vector string v4.0 nell’ordine richiesto dalla spec
    # Ordine (Base): AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA
    required = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
    missing = [m for m in required if m not in metrics]
    if missing:
        raise ValueError(f"Mancano metriche obbligatorie per v4.0: {', '.join(missing)}")

    vector = (
        "CVSS:4.0/"
        + "/".join([f"{k}:{metrics[k]}" for k in required])
    )

    # La libreria calcola il Base Score (CVSS-B)
    score = CVSS4(vector).base_score
    # È già arrotondato ad 1 decimale
    return score


# -----------------------------
# Entrypoint
# -----------------------------
def compute_from_vector(vector: str) -> float:
    ver, metrics = parse_vector(vector)
    if ver.startswith("3.1"):
        return cvss31_base(metrics)
    elif ver.startswith("4"):
        return cvss40_base(metrics)
    else:
        raise ValueError(f"Versione CVSS non supportata: {ver}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python cvss_calc.py \"CVSS:<ver>/...\"")
        print("Esempio: python cvss_calc.py \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N\"")
        sys.exit(1)

    vector = sys.argv[1]
    try:
        score = compute_from_vector(vector)
        print(f"Vector: {vector}")
        print(f"Base Score: {score}")
    except Exception as e:
        print(f"Errore: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
