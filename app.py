# app.py
"""
App: SQL Server Query Anonymizer / Deanonymizer
Author: ChatGPT (fixes: comments anonymization, robust USE support, bracket preservation)

Ce que fait l'app
-----------------
- Anonymise/déanonymise les identifiants T-SQL (bases, schémas, tables, colonnes).
- Mapping réversible en mémoire (session Streamlit), import/export JSON.
- Anonymisation aussi dans les commentaires (-- ... , /* ... */).
- Les chaînes de caractères ne sont pas modifiées.
- La commande USE est supportée, même sans point-virgule juste avant un SELECT.
- Les crochets [ ... ] sont préservés (si présents dans le texte d’origine).

Prérequis
---------
pip install streamlit sqlglot
streamlit run app.py
"""

import json
import re
import uuid
from typing import Dict, Tuple
import html as _html
import streamlit.components.v1 as components

import streamlit as st
from sqlglot import parse_one, exp

# -------------------------------
# Utilities: stable name mapping
# -------------------------------

DEFAULT_PREFIXES = {
    "database": "DB_",
    "schema": "SC_",
    "table": "T_",
    "column": "C_",
}

SQL_START_RE = re.compile(
    r"^\s*(SELECT|WITH|UPDATE|INSERT|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|EXEC|DECLARE|BEGIN|USE)\b",
    re.IGNORECASE
)

def _first_non_comment_code_line(text: str) -> Tuple[int, str]:
    """
    Retourne (index, contenu) de la première ligne non vide qui n'est pas un commentaire SQL.
    Si rien trouvé, retourne (-1, "").
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        if s.startswith("--") or s.startswith("/*"):
            # ligne de commentaire SQL -> on ignore
            continue
        return i, line
    return -1, ""

def _find_first_sql_statement_start(text: str) -> int:
    """
    Renvoie l'index de ligne de la première ligne qui ressemble à un début d'instruction SQL.
    Sinon -1.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if SQL_START_RE.search(line):
            return i
    return -1

def _new_session_id() -> str:
    return str(uuid.uuid4())

class NameMapper:
    """Keeps forward and reverse mappings per identifier type."""
    def __init__(self, mapping: Dict = None, prefixes: Dict[str, str] = None):
        self.prefixes = prefixes or DEFAULT_PREFIXES.copy()
        self.mapping = mapping or {
            "database": {},
            "schema": {},
            "table": {},
            "column": {},
        }
        # build reverse
        self.inverse = {k: {v: k_ for k_, v in d.items()} for k, d in self.mapping.items()}
        # counters for new names
        self.counters = {k: (len(d) + 1) for k, d in self.mapping.items()}

    def _gen(self, kind: str) -> str:
        name = f"{self.prefixes[kind]}{self.counters[kind]}"
        self.counters[kind] += 1
        return name

    def map(self, kind: str, original: str) -> str:
        if not original:
            return original
        d = self.mapping[kind]
        if original in d:
            return d[original]
        alias = self._gen(kind)
        d[original] = alias
        self.inverse[kind][alias] = original
        return alias

    def unmap(self, kind: str, alias: str) -> str:
        return self.inverse.get(kind, {}).get(alias, alias)

    def to_json(self) -> str:
        return json.dumps({
            "prefixes": self.prefixes,
            "mapping": self.mapping,
        }, ensure_ascii=False, indent=2)

    @staticmethod
    def from_json(s: str) -> "NameMapper":
        obj = json.loads(s)
        return NameMapper(mapping=obj.get("mapping"), prefixes=obj.get("prefixes"))

# ----------------------------------
# Mapping extraction using sqlglot
# ----------------------------------

DIALECT = "tsql"

# --- NEW: détection USE (hors chaînes/commentaires) ---
SEGMENT_RE = re.compile(
    r"(--[^\n]*\n?|/\*.*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")",
    flags=re.DOTALL | re.MULTILINE,
)

USE_DB_RE = re.compile(
    r"(?i)\bUSE\s+(?:\[\s*(?P<bracket>[^\]\r\n;]+)\s*\]|(?P<plain>[A-Za-z0-9_.$]+))"
)

def _is_comment(segment: str) -> bool:
    return segment.startswith("--") or segment.startswith("/*")

def _is_string(segment: str) -> bool:
    return (segment.startswith("'") and segment.endswith("'")) or (segment.startswith('"') and segment.endswith('"'))

def _scan_code_segments(sql: str):
    """Itère sur les segments de code (hors chaînes/commentaires)."""
    last_idx = 0
    for m in SEGMENT_RE.finditer(sql):
        # code avant le segment protégé
        yield sql[last_idx:m.start()]
        # sauter le segment protégé
        last_idx = m.end()
    # suffixe
    yield sql[last_idx:]

def _map_use_databases(sql: str, nm: NameMapper) -> None:
    """
    Repère les instructions USE ... dans les segments de code et mappe le nom de base.
    Gère : USE db | USE [db] | USE db; | USE [db] ; | USE db SELECT ...
    """
    for code in _scan_code_segments(sql):
        for m in USE_DB_RE.finditer(code):
            name = (m.group("bracket") or m.group("plain") or "").strip()
            if name:
                nm.map("database", name)

def _strip_use_for_parse(sql: str) -> str:
    """
    Supprime les USE ... uniquement dans les segments de code, afin de permettre à sqlglot
    de parser correctement les SELECT qui suivent (même sans point-virgule).
    """
    out = []
    last_idx = 0
    for m in SEGMENT_RE.finditer(sql):
        code = sql[last_idx:m.start()]
        # supprimer USE ... (ne pas toucher aux chaînes/commentaires)
        code = USE_DB_RE.sub("", code)
        out.append(code)
        # conserver tel quel le segment protégé
        out.append(m.group(0))
        last_idx = m.end()
    tail = sql[last_idx:]
    tail = USE_DB_RE.sub("", tail)
    out.append(tail)
    return "".join(out)

def _extract_mapping(sql: str, nm: NameMapper) -> None:
    """
    Analyse l'AST pour recenser les identifiants et remplir le mapping,
    sans produire de SQL réécrit (on réécrit ensuite par remplacement textuel).

    NEW: on mappe aussi les bases des instructions USE, et on retire
    ces USE du texte envoyé au parseur pour éviter un échec d'analyse.
    """
    # 1) Mapper les bases rencontrées dans USE ...
    _map_use_databases(sql, nm)

    # 2) Retirer USE du texte à parser pour ne garder que les SELECT/UPDATE/...
    sql_for_parse = _strip_use_for_parse(sql)

    try:
        tree = parse_one(sql_for_parse, read=DIALECT)
    except Exception:
        # Si l’analyse échoue, on ignore : l’anonymisation par remplacement
        # s’appliquera quand même aux parties détectables (USE inclus).
        return

    def _visit(node):
        # Tables: database.schema.table
        if isinstance(node, exp.Table):
            if node.catalog:  # database
                nm.map("database", str(node.catalog))
            if node.db:       # schema
                nm.map("schema", str(node.db))
            if node.this:     # table
                nm.map("table", node.name)

        # Colonnes potentiellement qualifiées
        if isinstance(node, exp.Column):
            if node.this:
                nm.map("column", node.name)
        for child in node.args.values():
            if isinstance(child, list):
                for c in child:
                    if isinstance(c, exp.Expression):
                        _visit(c)
            elif isinstance(child, exp.Expression):
                _visit(child)

    _visit(tree)

# ----------------------------------
# Text rewriting helpers
# ----------------------------------

def _build_replacements_forward(nm: NameMapper):
    """
    Crée les paires (pattern -> repl) pour anonymiser.
    On remplace formes bracketées puis non bracketées, pour DB/SC/T/C.
    """
    repls = []

    def add_kind(kind: str):
        for original, alias in nm.mapping[kind].items():
            # [original] -> [alias] (IGNORECASE)
            repls.append((
                re.compile(rf"\[\s*{re.escape(original)}\s*\]", flags=re.IGNORECASE),
                f"[{alias}]"
            ))
            # non-bracketed en limites de mot (identifiants T-SQL: lettres, chiffres, _, $)
            repls.append((
                re.compile(rf"(?<![\w$]){re.escape(original)}(?![\w$])", flags=re.IGNORECASE),
                alias
            ))

    for k in ("database", "schema", "table", "column"):
        add_kind(k)

    return repls

def _build_replacements_reverse(nm: NameMapper):
    """
    Crée les paires (pattern -> repl) pour dé-anonymiser.
    Ici pas d'IGNORECASE, on connaît précisément les alias (DB_1, SC_1, ...).
    """
    repls = []

    def add_kind(kind: str):
        for alias, original in nm.inverse.get(kind, {}).items():
            # [alias] -> [original]
            repls.append((
                re.compile(rf"\[\s*{re.escape(alias)}\s*\]"),
                f"[{original}]"
            ))
            # non-bracketed
            repls.append((
                re.compile(rf"(?<![\w$]){re.escape(alias)}(?![\w$])"),
                original
            ))

    for k in ("database", "schema", "table", "column"):
        add_kind(k)

    return repls

def _apply_all(text: str, repls) -> str:
    for pattern, rep in repls:
        text = pattern.sub(rep, text)
    return text

def _apply_replacements_to_code_and_comments(sql: str, repls) -> str:
    """
    Applique les remplacements sur les segments 'code' ET 'commentaires',
    mais JAMAIS à l'intérieur des chaînes ('...' ou "...").
    """
    out = []
    last_idx = 0
    for m in SEGMENT_RE.finditer(sql):
        # segment avant (code)
        code = sql[last_idx:m.start()]
        out.append(_apply_all(code, repls))  # remplacements dans code

        seg = m.group(0)
        if _is_string(seg):
            # ne pas toucher
            out.append(seg)
        else:
            # commentaire -> on anonymise aussi
            out.append(_apply_all(seg, repls))
        last_idx = m.end()

    # suffixe (code)
    tail = sql[last_idx:]
    out.append(_apply_all(tail, repls))
    return "".join(out)

def copy_to_clipboard_button(text: str, key: str, label: str = "📋 Copier"):
    """Affiche un bouton qui copie 'text' dans le presse-papiers (côté navigateur)."""
    if not text:
        return
    # On échappe pour éviter de casser le HTML quand le SQL contient des caractères spéciaux
    escaped = _html.escape(text, quote=True)
    components.html(f"""
        <div>
          <textarea id="{key}_ta" style="position:absolute; left:-10000px; top:-10000px;">{escaped}</textarea>
          <button id="{key}_btn" style="margin-top:8px; padding:6px 10px; border-radius:8px; cursor:pointer;">
            {label}
          </button>
          <span id="{key}_msg" style="margin-left:8px; color:gray; font-size:0.9em;"></span>
        </div>
        <script>
          const btn = document.getElementById("{key}_btn");
          const ta  = document.getElementById("{key}_ta");
          const msg = document.getElementById("{key}_msg");
          if (btn && ta) {{
            btn.onclick = async () => {{
              try {{
                await navigator.clipboard.writeText(ta.value);
                msg.textContent = "Copié !";
                setTimeout(() => (msg.textContent = ""), 1500);
              }} catch(e) {{
                // Fallback: sélection + execCommand pour navigateurs anciens
                ta.style.display = "block";
                ta.select();
                document.execCommand("copy");
                ta.style.display = "none";
                msg.textContent = "Copié !";
                setTimeout(() => (msg.textContent = ""), 1500);
              }}
            }};
          }}
        </script>
    """, height=60)

def anonymize_sql(sql: str, nm: NameMapper):
    """
    1) Extrait/actualise le mapping via l'AST (sqlglot) – en retirant USE pour l'analyse.
    2) Applique le mapping par remplacement texte sur code + commentaires (hors chaînes).
    -> Gère USE et crochets naturellement.
    """
    _extract_mapping(sql, nm)
    forward = _build_replacements_forward(nm)
    new_sql = _apply_replacements_to_code_and_comments(sql, forward)
    return new_sql, nm

def deanonymize_sql(sql: str, nm: NameMapper) -> str:
    reverse = _build_replacements_reverse(nm)
    new_sql = _apply_replacements_to_code_and_comments(sql, reverse)
    return new_sql

# --------------
# Streamlit UI
# --------------

st.set_page_config(page_title="SQL Server – Anonymiseur", layout="wide")

if "session_id" not in st.session_state:
    st.session_state.session_id = _new_session_id()
if "name_mapper" not in st.session_state:
    st.session_state.name_mapper = NameMapper()

st.title("🔐 Anonymiseur de requêtes SQL Server (réversible)")

with st.expander("⚙️ Options"):
    cols = st.columns(4)
    for i, kind in enumerate(["database", "schema", "table", "column"]):
        new_prefix = cols[i].text_input(f"Préfixe {kind}", value=st.session_state.name_mapper.prefixes[kind])
        st.session_state.name_mapper.prefixes[kind] = new_prefix
    st.caption("Les préfixes servent à générer les noms anonymes : DB_1, SC_1, T_1, C_1, etc.")

    st.markdown("**📥 Importer un mapping** (JSON)")
    uploaded = st.file_uploader("Importer un fichier JSON de mapping", type=["json"], accept_multiple_files=False)
    if uploaded is not None:
        try:
            data = uploaded.read().decode("utf-8")
            st.session_state.name_mapper = NameMapper.from_json(data)
            st.success("Mapping importé avec succès.")
        except Exception as e:
            st.error(f"Impossible d'importer le mapping: {e}")

    st.markdown("**📤 Exporter le mapping courant**")
    mapping_json = st.session_state.name_mapper.to_json()
    st.download_button(
        label="Télécharger le mapping JSON",
        file_name="mapping_sql_anonymizer.json",
        mime="application/json",
        data=mapping_json,
    )
    auto_clean = st.checkbox("Nettoyer automatiquement le texte non-SQL avant la première instruction", value=True, help="Si coché, les lignes situées avant la première instruction SQL (SELECT/INSERT/...) seront ignorées.")

left, right = st.columns(2)

# ======= ANONYMISER =======
with left:
    st.subheader("1) Anonymiser")
    src_sql = st.text_area(
        "Collez votre requête SQL d'origine (T-SQL)",
        height=250,
        placeholder="-- Exemple\nUSE AdventureWorks2019\nSELECT TOP 10 * FROM [dbo].[Person]",
        key="src_sql_input",
    )

    if st.button("Anonymiser", type="primary", key="btn_anonymize"):
        if not src_sql.strip():
            st.warning("Veuillez coller une requête SQL.")
        else:
            # --- Contrôle d’entrée ---
            idx_first, first_line = _first_non_comment_code_line(src_sql)
            if idx_first != -1 and not SQL_START_RE.search(first_line):
                # L’utilisateur a du texte non SQL avant la requête
                start_stmt = _find_first_sql_statement_start(src_sql)
                if auto_clean and start_stmt != -1:
                    # Nettoyage automatique : on coupe tout avant la première ligne SQL
                    src_sql = "\n".join(src_sql.splitlines()[start_stmt:])
                    st.info("Du texte non SQL a été détecté avant la requête et a été ignoré automatiquement.")
                else:
                    st.error(
                        "Le texte avant la requête ne ressemble pas à du SQL.\n"
                        "Veuillez supprimer ce texte ou le transformer en commentaire SQL en le préfixant par `--`.\n\n"
                        f"Première ligne problématique : `{first_line.strip()}`"
                    )
                    st.stop()

            try:
                anonym_sql, _ = anonymize_sql(src_sql, st.session_state.name_mapper)
                st.session_state["anonym_sql"] = anonym_sql
                st.info("Copiez ce SQL anonymisé et utilisez-le dans votre prompt ChatGPT. Conservez le mapping (export) pour pouvoir rétablir les noms ensuite.")
            except Exception as e:
                st.error(str(e))

    anonym_result = st.session_state.get("anonym_sql", "")
    st.text_area("Requête anonymisée", value=anonym_result, height=250, key="anonym_result", disabled=not bool(anonym_result))
    if anonym_result:
        copy_to_clipboard_button(anonym_result, key="copy_anonym", label="📋 Copier la requête anonymisée")

# ======= DÉANONYMISER =======
with right:
    st.subheader("2) Déanonymiser")
    mod_sql = st.text_area(
        "Collez la requête modifiée (toujours avec les noms anonymes)",
        height=250,
        placeholder="-- Collez ici le SQL renvoyé par ChatGPT, basé sur DB_*, SC_*, T_*, C_*.",
        key="mod_sql_input",
    )

    if st.button("Déanonymiser", key="btn_deanonymize"):
        if not mod_sql.strip():
            st.warning("Veuillez coller une requête SQL.")
        else:
            # --- Contrôle d’entrée ---
            idx_first, first_line = _first_non_comment_code_line(mod_sql)
            if idx_first != -1 and not SQL_START_RE.search(first_line):
                start_stmt = _find_first_sql_statement_start(mod_sql)
                if auto_clean and start_stmt != -1:
                    mod_sql = "\n".join(mod_sql.splitlines()[start_stmt:])
                    st.info("Du texte non SQL a été détecté avant la requête et a été ignoré automatiquement.")
                else:
                    st.error(
                        "Le texte avant la requête ne ressemble pas à du SQL.\n"
                        "Veuillez supprimer ce texte ou le transformer en commentaire SQL en le préfixant par `--`.\n\n"
                        f"Première ligne problématique : `{first_line.strip()}`"
                    )
                    st.stop()

            try:
                deanon_sql = deanonymize_sql(mod_sql, st.session_state.name_mapper)
                st.session_state["deanon_sql"] = deanon_sql
                st.info("Vérifiez le résultat. Les identifiants inconnus (non présents dans le mapping) sont laissés tels quels.")
            except Exception as e:
                st.error(str(e))

    deanon_result = st.session_state.get("deanon_sql", "")
    st.text_area("Requête rétablie (noms d'origine)", value=deanon_result, height=250, key="deanonym_result", disabled=not bool(deanon_result))
    if deanon_result:
        copy_to_clipboard_button(deanon_result, key="copy_deanon", label="📋 Copier la requête dé-anonymisée")

st.divider()
