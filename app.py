"""
App: SQL Server Query Anonymizer / Deanonymizer
Author: ChatGPT

What it does
------------
- Takes a SQL Server (T-SQL) query and anonymizes identifiers (databases, schemas, tables, columns).
- Produces a reversible mapping so you can paste GPT-modified SQL back in and de-anonymize it to original names.

How to run
----------
1) Create a virtual env and install deps:
   pip install streamlit sqlglot

2) Start the app:
   streamlit run app.py

Notes
-----
- Parsing/rewriting done with sqlglot (dialect: T-SQL).
- We only rewrite Table & Column identifiers to avoid touching keywords, variables, parameters.
- Mapping is kept in-memory (session) and can be exported/imported as JSON for reuse.
- If GPT adds brand-new identifiers that weren't anonymized originally, they won't be de-anonymized automatically (the app will leave them unchanged and warn you).
"""

import json
import uuid
from typing import Dict, Tuple

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
# SQL rewrite helpers using sqlglot
# ----------------------------------

DIALECT = "tsql"

def anonymize_sql(sql: str, nm: NameMapper) -> Tuple[str, NameMapper]:
    """Return anonymized SQL and the (updated) NameMapper."""
    try:
        tree = parse_one(sql, read=DIALECT)
    except Exception as e:
        raise ValueError(f"Erreur d'analyse SQL: {e}")

    def _transform(node):
        # Rewrite database.schema.table pieces on Table nodes
        if isinstance(node, exp.Table):
            # catalog -> database, db -> schema, this -> table (sqlglot naming)
            if node.catalog:  # database
                new_db = nm.map("database", node.catalog)
                node.set("catalog", exp.to_identifier(new_db))
            if node.db:       # schema
                new_schema = nm.map("schema", node.db)
                node.set("db", exp.to_identifier(new_schema))
            if node.this:     # table
                new_table = nm.map("table", node.name)
                node.set("this", exp.to_identifier(new_table))
            return node

        # Columns optionally have a table qualifier
        if isinstance(node, exp.Column):
            if node.table:  # qualifier (table alias or table name). We only rewrite if it matches a real table name mapping.
                qual = node.table
                # If the qualifier is an anonymized or original table name we keep it consistent.
                mapped = nm.mapping["table"].get(qual)
                if mapped:
                    node.set("table", exp.to_identifier(mapped))
                else:
                    # It's possibly an alias; don't change it.
                    pass
            if node.this:
                new_col = nm.map("column", node.name)
                node.set("this", exp.to_identifier(new_col))
            return node

        return node

    new_tree = tree.transform(_transform)
    return new_tree.sql(dialect=DIALECT), nm


def deanonymize_sql(sql: str, nm: NameMapper) -> str:
    try:
        tree = parse_one(sql, read=DIALECT)
    except Exception as e:
        raise ValueError(f"Erreur d'analyse SQL: {e}")

    def _transform(node):
        if isinstance(node, exp.Table):
            if node.catalog:  # database
                orig_db = nm.unmap("database", node.catalog)
                node.set("catalog", exp.to_identifier(orig_db))
            if node.db:       # schema
                orig_schema = nm.unmap("schema", node.db)
                node.set("db", exp.to_identifier(orig_schema))
            if node.this:     # table
                orig_table = nm.unmap("table", node.name)
                node.set("this", exp.to_identifier(orig_table))
            return node

        if isinstance(node, exp.Column):
            if node.table:
                qual = node.table
                # If qualifier is anonymized table, revert to original; otherwise leave alias as-is.
                orig_qual = nm.unmap("table", qual)
                if orig_qual != qual:
                    node.set("table", exp.to_identifier(orig_qual))
            if node.this:
                orig_col = nm.unmap("column", node.name)
                node.set("this", exp.to_identifier(orig_col))
            return node

        return node

    new_tree = tree.transform(_transform)
    return new_tree.sql(dialect=DIALECT)

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

left, right = st.columns(2)

with left:
    st.subheader("1) Anonymiser")
    src_sql = st.text_area(
        "Collez votre requête SQL d'origine (T-SQL)",
        height=250,
        placeholder="SELECT p.PersonID, p.LastName FROM AdventureWorks2019.Person.Person AS p WHERE p.LastName = 'Smith';",
    )
    if st.button("Anonymiser", type="primary"):
        if not src_sql.strip():
            st.warning("Veuillez coller une requête SQL.")
        else:
            try:
                anonym_sql, _ = anonymize_sql(src_sql, st.session_state.name_mapper)
                st.text_area("Requête anonymisée", value=anonym_sql, height=250)
                st.info("Copiez ce SQL anonymisé et utilisez-le dans votre prompt ChatGPT. Gardez le mapping (export) pour pouvoir rétablir les noms ensuite.")
            except Exception as e:
                st.error(str(e))

with right:
    st.subheader("2) Déanonymiser")
    mod_sql = st.text_area(
        "Collez la requête modifiée (toujours avec les noms anonymes)",
        height=250,
        placeholder="-- Collez ici le SQL renvoyé par ChatGPT, basé sur les noms anonymes (DB_*, SC_*, T_*, C_*).",
    )
    if st.button("Déanonymiser"):
        if not mod_sql.strip():
            st.warning("Veuillez coller une requête SQL.")
        else:
            try:
                deanon_sql = deanonymize_sql(mod_sql, st.session_state.name_mapper)
                st.text_area("Requête rétablie (noms d'origine)", value=deanon_sql, height=250)
                st.info("Vérifiez le résultat. Les identifiants inconnus (non présents dans le mapping) sont laissés tels quels.")
            except Exception as e:
                st.error(str(e))

st.divider()

st.markdown(
    """
### ✅ Conseils d'utilisation
- Exportez le mapping JSON après l'anonymisation si vous comptez retravailler la requête plus tard ou sur une autre machine.
- Si ChatGPT ajoute de nouvelles tables/colonnes, elles n'existeront pas dans le mapping et ne seront pas dé-anonymisées automatiquement (vous pourrez compléter le mapping à la main si besoin).
- Le code évite de toucher aux alias (ex. `p`, `t1`) pour limiter les effets de bord.
- Les noms entre crochets [ ] ou guillemets sont gérés via l'AST de sqlglot.

### 🧪 Exemple rapide
**Entrée :** `SELECT p.PersonID, p.LastName FROM AdventureWorks2019.Person.Person AS p WHERE p.LastName = 'Smith';`

**Sortie anonymisée (exemple) :** `SELECT p.C_1, p.C_2 FROM DB_1.SC_1.T_1 AS p WHERE p.C_2 = 'Smith';`

**Dé-anonymisation :** redevient la requête d'origine.
"""
)
