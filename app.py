import json, hashlib, copy
import pandas as pd
import streamlit as st
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

st.set_page_config(page_title="Food Traceability - Blockchain", layout="wide")

# ---------- load ----------
@st.cache_data
def load():
    chain = json.load(open("data/synthetic/ledger.json"))
    rej = pd.read_csv("data/synthetic/rejected_log.csv")
    return chain, rej

chain, rej = load()

def calc_hash(b):
    body = {k: b[k] for k in ["index", "timestamp", "data", "prev_hash"]}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

def verify(ch):
    for i, b in enumerate(ch):
        if b["hash"] != calc_hash(b):
            return False, i
        if i > 0 and b["prev_hash"] != ch[i - 1]["hash"]:
            return False, i
    return True, None

def check_sig(public_hex, signature_hex, message):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def msg_event(d, ts):
    body = {k: d[k] for k in ["event_id", "batch_id", "step", "handler_id", "location", "temperature_c"]}
    body["timestamp"] = str(ts)
    return json.dumps(body, sort_keys=True).encode()

def msg_register(d):
    body = {k: d[k] for k in ["batch_id", "product", "quantity_kg", "farm_id", "expiry_date"]}
    return json.dumps(body, sort_keys=True).encode()

def sig_status(ch):
    """Returns {block index: True/False} for every signed block, using public keys stored on the chain."""
    pub = {b["data"]["actor_id"]: b["data"]["public_key"] for b in ch if b["data"].get("type") == "PARTY"}
    out = {}
    for b in ch:
        d = b["data"]
        if d.get("type") == "REGISTER":
            who, m = d["farm_id"], msg_register(d)
        elif d.get("type") == "EVENT":
            who, m = d["handler_id"], msg_event(d, b["timestamp"])
        else:
            continue
        out[b["index"]] = who in pub and check_sig(pub[who], d["signature"], m)
    return out

def sigs_ok(ch):
    st_ = sig_status(ch)
    bad = [i for i, v in st_.items() if not v]
    return (len(bad) == 0), (bad[0] if bad else None)

def rebuild_hashes(ch):
    for i, b in enumerate(ch):
        b["prev_hash"] = ch[i - 1]["hash"] if i else "0" * 64
        b["hash"] = calc_hash(b)

n_parties = sum(1 for b in chain if b["data"].get("type") == "PARTY")
sig_map = sig_status(chain)

reg = pd.DataFrame([{"batch_id": b["data"]["batch_id"], "product": b["data"]["product"],
                     "quantity_kg": b["data"]["quantity_kg"], "farm_id": b["data"]["farm_id"],
                     "expiry_date": b["data"]["expiry_date"]}
                    for b in chain if b["data"].get("type") == "REGISTER"])
ev = pd.DataFrame([{"block": b["index"], "time": b["timestamp"], **{k: v for k, v in b["data"].items() if k != "type"},
                    "hash": b["hash"][:12]}
                   for b in chain if b["data"].get("type") == "EVENT"])
ev["sig_ok"] = ev["block"].map(sig_map)
ev["signature"] = ev["signature"].str[:12] + "..."
flagged = ev[ev["status"] == "FLAGGED"]

# ---------- sidebar ----------
page = st.sidebar.radio("Page", ["Overview", "Batch lookup", "Flagged & blocked", "Recall", "Tamper check"])
st.sidebar.caption("Single-node simulation of a permissioned blockchain. Data is synthetic.")

st.title("Food Supply Chain Traceability")

# ---------- pages ----------
if page == "Overview":
    ok, bad = verify(chain)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Blocks on chain", len(chain))
    c2.metric("Registered batches", len(reg))
    c3.metric("Flagged (temp breach)", flagged["batch_id"].nunique())
    c4.metric("Blocked transactions", len(rej))
    c5.metric("Registered parties", n_parties)
    if ok:
        st.success("Chain is valid")
    else:
        st.error(f"Chain broken at block #{bad}")
    s_ok, s_bad = sigs_ok(chain)
    if s_ok:
        st.success("All digital signatures are valid")
    else:
        st.error(f"Invalid signature at block #{s_bad}")
    st.subheader("Why transactions were blocked")
    st.bar_chart(rej["reason"].value_counts())

elif page == "Batch lookup":
    bid = st.selectbox("Select batch ID", reg["batch_id"])
    info = reg[reg.batch_id == bid].iloc[0]
    st.write(f"**{info['product']}** | {info['quantity_kg']} kg | farm {info['farm_id']} | expiry {info['expiry_date'][:10]}")
    t = ev[ev.batch_id == bid][["step", "handler_id", "location", "time", "temperature_c", "status", "reason", "signature", "sig_ok", "block", "hash"]]
    st.dataframe(t, hide_index=True)
    if (t["status"] == "FLAGGED").any():
        st.error("This batch was flagged: temperature went outside the safe range.")
    blocked = rej[rej.batch_id == bid]
    if len(blocked):
        st.warning("Blocked transactions for this batch:")
        st.dataframe(blocked, hide_index=True)
    st.caption("Fake batch IDs (FAKE01..) are not registered, so they appear under 'Flagged & blocked'.")

elif page == "Flagged & blocked":
    st.subheader("Flagged batches (recorded, but unsafe)")
    st.dataframe(flagged[["batch_id", "step", "handler_id", "location", "temperature_c", "reason", "block"]], hide_index=True)
    st.subheader("Blocked transactions (rejected by the smart contract)")
    st.dataframe(rej, hide_index=True)

elif page == "Recall":
    st.write("Pick an unsafe batch and see every retailer that received it.")
    options = sorted(flagged["batch_id"].unique())
    bid = st.selectbox("Batch to recall", options)
    r = ev[(ev.batch_id == bid) & (ev.step == "Retailer")]
    if r.empty:
        st.info("This batch never reached a retailer.")
    else:
        st.error(f"Recall {bid}: reached {len(r)} retailer(s)")
        st.dataframe(r[["handler_id", "location", "time", "block"]], hide_index=True)
    st.caption("Without a shared ledger this needs a phone call to every party.")

elif page == "Tamper check":
    st.write("Edit one record in a **copy** of the ledger and see what happens.")
    ids = [b["index"] for b in chain if b["data"].get("status") == "FLAGGED"]
    idx = st.selectbox("Block to edit (a flagged one)", ids)
    new_t = st.number_input("Change recorded temperature to", value=4.0)
    smart = st.checkbox("Smart attacker: also rebuild every hash after the edit")
    if st.button("Edit record and verify"):
        c2 = copy.deepcopy(chain)
        c2[idx]["data"]["temperature_c"] = new_t
        c2[idx]["data"]["status"] = "OK"
        if smart:
            rebuild_hashes(c2)
        st.write("Normal database: the edit is saved silently, no alarm.")
        ok, bad = verify(c2)
        if ok:
            st.success("Hash chain: still valid (the attacker rebuilt the hashes)")
        else:
            st.error(f"Hash chain: TAMPERING DETECTED at block #{bad}")
        s_ok, s_bad = sigs_ok(c2)
        if s_ok:
            st.success("Signatures: still valid")
        else:
            st.error(f"Signatures: FORGERY DETECTED at block #{s_bad}. The sender's private key is needed to re-sign.")
