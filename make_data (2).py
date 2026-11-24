import pandas as pd, numpy as np, random, os, hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

random.seed(42); np.random.seed(42)
arng = random.Random(7)   # separate generator for the attack cases

def make_key(actor_id):
    """Demo key pair (Ed25519), derived from the actor id so results repeat. Real systems keep private keys secret."""
    seed = hashlib.sha256(("food-demo-key-" + actor_id).encode()).digest()
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return seed.hex(), pub.hex()
os.makedirs("data/synthetic", exist_ok=True)

products = pd.DataFrame([
    ["P01", "Milk",   "dairy",     2,  6,   3],
    ["P02", "Paneer", "dairy",     2,  6,   6],
    ["P03", "Curd",   "dairy",     2,  6,   6],
    ["P04", "Fish",   "fish",      0,  4,   2],
    ["P05", "Tomato", "vegetable", 10, 15,  8],
    ["P06", "Onion",  "vegetable", 0,  25,  30],
    ["P07", "Potato", "vegetable", 4,  15,  30],
    ["P08", "Rice",   "grain",     5,  30,  180],
], columns=["product_id", "product", "category", "min_temp_c", "max_temp_c", "shelf_life_days"])

steps = ["Farm", "Collection Center", "Processor", "Distributor", "Retailer"]
names = {
    "Farm": ["Shivar Farms", "Green Valley Farm", "Sahyadri Farm", "Krishna Agro", "Godavari Farm"],
    "Collection Center": ["Pune Collection Hub", "Nashik Collection Hub", "Satara Collection Hub"],
    "Processor": ["FreshPro Processing", "AgriCool Foods", "PureLine Dairy"],
    "Distributor": ["QuickMove Logistics", "ColdChain India", "Sahyadri Transport", "MetroFresh Dist"],
    "Retailer": ["Big Basket Store Pune", "Reliance Fresh Mumbai", "Local Mart Nagpur", "Fresh Corner Nashik",
                 "Daily Needs Satara", "Super Bazaar Kolhapur", "City Mart Solapur", "Green Basket Aurangabad"],
}
cities = ["Pune", "Nashik", "Satara", "Kolhapur", "Nagpur", "Mumbai", "Aurangabad", "Solapur"]
actors, by_role = [], {}
for role, lst in names.items():
    by_role[role] = []
    for i, n in enumerate(lst):
        a = {"actor_id": f"{role[:2].upper()}{i+1:02d}", "name": n, "role": role, "city": random.choice(cities)}
        actors.append(a); by_role[role].append(a)
all_ids = [a["actor_id"] for a in actors]
keypairs = {a["actor_id"]: make_key(a["actor_id"]) for a in actors}
for a in actors:
    a["public_key"] = keypairs[a["actor_id"]][1]
actors = pd.DataFrame(actors)
pd.DataFrame([{"actor_id": k, "private_seed": v[0]} for k, v in keypairs.items()]).to_csv("data/synthetic/keys_private.csv", index=False)

N = 100
start = datetime(2026, 9, 1, 6, 0)
real_types = ["temperature_breach", "missing_step", "expired_sale", "bad_signature", "wrong_role"]
ids = list(range(1, N + 1)); random.shuffle(ids)
assign = {}
for k, t in enumerate(real_types):
    for i in ids[k*4:(k+1)*4]:
        assign[i] = t

batches, events, labels = [], [], []
eid = 1

def temp_ok(p):
    lo, hi = p["min_temp_c"], p["max_temp_c"]
    r = hi - lo
    return round(random.uniform(lo + 0.2*r, hi - 0.2*r), 1)

def add_event(bid, step, actor, ts, temp, signed_by=None):
    global eid
    events.append({"event_id": f"E{eid:05d}", "batch_id": bid, "step": step,
                   "handler_id": actor["actor_id"], "handler_name": actor["name"],
                   "location": actor["city"], "timestamp": ts, "temperature_c": temp,
                   "signed_by": signed_by or actor["actor_id"]})
    eid += 1

for i in range(1, N + 1):
    p = products.iloc[random.randrange(len(products))]
    bid = f"B{i:04d}"
    harvest = start + timedelta(days=random.randint(0, 45), hours=random.randint(0, 5))
    expiry = harvest + timedelta(days=int(p["shelf_life_days"]))
    farm = random.choice(by_role["Farm"])
    qty = random.choice([100, 200, 250, 500, 1000])
    batches.append({"batch_id": bid, "product_id": p["product_id"], "product": p["product"],
                    "quantity_kg": qty, "farm_id": farm["actor_id"], "farm_location": farm["city"],
                    "harvest_date": harvest, "expiry_date": expiry})
    atype = assign.get(i, "none")
    breach_step = random.choice(["Collection Center", "Distributor", "Retailer"])
    t = harvest
    for step in steps:
        if atype == "missing_step" and step == "Processor":
            continue
        if step != "Farm":
            t += timedelta(hours=random.randint(3, 12))
        actor = farm if step == "Farm" else random.choice(by_role[step])
        signed_by = actor["actor_id"]
        if atype == "wrong_role" and step == "Retailer":      # a Distributor writes the Retailer step
            actor = arng.choice(by_role["Distributor"]); signed_by = actor["actor_id"]
        if atype == "bad_signature" and step == "Retailer":   # signed with someone else's key
            signed_by = arng.choice([x for x in all_ids if x != actor["actor_id"]])
        temp = temp_ok(p)
        if atype == "temperature_breach" and step == breach_step:
            temp = round(p["max_temp_c"] + random.uniform(3, 8), 1)
        if atype == "expired_sale" and step == "Retailer":
            t = expiry + timedelta(days=random.randint(1, 3))
        add_event(bid, step, actor, t, temp, signed_by)
    labels.append({"batch_id": bid, "anomaly_type": atype})

for j in range(1, 5):
    p = products.iloc[random.randrange(len(products))]
    bid = f"FAKE{j:02d}"
    t = start + timedelta(days=random.randint(10, 40))
    for step in ["Distributor", "Retailer"]:
        t += timedelta(hours=random.randint(3, 12))
        add_event(bid, step, random.choice(by_role[step]), t, temp_ok(p))
    labels.append({"batch_id": bid, "anomaly_type": "fake_batch"})

batches = pd.DataFrame(batches)
events = pd.DataFrame(events).sort_values(["batch_id", "timestamp"]).reset_index(drop=True)
labels = pd.DataFrame(labels)
products.to_csv("data/synthetic/rules.csv", index=False)
actors.to_csv("data/synthetic/actors.csv", index=False)
batches.to_csv("data/synthetic/batches.csv", index=False)
events.to_csv("data/synthetic/events.csv", index=False)
labels.to_csv("data/synthetic/anomaly_labels.csv", index=False)
print("CELL 1 OK -> batches:", batches.shape, "| events:", events.shape, "| actors:", actors.shape)
print(labels["anomaly_type"].value_counts().to_dict())

# ---------------- blockchain build ----------------
import pandas as pd, hashlib, json, copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

rules   = pd.read_csv("data/synthetic/rules.csv").set_index("product_id")
batches = pd.read_csv("data/synthetic/batches.csv", parse_dates=["harvest_date", "expiry_date"])
events  = pd.read_csv("data/synthetic/events.csv", parse_dates=["timestamp"])
labels  = pd.read_csv("data/synthetic/anomaly_labels.csv")
actors  = pd.read_csv("data/synthetic/actors.csv")
keys    = pd.read_csv("data/synthetic/keys_private.csv").set_index("actor_id")["private_seed"].to_dict()

STEPS = ["Farm", "Collection Center", "Processor", "Distributor", "Retailer"]

# ---------- digital signatures (Ed25519) ----------
def sign(actor_id, message):                      # the SENDER signs with its own private key
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[actor_id])).sign(message).hex()

def check_sig(public_hex, signature_hex, message):  # anyone can check with the PUBLIC key
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

# ---------- blockchain ----------
class Blockchain:
    def __init__(self):
        self.chain = []
        self.add_block({"type": "GENESIS"}, "2026-01-01 00:00:00")
    @staticmethod
    def calc_hash(b):
        body = {k: b[k] for k in ["index", "timestamp", "data", "prev_hash"]}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    def add_block(self, data, ts):
        b = {"index": len(self.chain), "timestamp": str(ts), "data": data,
             "prev_hash": self.chain[-1]["hash"] if self.chain else "0" * 64}
        b["hash"] = self.calc_hash(b)
        self.chain.append(b)
    def verify(self):
        for i, b in enumerate(self.chain):
            if b["hash"] != self.calc_hash(b):
                return False, i, "block content changed"
            if i > 0 and b["prev_hash"] != self.chain[i - 1]["hash"]:
                return False, i, "chain link broken"
        return True, None, "chain is valid"

def verify_signatures(chain):
    pub = {b["data"]["actor_id"]: b["data"]["public_key"] for b in chain if b["data"].get("type") == "PARTY"}
    for b in chain:
        d = b["data"]
        if d.get("type") == "REGISTER":
            who, m = d["farm_id"], msg_register(d)
        elif d.get("type") == "EVENT":
            who, m = d["handler_id"], msg_event(d, b["timestamp"])
        else:
            continue
        if who not in pub or not check_sig(pub[who], d["signature"], m):
            return False, b["index"]
    return True, None

# ---------- smart contract ----------
class FoodContract:
    def __init__(self, chain):
        self.chain = chain
        self.parties = {}      # actor_id -> {"role", "public_key"}  (also stored on the chain)
        self.registered = {}
        self.last_step = {}
        self.rejected = []
    def register_party(self, row):
        self.parties[row.actor_id] = {"role": row.role, "public_key": row.public_key}
        self.chain.add_block({"type": "PARTY", "actor_id": row.actor_id, "name": row.name,
                              "role": row.role, "public_key": row.public_key}, "2026-01-01 00:00:01")
    def register_batch(self, row):
        d = {"batch_id": row.batch_id, "product": row.product, "quantity_kg": int(row.quantity_kg),
             "farm_id": row.farm_id, "expiry_date": str(row.expiry_date)}
        sig = sign(row.farm_id, msg_register(d))
        p = self.parties.get(row.farm_id)
        assert p and p["role"] == "Farm" and check_sig(p["public_key"], sig, msg_register(d))
        self.registered[row.batch_id] = {"product_id": row.product_id, "expiry": row.expiry_date}
        self.last_step[row.batch_id] = -1
        self.chain.add_block({"type": "REGISTER", **d, "signature": sig}, row.harvest_date)
    def add_event(self, e):
        d = {"event_id": e.event_id, "batch_id": e.batch_id, "step": e.step, "handler_id": e.handler_id,
             "location": e.location, "temperature_c": float(e.temperature_c)}
        sig = sign(e.signed_by, msg_event(d, e.timestamp))    # the sender signs the transaction
        def reject(reason):
            self.rejected.append({"event_id": e.event_id, "batch_id": e.batch_id, "step": e.step, "reason": reason})
        party = self.parties.get(e.handler_id)
        if party is None:                                              return reject("unknown_party")
        if not check_sig(party["public_key"], sig, msg_event(d, e.timestamp)): return reject("bad_signature")
        if party["role"] != e.step:                                    return reject("wrong_role")
        if e.batch_id not in self.registered:                          return reject("unregistered_batch")
        info = self.registered[e.batch_id]
        if STEPS.index(e.step) != self.last_step[e.batch_id] + 1:      return reject("step_skipped")
        if e.timestamp > info["expiry"]:                               return reject("expired")
        r = rules.loc[info["product_id"]]
        status, reason = "OK", ""
        if not (r.min_temp_c <= e.temperature_c <= r.max_temp_c):
            status, reason = "FLAGGED", "temp_breach"
        self.last_step[e.batch_id] += 1
        self.chain.add_block({"type": "EVENT", **d, "status": status, "reason": reason, "signature": sig}, e.timestamp)

bc = Blockchain()
sc = FoodContract(bc)
for row in actors.itertuples():
    sc.register_party(row)
for row in batches.itertuples():
    sc.register_batch(row)
for e in events.sort_values("timestamp").itertuples():
    sc.add_event(e)

rej = pd.DataFrame(sc.rejected)
json.dump(bc.chain, open("data/synthetic/ledger.json", "w"), indent=1)
rej.to_csv("data/synthetic/rejected_log.csv", index=False)

print("CELL 2 OK -> blocks:", len(bc.chain), "| rejected:", len(rej))
print(rej["reason"].value_counts().to_dict())
print("Chain check:", bc.verify())
print("Signature check:", verify_signatures(bc.chain))

print("DONE. Files saved in data/synthetic/")
