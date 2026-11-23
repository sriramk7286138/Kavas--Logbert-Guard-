# Generated from: LogBERT_Local_Guard_01 - Copy.ipynb
# Converted at: 2026-11-23T01:08:18.946Z
# Next step (optional): refactor into modules & generate tests with RunCell
# Quick start: pip install runcell

# # LogBERT Local Guard


# ## Step 1 — Check Python, PyTorch and the GPU


import sys, torch
print("Python version :", sys.version.split()[0])
print("PyTorch version :", torch.__version__)
print("GPU available   :", torch.cuda.is_available())
if torch.cuda.is_available():
    print("GPU name        :", torch.cuda.get_device_name(0))

# ## Step 2 — Imports and settings


import os, re, glob, json, math, random, shutil, platform, getpass, tempfile, subprocess, time, warnings, smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score
warnings.filterwarnings("ignore")

DATA_ROOT   = r"data"
OUTPUT_ROOT = r"outputs"

FAST_CHECK = False

PAD_ID, UNK_ID, CLS_ID, MASK_ID = 0, 1, 2, 3
NUM_SPECIAL = 4

WINDOW_SIZE  = 32
STRIDE       = 8
TRAIN_STRIDE = 8

VAL_DAY_FRACTION  = 0.15
TEST_DAY_FRACTION = 0.15

USE_CONTEXT_FEATURES = False
HOUR_BIN_HOURS = 4

EMBED_DIM  = 64
NUM_LAYERS = 2
NUM_HEADS  = 2
FF_DIM     = 128
DROPOUT    = 0.1

MASK_RATIO    = 0.15
BATCH_SIZE    = 32
LEARNING_RATE = 1e-3
MAX_EPOCHS    = 400
PATIENCE      = 15
USE_VHM       = False
VHM_WEIGHT    = 0.1
N_ENSEMBLE    = 3
SEED          = 42

TOP_G        = 10
MASK_ROUNDS  = 7
TOPK_EVENTS  = 4
SURPRISAL_CAP = 8.0
UNK_KNOWN_PROVIDER_FACTOR = 0.5
ALL_COMPONENTS   = ("surprisal_mean", "surprisal_topk", "hypersphere", "miss_rate")
SCORE_COMPONENTS = ("surprisal_mean", "surprisal_topk")

SMOOTH_WINDOWS         = 3
THRESHOLD_PERCENTILE   = 99
ALERTS_PER_DAY_BUDGET  = 0.5
EPISODE_MERGE_GAP      = 2
OBSERVATION_DAYS       = 5
CHANGE_STREAK_DAYS     = 3
SHIFT_FLAG_SHARE       = 0.25
MIN_DAY_WINDOWS        = 10
AUTO_RESET             = True
RESET_LEARN_DAYS       = 7

AUTO_COLLECT    = True
LOG_DAYS        = 15
CHECK_DAYS      = CHANGE_STREAK_DAYS + 2
MIN_DAYS        = 5
MIN_VAL_WINDOWS = 20
WATCH_MINUTES   = 360

N_INJECT_REPEATS = 5
INJECT_SEGMENTS  = 6
INJECT_LENGTH    = 10

if FAST_CHECK:
    N_ENSEMBLE, MAX_EPOCHS, PATIENCE, N_INJECT_REPEATS = 1, 25, 5, 2

CH_KEY, CH_PROV, CH_LEVEL, CH_LOG, CH_HOUR, CH_GAP, CH_REP = range(7)
NUM_CH = 7
IDENTITY_CH = (CH_KEY, CH_PROV, CH_LEVEL, CH_LOG)
GAP_EDGES = np.array([1, 5, 30, 300, 3600, 21600], dtype=float)
REP_EDGES = np.array([2, 4, 10, 50])
assert 24 % HOUR_BIN_HOURS == 0
N_HOUR_BINS = 24 // HOUR_BIN_HOURS
N_HOUR_EMB, N_GAP_EMB, N_REP_EMB = N_HOUR_BINS + 1, len(GAP_EDGES) + 2, len(REP_EDGES) + 2

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
os.makedirs(OUTPUT_ROOT, exist_ok=True)
print("Running on:", DEVICE, "| FAST_CHECK =", FAST_CHECK)
print("data folder  :", os.path.abspath(DATA_ROOT))
print("output folder:", os.path.abspath(OUTPUT_ROOT))

# ## Step 3 — Collect the last 15 days of logs from this machine


LOG_NAMES = ("System", "Application")
LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}

def read_csv_any(path, **kw):
    try:
        return pd.read_csv(path, encoding="utf-8-sig", **kw)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="latin-1", **kw)

def parse_time(values):
    try:
        return pd.to_datetime(values, utc=True, format="ISO8601")
    except (ValueError, TypeError):
        return pd.to_datetime(values, utc=True)

def has_csv(path):
    return os.path.isdir(path) and len(glob.glob(os.path.join(path, "*.csv"))) > 0

def local_user_name():
    name = os.environ.get("USERNAME") or getpass.getuser()
    return re.sub(r'[\\/:*?"<>|\s]+', "_", name).strip("_") or "local_user"

def powershell_exe():
    if platform.system() != "Windows":
        raise OSError("collecting logs works on Windows only")
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if exe is None:
        raise OSError("PowerShell was not found on this machine")
    return exe

def read_windows_log(log_name, start):
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, log_name + ".csv")
    ps_path = path.replace("'", "''")
    script = (
        f"$s=[datetime]::ParseExact('{start:%Y-%m-%dT%H:%M:%S}','yyyy-MM-ddTHH:mm:ss',[Globalization.CultureInfo]::InvariantCulture);"
        f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}';StartTime=$s}} -ErrorAction SilentlyContinue | "
        "Select-Object @{n='TimeCreated';e={$_.TimeCreated.ToString('o')}},@{n='LogName';e={$_.LogName}},"
        "@{n='EventID';e={$_.Id}},@{n='Level';e={$_.Level}},@{n='Provider';e={$_.ProviderName}} | "
        f"Export-Csv -Path '{ps_path}' -NoTypeInformation -Encoding UTF8"
    )
    try:
        run = subprocess.run([powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, errors="replace", timeout=3600)
        if run.returncode != 0:
            raise RuntimeError(run.stderr.strip()[:500] or "PowerShell failed")
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return pd.DataFrame(columns=["TimeCreated", "LogName", "EventID", "Level", "Provider"])
        return read_csv_any(path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def collect_logs(user, days=None, since_day=None, out_dir=None):
    days = days or LOG_DAYS
    out_dir = out_dir or os.path.join(DATA_ROOT, user)
    os.makedirs(out_dir, exist_ok=True)
    start = datetime.strptime(since_day, "%Y-%m-%d") if since_day else datetime.now() - timedelta(days=days)
    print(f"reading {' and '.join(LOG_NAMES)} events since {start:%Y-%m-%d %H:%M} (this can take a minute or two)")
    df = pd.concat([read_windows_log(n, start) for n in LOG_NAMES], ignore_index=True)
    df = df.dropna(subset=["TimeCreated"])
    if df.empty:
        raise RuntimeError("no events were collected; try starting Jupyter as administrator")
    df["Level"] = pd.to_numeric(df["Level"], errors="coerce").fillna(-1).astype(int).map(LEVEL_NAMES).fillna("NA")
    df["Provider"] = df["Provider"].fillna("NA").astype(str)
    for name in LOG_NAMES:
        part = df[df["LogName"] == name]
        if len(part):
            part.to_csv(os.path.join(out_dir, name + ".csv"), index=False, encoding="utf-8")
        print(f"  {name:12s}: {len(part)} events")
    t = parse_time(df["TimeCreated"].astype(str))
    covered = (t.max() - t.min()).total_seconds() / 86400
    print(f"  first event {df.loc[t.idxmin(), 'TimeCreated'][:19]} | last event {df.loc[t.idxmax(), 'TimeCreated'][:19]} | {covered:.1f} days covered")
    if not since_day and covered < days - 1:
        print(f"  warning: Windows only kept {covered:.1f} of the last {days} days (its event logs are small and overwrite old events)")
        print("  to keep more history from now on, run these once in an administrator command prompt:")
        print("    wevtutil sl System /ms:104857600")
        print("    wevtutil sl Application /ms:104857600")
    return {"events": len(df), "days": round(covered, 1), "dir": out_dir}

LOCAL_USER = local_user_name()
os.makedirs(DATA_ROOT, exist_ok=True)
if AUTO_COLLECT and platform.system() == "Windows" and not has_csv(os.path.join(DATA_ROOT, LOCAL_USER)):
    print(f"no logs found for {LOCAL_USER}; collecting the last {LOG_DAYS} days from this machine")
    collect_logs(LOCAL_USER)

# ## Step 4 — Read the logs and check what you have


REQUIRED_COLUMNS = ["TimeCreated", "EventID", "Provider"]
OPTIONAL_COLUMNS = {"Level": "NA", "LogName": "NA"}

def load_logs(path):
    files = sorted(glob.glob(os.path.join(path, "*.csv"))) if os.path.isdir(path) else [path]
    if not files:
        raise FileNotFoundError(f"No .csv files found in: {path}")
    frames = []
    for f in files:
        df = read_csv_any(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(f"{f} is missing columns {missing}. Found: {list(df.columns)}")
        for c, default in OPTIONAL_COLUMNS.items():
            if c not in df.columns:
                df[c] = default
        frames.append(df[REQUIRED_COLUMNS + list(OPTIONAL_COLUMNS)])
    df = pd.concat(frames, ignore_index=True).dropna(subset=["TimeCreated"])
    df["TimeCreated"] = df["TimeCreated"].astype(str)
    if not df["TimeCreated"].str.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}").all():
        raise ValueError("TimeCreated must be ISO 8601, for example 2026-11-22T14:05:12+05:30 (the collector in Step 3 writes this format)")
    df["Level"] = df["Level"].fillna("NA").astype(str)
    df["LogName"] = df["LogName"].fillna("NA").astype(str)
    df["time"] = parse_time(df["TimeCreated"])
    df["day"] = df["TimeCreated"].str[:10]
    return df.sort_values("time", kind="stable").reset_index(drop=True)

def check_coverage(path):
    rows = []
    for f in sorted(glob.glob(os.path.join(path, "*.csv"))):
        t = parse_time(read_csv_any(f, usecols=["TimeCreated"])["TimeCreated"].astype(str))
        rows.append({"file": os.path.basename(f), "events": len(t), "first_event": t.min(),
                     "last_event": t.max(), "days_covered": round((t.max() - t.min()).total_seconds() / 86400, 1)})
    return pd.DataFrame(rows)

def list_users():
    return sorted(d for d in os.listdir(DATA_ROOT) if has_csv(os.path.join(DATA_ROOT, d)))

USERS = list_users()
if not USERS:
    raise FileNotFoundError(f"No user folders with .csv files found in {os.path.abspath(DATA_ROOT)}. On Windows keep AUTO_COLLECT = True in Step 2 and run Step 3 again.")
print("Users found:", USERS)
check_coverage(os.path.join(DATA_ROOT, USERS[0]))

# ## Step 5 — Turn events into numbers


def local_times(df):
    return df["TimeCreated"].astype(str).str[:19].str.replace("T", " ", regex=False).to_numpy()

def add_keys(df):
    df = df.copy()
    df["key"] = df["Provider"].astype(str) + ":" + df["EventID"].astype(str)
    return df

def collapse_repeats(df):
    df = df.reset_index(drop=True)
    new_run = df["key"] != df["key"].shift()
    run_id = new_run.cumsum()
    out = df[new_run].copy().reset_index(drop=True)
    out["rep"] = df.groupby(run_id).size().to_numpy()
    return out

def preprocess(df_raw):
    df = collapse_repeats(add_keys(df_raw))
    df["hour"] = df["TimeCreated"].astype(str).str[11:13].astype(int)
    df["gap"] = df["time"].diff().dt.total_seconds().fillna(1e9)
    return df

def split_days(days):
    n = len(days)
    if n < MIN_DAYS:
        raise ValueError(f"Only {n} days of logs found; at least {MIN_DAYS} are needed.")
    n_test = max(1, round(TEST_DAY_FRACTION * n))
    n_val = max(1, round(VAL_DAY_FRACTION * n))
    n_train = n - n_val - n_test
    return days[:n_train], days[n_train:n_train + n_val], days[n_train + n_val:]

def list_days(path):
    return sorted(preprocess(load_logs(path))["day"].unique())

def build_vocabs(train_df):
    cols = {"key": "key", "prov": "Provider", "level": "Level", "log": "LogName"}
    voc = {}
    for name, col in cols.items():
        values = sorted(set(train_df[col].astype(str)))
        voc[name] = {v: i + NUM_SPECIAL for i, v in enumerate(values)}
    V = len(voc["key"]) + NUM_SPECIAL
    attrs = [[0, 0, 0] for _ in range(V)]
    first = train_df.drop_duplicates("key")
    for k, p, l, g in zip(first["key"], first["Provider"], first["Level"], first["LogName"]):
        attrs[voc["key"][k]] = [voc["prov"][str(p)], voc["level"][str(l)], voc["log"][str(g)]]
    counts = [0] * V
    for k, c in train_df["key"].value_counts().items():
        counts[voc["key"][k]] = int(c)
    voc["key_attrs"], voc["key_count"] = attrs, counts
    return voc

def vocab_sizes(voc):
    return {n: len(voc[n]) + NUM_SPECIAL for n in ("key", "prov", "level", "log")}

def encode(df, voc):
    Z = np.zeros((len(df), NUM_CH), dtype=np.int64)
    for ch, name, col in ((CH_KEY, "key", "key"), (CH_PROV, "prov", "Provider"),
                          (CH_LEVEL, "level", "Level"), (CH_LOG, "log", "LogName")):
        Z[:, ch] = df[col].astype(str).map(voc[name]).fillna(UNK_ID).astype(np.int64).to_numpy()
    if USE_CONTEXT_FEATURES:
        Z[:, CH_HOUR] = df["hour"].to_numpy() // HOUR_BIN_HOURS + 1
        Z[:, CH_GAP] = np.searchsorted(GAP_EDGES, df["gap"].to_numpy(dtype=float), side="right") + 1
        Z[:, CH_REP] = np.searchsorted(REP_EDGES, df["rep"].to_numpy(), side="right") + 1
    else:
        Z[:, CH_HOUR:] = 1
    return Z

def make_windows(feat, stride=None, offset=0, cover_end=True):
    stride = stride or STRIDE
    n = len(feat)
    if n - offset < WINDOW_SIZE:
        return np.zeros((0, WINDOW_SIZE + 1, NUM_CH), dtype=np.int64), np.zeros(0, dtype=np.int64)
    starts = list(range(offset, n - WINDOW_SIZE + 1, stride))
    if cover_end and starts[-1] != n - WINDOW_SIZE:
        starts.append(n - WINDOW_SIZE)
    starts = np.array(starts, dtype=np.int64)
    X = np.zeros((len(starts), WINDOW_SIZE + 1, NUM_CH), dtype=np.int64)
    X[:, 0, :CH_HOUR] = CLS_ID
    X[:, 1:, :] = feat[starts[:, None] + np.arange(WINDOW_SIZE)[None, :]]
    return X, starts

def prepare_user(path, split=None):
    df = preprocess(load_logs(path))
    days = sorted(df["day"].unique())
    train_days, val_days, test_days = split if split else split_days(days)
    parts = {"train": df[df["day"].isin(train_days)].reset_index(drop=True),
             "val":   df[df["day"].isin(val_days)].reset_index(drop=True),
             "test":  df[df["day"].isin(test_days)].reset_index(drop=True)}
    voc = build_vocabs(parts["train"])
    out = {"voc": voc, "days": {"train": list(train_days), "val": list(val_days), "test": list(test_days)}}
    for name, part in parts.items():
        feat = encode(part, voc)
        X, starts = make_windows(feat)
        out[name] = {"feat": feat, "X": X, "starts": starts, "n_events": len(part),
                     "times": local_times(part)}
    return out

def prepare_new_logs(path, voc):
    df = preprocess(load_logs(path))
    feat = encode(df, voc)
    X, starts = make_windows(feat)
    return X, starts, local_times(df), df, feat

# ## Step 6 — Explore one user before modelling


def explore_user(user):
    path = os.path.join(DATA_ROOT, user)
    raw = add_keys(load_logs(path))
    clean = preprocess(raw)
    days = sorted(clean["day"].unique())
    tr, va, te = split_days(days)
    print(f"=== {user} ===")
    print(f"Time range            : {raw['time'].min()} -> {raw['time'].max()}")
    print(f"Events (raw)          : {len(raw)}")
    print(f"Events after cleaning : {len(clean)} ({len(raw) - len(clean)} repeated events merged; burst size is kept as a feature)")
    print(f"Different log keys    : {raw['key'].nunique()} | providers: {raw['Provider'].nunique()} | levels: {sorted(raw['Level'].unique())}")
    print(f"Days                  : {len(days)} (train {len(tr)}, validation {len(va)}, test {len(te)})")
    print("\nTop 8 noisiest log keys (raw):")
    print(raw["key"].value_counts().head(8).to_string())
    fig, ax = plt.subplots(1, 2, figsize=(13, 4))
    clean.groupby("day").size().plot(kind="bar", ax=ax[0], title="Events per day (after cleaning)")
    clean["hour"].value_counts().reindex(range(24), fill_value=0).plot(kind="bar", ax=ax[1], title="Events per hour of the day")
    plt.tight_layout()
    os.makedirs(os.path.join(OUTPUT_ROOT, "figures"), exist_ok=True)
    plt.savefig(os.path.join(OUTPUT_ROOT, "figures", f"{user}_explore.png"), dpi=130)
    plt.show()
    data = prepare_user(path)
    sizes = vocab_sizes(data["voc"])
    print("\nWindows:", {p: len(data[p]["X"]) for p in ("train", "val", "test")}, "| vocabulary sizes:", sizes)
    for p in ("val", "test"):
        X = data[p]["X"]
        print(f"never-seen event slots in {p:4s} windows: {100 * (X[:, 1:, CH_KEY] == UNK_ID).mean():.1f} %")

for i in USERS:
    try:
        explore_user(i)
    except Exception as err:
        print(f"SKIPPED {i}: {err}")

# ## Step 7 — The LogBERT model


class LogBERT(nn.Module):
    def __init__(self, sizes, seq_len):
        super().__init__()
        d = EMBED_DIM
        self.emb = nn.ModuleList([
            nn.Embedding(sizes["key"],   d, padding_idx=PAD_ID),
            nn.Embedding(sizes["prov"],  d, padding_idx=PAD_ID),
            nn.Embedding(sizes["level"], d, padding_idx=PAD_ID),
            nn.Embedding(sizes["log"],   d, padding_idx=PAD_ID),
            nn.Embedding(N_HOUR_EMB, d, padding_idx=0),
            nn.Embedding(N_GAP_EMB,  d, padding_idx=0),
            nn.Embedding(N_REP_EMB,  d, padding_idx=0)])
        self.pos_emb = nn.Embedding(seq_len, d)
        self.norm = nn.LayerNorm(d)
        self.drop = nn.Dropout(DROPOUT)
        layer = nn.TransformerEncoderLayer(d_model=d, nhead=NUM_HEADS, dim_feedforward=FF_DIM,
                                           dropout=DROPOUT, batch_first=True, activation="gelu")
        self.encoder = nn.TransformerEncoder(layer, num_layers=NUM_LAYERS, enable_nested_tensor=False)
        self.transform = nn.Sequential(nn.Linear(d, d), nn.GELU(), nn.LayerNorm(d))
        self.out_bias = nn.Parameter(torch.zeros(sizes["key"]))
        self.register_buffer("center", torch.zeros(d))

        for m in self.modules():
            if isinstance(m, nn.Embedding):
                nn.init.normal_(m.weight, mean=0.0, std=0.02)

    def forward(self, x):
        h = self.emb[0](x[:, :, 0])
        for c in range(1, NUM_CH):
            h = h + self.emb[c](x[:, :, c])
        positions = torch.arange(x.size(1), device=x.device).unsqueeze(0)
        h = self.drop(self.norm(h + self.pos_emb(positions)))
        h = self.encoder(h, src_key_padding_mask=(x[:, :, CH_KEY] == PAD_ID))

        logits = F.linear(self.transform(h), self.emb[0].weight, self.out_bias)
        logits = logits / math.sqrt(EMBED_DIM)

        return logits, h[:, 0, :]

    @torch.no_grad()
    def update_center(self, X, batch_size=256):
        self.eval()
        total, count = torch.zeros_like(self.center), 0
        for i in range(0, len(X), batch_size):
            _, cls = self(X[i:i + batch_size].to(DEVICE))
            total += cls.sum(dim=0)
            count += cls.size(0)
        self.center.copy_(total / max(count, 1))

def apply_mask(x, hide):
    m = x.clone()
    for c in IDENTITY_CH:
        m[..., c] = m[..., c].masked_fill(hide, MASK_ID)
    return m

def random_mask(x, ratio, generator=None):
    key = x[..., CH_KEY]
    candidates = (key != PAD_ID) & (key != CLS_ID)
    chosen = (torch.rand(key.shape, generator=generator) < ratio) & candidates
    empty = ~chosen.any(dim=1)
    if empty.any():
        r = torch.rand(key.shape, generator=generator).masked_fill(~candidates, -1.0)
        forced = r.argmax(dim=1)
        rows = torch.nonzero(empty).squeeze(1)
        chosen[rows, forced[rows]] = True
    labels = torch.full_like(key, -100)
    labels[chosen] = key[chosen]
    return apply_mask(x, chosen), labels

def vhm_loss(cls, center):
    return ((cls - center) ** 2).sum(dim=1).mean()

# ## Step 8 — Scoring, calibration and alert logic


@torch.no_grad()
def score_components(models, X, fast=False, batch_size=128):
    names = ["surprisal_mean"] if fast else ["surprisal_mean", "surprisal_topk", "hypersphere", "miss_rate"]
    X = torch.as_tensor(X)
    if len(X) == 0:
        return {n: np.zeros(0) for n in names + ["unk_frac"]}
    acc = {n: [] for n in names}
    unk_acc = []
    for i in range(0, len(X), batch_size):
        x = X[i:i + batch_size].to(DEVICE)
        key = x[:, :, CH_KEY]
        real = (key != PAD_ID) & (key != CLS_ID)
        n_real = real.sum(dim=1).clamp(min=1).float()
        is_unk = key == UNK_ID
        unk_prov = x[:, :, CH_PROV] == UNK_ID

        unk_cost = SURPRISAL_CAP * (unk_prov.float() + UNK_KNOWN_PROVIDER_FACTOR * (~unk_prov).float())
        pos = torch.arange(x.size(1), device=DEVICE).unsqueeze(0).expand_as(key)
        sums = {n: torch.zeros(x.size(0), device=DEVICE) for n in names}
        for model in models:
            model.eval()
            surpr = torch.zeros(key.shape, device=DEVICE)
            miss = torch.zeros(x.size(0), device=DEVICE)
            for r in range(MASK_ROUNDS):
                hide = real & (pos % MASK_ROUNDS == r)
                logits, _ = model(apply_mask(x, hide))
                logits[:, :, :NUM_SPECIAL] = float("-inf")
                logp = F.log_softmax(logits, dim=-1)
                lp = logp.gather(-1, key.unsqueeze(-1)).squeeze(-1)
                s = (-lp).clamp(max=SURPRISAL_CAP)
                s = torch.where(is_unk, unk_cost, s)
                surpr = surpr + s * hide.float()
                if not fast:
                    top = logits.topk(min(TOP_G, logits.size(-1) - NUM_SPECIAL), dim=-1).indices
                    hit = (top == key.unsqueeze(-1)).any(dim=-1)
                    miss = miss + (hide & ~hit).sum(dim=1).float()
            sums["surprisal_mean"] += (surpr * real.float()).sum(dim=1) / n_real
            if not fast:
                tail = surpr.masked_fill(~real, 0.0).topk(min(TOPK_EVENTS, surpr.size(1)), dim=1).values.mean(dim=1)
                sums["surprisal_topk"] += tail
                _, cls = model(x)
                sums["hypersphere"] += ((cls - model.center) ** 2).sum(dim=1).sqrt()
                sums["miss_rate"] += miss / n_real
        for n in names:
            acc[n].append((sums[n] / len(models)).cpu())
        unk_acc.append(((is_unk & real).sum(dim=1).float() / n_real).cpu())
    out = {n: torch.cat(acc[n]).numpy() for n in names}
    out["unk_frac"] = torch.cat(unk_acc).numpy()
    return out

def fit_calibration(val_comps):
    cal = {}
    for k in ALL_COMPONENTS:
        v = np.asarray(val_comps[k], dtype=float)
        med = float(np.median(v))
        mad = float(np.median(np.abs(v - med))) * 1.4826
        cal[k] = {"median": med, "scale": float(max(mad, 0.5 * v.std(), 1e-6))}
    return cal

def standardize(values, c):
    return np.clip((np.asarray(values, dtype=float) - c["median"]) / c["scale"], -3.0, 30.0)

def combine_z(z, which=None):
    which = which or SCORE_COMPONENTS
    return np.mean([z[k] for k in which], axis=0)

def smooth(scores, k=None):
    k = k or SMOOTH_WINDOWS
    scores = np.asarray(scores, dtype=float)
    if len(scores) == 0:
        return scores
    c = np.cumsum(np.insert(scores, 0, 0.0))
    out = np.empty(len(scores))
    for i in range(len(scores)):
        lo = max(0, i - k + 1)
        out[i] = (c[i + 1] - c[lo]) / (i + 1 - lo)
    return out

def find_episodes(flags, merge_gap=None):
    merge_gap = EPISODE_MERGE_GAP if merge_gap is None else merge_gap
    runs, start = [], None
    for i, f in enumerate(list(flags) + [False]):
        if f and start is None:
            start = i
        elif not f and start is not None:
            runs.append([start, i - 1]); start = None
    merged = []
    for a, b in runs:
        if merged and a - merged[-1][1] - 1 <= merge_gap:
            merged[-1][1] = b
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]

def choose_threshold(val_smooth, n_val_days):
    val_smooth = np.asarray(val_smooth, dtype=float)
    t_pct = float(np.percentile(val_smooth, THRESHOLD_PERCENTILE))
    t_budget = float(val_smooth.max())
    for t in np.sort(np.unique(val_smooth[val_smooth >= t_pct])):
        if len(find_episodes(val_smooth > t)) / max(n_val_days, 1) <= ALERTS_PER_DAY_BUDGET:
            t_budget = float(t); break
    return max(t_pct, t_budget), {"percentile_threshold": t_pct, "budget_threshold": t_budget}

class Detector:
    def __init__(self, models, voc, meta):
        self.models, self.voc, self.meta = models, voc, meta
        self.cal, self.thr = meta["calibration"], meta["threshold"]
        self.which = tuple(meta["score_components"])
    def score(self, X):
        comps = score_components(self.models, X)
        z = {k: standardize(comps[k], self.cal[k]) for k in ALL_COMPONENTS}
        raw = combine_z(z, self.which)
        sm = smooth(raw, self.meta["smooth_windows"])
        return {"comps": comps, "z": z, "raw": raw, "smooth": sm, "flags": sm > self.thr}

def model_path(user, tag=""):
    return os.path.join(OUTPUT_ROOT, "models", user + (f"__{tag}" if tag else ""))

def load_trained(model_dir):
    ckpt = torch.load(os.path.join(model_dir, "model.pt"), map_location=DEVICE)
    models = []
    for sd in ckpt["state_dicts"]:
        m = LogBERT(ckpt["sizes"], ckpt["seq_len"]).to(DEVICE)
        m.load_state_dict(sd); m.eval(); models.append(m)
    with open(os.path.join(model_dir, "vocab.json"), encoding="utf-8") as f:
        voc = json.load(f)
    with open(os.path.join(model_dir, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    return Detector(models, voc, meta)

def update_meta(user, tag="", **changes):
    path = os.path.join(model_path(user, tag), "meta.json")
    with open(path, encoding="utf-8") as f:
        meta = json.load(f)
    meta.update(changes)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta

# ## Step 9 — Training


def set_seed(seed):
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def run_epoch(model, X, optimizer):
    model.train()
    perm = torch.randperm(len(X))
    tot_m, tot_v, n = 0.0, 0.0, 0
    for i in range(0, len(X), BATCH_SIZE):
        x = X[perm[i:i + BATCH_SIZE]]
        masked, labels = random_mask(x, MASK_RATIO)
        masked, labels = masked.to(DEVICE), labels.to(DEVICE)
        logits, cls = model(masked)
        mlkp = F.cross_entropy(logits.reshape(-1, logits.size(-1)), labels.reshape(-1), ignore_index=-100)
        vhm = vhm_loss(cls, model.center)
        loss = mlkp + (VHM_WEIGHT * vhm if USE_VHM else 0.0)
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        tot_m += mlkp.item(); tot_v += vhm.item(); n += 1
    return tot_m / max(n, 1), tot_v / max(n, 1)

def train_member(feat_train, Xva, sizes, seed, verbose=True):
    set_seed(seed)
    rng = np.random.default_rng(seed)
    model = LogBERT(sizes, WINDOW_SIZE + 1).to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="min", factor=0.5, patience=6, min_lr=1e-5)
    Xva_t = torch.as_tensor(Xva)
    best, best_state, bad = float("inf"), None, 0
    hist = {"train": [], "val": [], "vhm": []}
    for epoch in range(1, MAX_EPOCHS + 1):
        Xtr_np, _ = make_windows(feat_train, stride=TRAIN_STRIDE, offset=int(rng.integers(0, TRAIN_STRIDE)), cover_end=False)
        Xtr = torch.as_tensor(Xtr_np)
        if USE_VHM:
            model.update_center(Xtr)
        tr, vhm = run_epoch(model, Xtr, opt)
        va = float(score_components([model], Xva_t, fast=True)["surprisal_mean"].mean())
        sched.step(va)
        hist["train"].append(tr); hist["val"].append(va); hist["vhm"].append(vhm)
        if verbose and (epoch == 1 or epoch % 10 == 0):
            print(f"    epoch {epoch:3d} | train error {tr:.3f} | validation surprisal {va:.3f} | hypersphere {vhm:.2f}")
        if va < best - 1e-3:
            best, bad = va, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= PATIENCE:
                if verbose: print(f"    no improvement for {PATIENCE} epochs -> stopped early at epoch {epoch}")
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    Xfull, _ = make_windows(feat_train, stride=TRAIN_STRIDE, offset=0, cover_end=True)
    model.update_center(torch.as_tensor(Xfull))
    hist["best_val"] = best
    return model, hist

def train_user(user, split=None, tag="", verbose=True):
    out_dir = model_path(user, tag)
    os.makedirs(out_dir, exist_ok=True)
    data = prepare_user(os.path.join(DATA_ROOT, user), split)
    voc, sizes = data["voc"], vocab_sizes(data["voc"])
    feat_tr, Xva = data["train"]["feat"], data["val"]["X"]
    n_tr = len(make_windows(feat_tr, stride=TRAIN_STRIDE, cover_end=False)[0])

    if n_tr < 50:
        raise ValueError(f"too little data: {n_tr} training windows (try a smaller WINDOW_SIZE/STRIDE or more days)")
    if len(Xva) < MIN_VAL_WINDOWS:
        raise ValueError(f"too little validation data: {len(Xva)} windows, at least {MIN_VAL_WINDOWS} are needed (more days of logs help)")

    print(f"[{user}{'/' + tag if tag else ''}] train windows/epoch {n_tr} | validation windows {len(Xva)} | vocabulary {sizes}")
    t0 = time.time()
    models, hists = [], []
    for k in range(N_ENSEMBLE):
        print(f"  member {k + 1}/{N_ENSEMBLE} (seed {SEED + k})")
        m, h = train_member(feat_tr, Xva, sizes, SEED + k, verbose=(verbose and k == 0))
        print(f"    epochs {len(h['train'])} | best validation surprisal {h['best_val']:.3f}")
        models.append(m); hists.append(h)
    n_params = sum(p.numel() for p in models[0].parameters())

    val_comps = score_components(models, Xva)
    cal = fit_calibration(val_comps)
    z = {k: standardize(val_comps[k], cal[k]) for k in ALL_COMPONENTS}
    val_smooth = smooth(combine_z(z, SCORE_COMPONENTS))

    if len(Xva) < 100:
        thr = float(np.percentile(val_smooth, 99.0))
        thr_info = "percentile_99_fallback"
    else:
        thr, thr_info = choose_threshold(val_smooth, len(data["days"]["val"]))

    print(f"  alert threshold (smoothed score): {thr:.2f}  {thr_info} | parameters per model: {n_params:,} | training time {time.time() - t0:.0f} s")

    torch.save({"state_dicts": [m.state_dict() for m in models], "sizes": sizes,
                "seq_len": WINDOW_SIZE + 1}, os.path.join(out_dir, "model.pt"))
    with open(os.path.join(out_dir, "vocab.json"), "w", encoding="utf-8") as f:
        json.dump(voc, f)
    meta = {"user": user, "tag": tag, "threshold": float(thr), "threshold_info": thr_info, "calibration": cal,
            "score_components": list(SCORE_COMPONENTS), "smooth_windows": SMOOTH_WINDOWS, "days": data["days"],
            "window_size": WINDOW_SIZE, "stride": STRIDE, "n_ensemble": N_ENSEMBLE, "use_vhm": USE_VHM,
            "use_context_features": USE_CONTEXT_FEATURES, "hour_bin_hours": HOUR_BIN_HOURS,
            "epochs": [len(h["train"]) for h in hists], "best_val": [float(h["best_val"]) for h in hists],
            "n_params": int(n_params), "profile_start": data["days"]["train"][0], "observe_until": ""}
    with open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    fig, ax = plt.subplots(1, 2, figsize=(12, 4))
    for i, h in enumerate(hists):
        ax[0].plot(h["train"], label=f"member {i + 1}")
        ax[1].plot(h["val"], label=f"member {i + 1}")
    ax[0].set_title(f"{user}: training error (hidden-event guessing)"); ax[0].set_xlabel("epoch"); ax[0].legend()
    ax[1].set_title(f"{user}: validation surprisal (what the detector uses)"); ax[1].set_xlabel("epoch"); ax[1].legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "training_curve.png"), dpi=130)
    plt.show()
    return {"threshold": float(thr), "epochs": float(np.mean(meta["epochs"])), "seconds": time.time() - t0}

# ## Step 10 — Train the first user


FIRST_USER = LOCAL_USER if LOCAL_USER in USERS else USERS[0]
first_result = train_user(FIRST_USER)

# ## Step 11 — A much stricter evaluation


INJECT_KINDS = ("reorder", "rare_burst", "novel_burst", "time_shift")

class FrequencyBaseline:
    def __init__(self, voc):
        c = np.array(voc["key_count"], dtype=float)
        p = (c + 1.0) / (c.sum() + len(c))
        self.s = -np.log(p)
        self.s[UNK_ID] = self.s.max()
    def score(self, X):
        return self.s[X[:, 1:, CH_KEY]].mean(axis=1)

class BigramBaseline:
    def __init__(self, train_keys, voc, alpha=0.1):
        V = len(voc["key"]) + NUM_SPECIAL
        T = np.zeros((V, V))
        np.add.at(T, (train_keys[:-1], train_keys[1:]), 1.0)
        self.logp = np.log((T + alpha) / (T.sum(axis=1, keepdims=True) + alpha * V))
    def score(self, X):
        k = X[:, 1:, CH_KEY]
        return -self.logp[k[:, :-1], k[:, 1:]].mean(axis=1)

def inject_stream(feat, kind, voc, rng, n_inj=None, seg_len=None):
    n_inj, seg_len = n_inj or INJECT_SEGMENTS, seg_len or INJECT_LENGTH
    F2 = feat.copy()
    mask = np.zeros(len(feat), dtype=bool)
    slots = len(feat) // (2 * seg_len)
    if slots < 1:
        return F2, mask, []
    chosen = np.sort(rng.choice(slots, size=min(n_inj, slots), replace=False))
    attrs, counts = np.array(voc["key_attrs"]), np.array(voc["key_count"])
    seen = np.where(counts > 0)[0]
    rare = seen[np.argsort(counts[seen])[:max(1, len(seen) // 2)]]
    segs = []
    for k in chosen:
        s = int(2 * seg_len * k + rng.integers(0, seg_len)); e = s + seg_len
        n = e - s
        if kind == "reorder":
            F2[s:e, :CH_HOUR] = F2[s:e, :CH_HOUR][rng.permutation(n)]
        elif kind == "rare_burst":
            ids = rng.choice(rare, size=n)
            F2[s:e, CH_KEY] = ids
            F2[s:e, CH_PROV:CH_HOUR] = attrs[ids]
            F2[s:e, CH_GAP:] = 1
        elif kind == "novel_burst":
            F2[s:e, CH_KEY] = UNK_ID
            F2[s:e, CH_PROV] = UNK_ID
            F2[s:e, CH_GAP:] = 1
        elif kind == "time_shift":
            h = F2[s:e, CH_HOUR] - 1
            F2[s:e, CH_HOUR] = (h + N_HOUR_BINS // 2) % N_HOUR_BINS + 1
        else:
            raise ValueError(kind)
        mask[s:e] = True
        segs.append((s, e))
    return F2, mask, segs

def injected_fraction(starts, mask):
    c = np.cumsum(np.r_[0, mask.astype(int)])
    return (c[starts + WINDOW_SIZE] - c[starts]) / WINDOW_SIZE

def segments_found(segs, starts, flags):
    hit = 0
    for s, e in segs:
        near = (starts + WINDOW_SIZE > s) & (starts < e + (SMOOTH_WINDOWS - 1) * STRIDE)
        hit += int(bool(flags[near].any()))
    return hit, len(segs)

def safe_auc(neg, pos):
    if len(neg) == 0 or len(pos) == 0:
        return float("nan")
    y = np.r_[np.zeros(len(neg)), np.ones(len(pos))]
    return float(roc_auc_score(y, np.r_[neg, pos]))

def scorer_table(det, out, X, baselines):
    t = {"v1 hard-miss score": smooth(out["z"]["miss_rate"]),
         "surprisal_mean": smooth(out["z"]["surprisal_mean"]),
         "surprisal_topk": smooth(out["z"]["surprisal_topk"]),
         "hypersphere": smooth(out["z"]["hypersphere"]),
         "v2 combined (final)": out["smooth"]}
    for name, b in baselines.items():
        t[f"{name} baseline"] = smooth(b.score(X))
    return t

def evaluate_user(user, tag="", verbose=True):
    det = load_trained(model_path(user, tag))
    split = tuple(det.meta["days"][k] for k in ("train", "val", "test"))
    data = prepare_user(os.path.join(DATA_ROOT, user), split)
    te = data["test"]
    X, feat = te["X"], te["feat"]
    n_test_days = len(split[2])
    baselines = {"freq": FrequencyBaseline(det.voc), "bigram": BigramBaseline(data["train"]["feat"][:, CH_KEY], det.voc)}

    clean = det.score(X)
    eps = find_episodes(clean["flags"])
    clean_tab = scorer_table(det, clean, X, baselines)
    res = {"user": user, "tag": tag, "test_windows": len(X), "threshold": round(det.thr, 2),
           "window_false_alarm_%": round(100 * float(clean["flags"].mean()), 1),
           "alert_episodes_test": len(eps), "alerts_per_test_day": round(len(eps) / max(n_test_days, 1), 2)}

    rng = np.random.default_rng(SEED)
    abl = []
    for kind in INJECT_KINDS:
        if kind == "time_shift" and not USE_CONTEXT_FEATURES:
            continue
        pooled = {name: [] for name in clean_tab}
        flagged, found, total = [], 0, 0
        for _ in range(N_INJECT_REPEATS):
            F2, mask, segs = inject_stream(feat, kind, det.voc, rng)
            X2, starts2 = make_windows(F2)
            if len(X2) == 0 or not segs:
                continue
            out2 = det.score(X2)
            sel = injected_fraction(starts2, mask) >= 0.25
            for name, sc in scorer_table(det, out2, X2, baselines).items():
                pooled[name].append(sc[sel])
            flagged.append(out2["flags"][sel])
            h, t = segments_found(segs, starts2, out2["flags"])
            found += h; total += t
        for name in clean_tab:
            bad = np.concatenate(pooled[name]) if pooled[name] else np.zeros(0)
            abl.append({"kind": kind, "scorer": name, "AUC": round(safe_auc(clean_tab[name], bad), 3)})
        a = {r["scorer"]: r["AUC"] for r in abl if r["kind"] == kind}
        res[f"AUC_{kind}"] = a["v2 combined (final)"]
        res[f"AUC_{kind}_freq"] = a["freq baseline"]
        res[f"AUC_{kind}_bigram"] = a["bigram baseline"]
        res[f"segments_found_{kind}_%"] = round(100 * found / max(total, 1), 1)
        res[f"windows_flagged_{kind}_%"] = round(100 * float(np.concatenate(flagged).mean()), 1) if flagged else float("nan")
    abl = pd.DataFrame(abl)
    if verbose:
        for k, v in res.items():
            print(f"{k:32s}: {v}")
    return res, abl

first_eval, first_abl = evaluate_user(FIRST_USER)
print("\nAUC of every scorer on the SAME injected windows (higher = better, 0.5 = coin flip):")
first_abl.pivot(index="scorer", columns="kind", values="AUC")

def plot_test_scores(user, tag="", kind="rare_burst", save=True):
    det = load_trained(model_path(user, tag))
    split = tuple(det.meta["days"][k] for k in ("train", "val", "test"))
    data = prepare_user(os.path.join(DATA_ROOT, user), split)
    te = data["test"]
    clean = det.score(te["X"])
    F2, mask, segs = inject_stream(te["feat"], kind, det.voc, np.random.default_rng(SEED))
    X2, starts2 = make_windows(F2)
    inj = det.score(X2)
    fig, ax = plt.subplots(2, 1, figsize=(12, 6), sharey=True)
    ax[0].plot(clean["smooth"]); ax[0].axhline(det.thr, color="r", ls="--", label="alert level")
    ax[0].set_title(f"{user}: clean test days (every flagged window is a false alarm)"); ax[0].legend()
    ax[1].plot(inj["smooth"]); ax[1].axhline(det.thr, color="r", ls="--")
    for s, e in segs:
        ax[1].axvspan(max(0, (s - WINDOW_SIZE) / STRIDE), e / STRIDE, color="orange", alpha=0.3)
    ax[1].set_title(f"{user}: test days with injected '{kind}' segments (orange)")
    ax[1].set_xlabel("window number"); ax[0].set_ylabel("smoothed score"); ax[1].set_ylabel("smoothed score")
    plt.tight_layout()
    if save:
        os.makedirs(os.path.join(OUTPUT_ROOT, "figures"), exist_ok=True)
        plt.savefig(os.path.join(OUTPUT_ROOT, "figures", f"{user}{'_' + tag if tag else ''}_scores_{kind}.png"), dpi=130)
    plt.show()

plot_test_scores(FIRST_USER)

# ## Step 12 — Train and evaluate all users


summary, abl_all = [], []
for user in USERS:
    print("=" * 78)
    try:
        tr = train_user(user, verbose=False)
        ev, ab = evaluate_user(user, verbose=False)
        ev.update({"epochs": tr["epochs"], "train_seconds": round(tr["seconds"]), "note": ""})
        ab["user"] = user
        abl_all.append(ab)
    except Exception as err:
        print(f"SKIPPED {user}: {err}")
        ev = {"user": user, "note": str(err)}
    summary.append(ev)
summary_df = pd.DataFrame(summary)
os.makedirs(os.path.join(OUTPUT_ROOT, "results"), exist_ok=True)
summary_df.to_csv(os.path.join(OUTPUT_ROOT, "results", "summary_all_users_v2.csv"), index=False)
if abl_all:
    pd.concat(abl_all).to_csv(os.path.join(OUTPUT_ROOT, "results", "ablation_all_users_v2.csv"), index=False)
summary_df

if abl_all:
    A = pd.concat(abl_all)
    display_table = A.pivot_table(index="scorer", columns="kind", values="AUC", aggfunc="mean").round(3)
    display_table["mean"] = display_table.mean(axis=1).round(3)
    display_table.sort_values("mean", ascending=False)

# ## Step 13 (optional) — Rolling-origin evaluation: a more trustworthy false-alarm estimate


RUN_ROLLING = False

def make_rolling_splits(days, n_folds=3, n_val=2, n_test=2, min_train=5):
    splits = []
    for f in range(n_folds):
        end = len(days) - f * n_test
        tr, va, te = days[:end - n_test - n_val], days[end - n_test - n_val:end - n_test], days[end - n_test:end]
        if len(tr) >= min_train:
            splits.append((tr, va, te))
    return splits[::-1]

def rolling_evaluation(user):
    days = list_days(os.path.join(DATA_ROOT, user))
    rows = []
    for i, sp in enumerate(make_rolling_splits(days)):
        tag = f"fold{i + 1}"
        train_user(user, split=sp, tag=tag, verbose=False)
        res, _ = evaluate_user(user, tag=tag, verbose=False)
        rows.append(res)
    df = pd.DataFrame(rows)
    num = df.select_dtypes("number")
    print("\nmean over folds:\n", num.mean().round(3).to_string())
    print("\nstd over folds:\n", num.std().round(3).to_string())
    return df

if RUN_ROLLING:
    rolling_df = rolling_evaluation(FIRST_USER)
    rolling_df

# ## Step 14 — Cross-user comparison


ok_users = [u for u in USERS if os.path.exists(os.path.join(model_path(u), "model.pt"))]
auc = pd.DataFrame(np.nan, index=ok_users, columns=ok_users)
for owner in ok_users:
    det = load_trained(model_path(owner))
    split = tuple(det.meta["days"][k] for k in ("train", "val", "test"))
    own = det.score(prepare_user(os.path.join(DATA_ROOT, owner), split)["test"]["X"])["smooth"]
    for other in ok_users:
        if other == owner:
            continue
        Xo = prepare_new_logs(os.path.join(DATA_ROOT, other), det.voc)[0]
        auc.loc[owner, other] = safe_auc(own, det.score(Xo)["smooth"])
os.makedirs(os.path.join(OUTPUT_ROOT, "results"), exist_ok=True)
auc.round(3).to_csv(os.path.join(OUTPUT_ROOT, "results", "cross_user_auc_v2.csv"))
if len(ok_users) > 1:
    plt.figure(figsize=(7, 6))
    plt.imshow(np.ma.masked_invalid(auc.values), vmin=0.5, vmax=1.0, cmap="viridis")
    plt.colorbar(label="AUC")
    plt.xticks(range(len(ok_users)), ok_users, rotation=60); plt.yticks(range(len(ok_users)), ok_users)
    for i in range(len(ok_users)):
        for j in range(len(ok_users)):
            if i != j:
                plt.text(j, i, f"{auc.values[i, j]:.2f}", ha="center", va="center", color="white", fontsize=7)
    plt.xlabel("whose logs are scored"); plt.ylabel("whose model is used"); plt.title("Cross-user AUC (v2)")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_ROOT, "figures", "cross_user_auc_v2.png"), dpi=130)
    plt.show()
auc.round(3)

# ## Step 15 — E-mail alert


CONFIGURE_EMAIL = False

if CONFIGURE_EMAIL:
    import getpass
    os.environ["SMTP_HOST"] = "smtp.gmail.com"
    os.environ["SMTP_PORT"] = "587"
    os.environ["SMTP_USER"] = input("Sender e-mail address: ")
    os.environ["SMTP_PASS"] = getpass.getpass("App password (typing is hidden): ")
    os.environ["ALERT_TO"] = input("Send alerts to: ")

def send_alert(subject, body):
    needed = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "ALERT_TO"]
    missing = [v for v in needed if not os.environ.get(v)]
    if missing:
        print("[e-mail not configured - dry run. Missing: " + ", ".join(missing) + "]\n")
        print("Subject:", subject); print(body)
        return False
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, os.environ["SMTP_USER"], os.environ["ALERT_TO"]
    msg.set_content(body)
    try:
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=30) as server:
            server.starttls()
            server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
            server.send_message(msg)
        print("Alert e-mail sent.")
        return True
    except Exception as err:
        print("Could not send the e-mail:", err)
        return False

send_alert("LogBERT Local Guard - test", "This is only a test e-mail.")

# ## Step 16 — Detect unusual behaviour in NEW logs


REASON_TEXT = {"surprisal_mean": "an unusual order or combination of events",
               "surprisal_topk": "a few very unexpected events",
               "hypersphere": "an overall pattern unlike any normal period",
               "miss_rate": "events that were hard to predict"}

def describe_episode(det, out, a, b):
    if float(out["comps"]["unk_frac"][a:b + 1].mean()) >= 0.10:
        return "many event types that were never seen during training"
    z = {k: float(out["z"][k][a:b + 1].mean()) for k in det.which}
    return REASON_TEXT[max(z, key=z.get)]

def detect_new_logs(user, new_path, send_email=False, tag=""):
    det = load_trained(model_path(user, tag))
    X, starts, times, df, feat = prepare_new_logs(new_path, det.voc)
    if len(X) == 0:
        print(f"Not enough events for even one window (need at least {WINDOW_SIZE} after cleaning)."); return []
    out = det.score(X)
    episodes = find_episodes(out["flags"])
    print(f"Windows checked: {len(X)} | flagged windows: {int(out['flags'].sum())} | "
          f"never-seen event slots: {int((X[:, 1:, CH_KEY] == UNK_ID).sum())} | alert episodes: {len(episodes)}")
    if not episodes:
        print("Everything looks like normal behaviour. No e-mail sent."); return []
    until = det.meta.get("observe_until", "")
    observing = bool(until) and times[starts[episodes[0][0]]][:10] <= until
    lines = []
    for a, b in episodes[:5]:
        lines.append(f" - from {times[starts[a]]} (local time), {b - a + 1} windows in a row, highest score "
                     f"{out['smooth'][a:b + 1].max():.1f} (alert level {det.thr:.1f}); looks like: {describe_episode(det, out, a, b)}")
    body = ("LogBERT Local Guard noticed activity on this laptop that differs from its usual pattern.\n\n"
            + "\n".join(lines)
            + "\n\nIf this was you (for example you installed software), you can ignore this message. "
              "If you do not recognise the activity, please check your laptop and change your passwords."
              "\n\n(This e-mail contains no log details by design.)")
    if observing:
        print(f"profile was rebuilt recently (quiet period until {until}); logging only, no alert sent.")
        print("\n" + body)
        return episodes
    if send_email:
        send_alert("LogBERT Local Guard: unusual activity detected", body)
    else:
        print("\n" + body)
    return episodes

demo_dir = os.path.join(OUTPUT_ROOT, "demo_new_logs")
os.makedirs(demo_dir, exist_ok=True)
real = load_logs(os.path.join(DATA_ROOT, FIRST_USER))
last_days = sorted(real["day"].unique())[-2:]
cols = ["TimeCreated", "LogName", "EventID", "Level", "Provider"]
demo = real[real["day"].isin(last_days)].reindex(columns=cols)
zone = re.search(r"([+-]\d{2}:\d{2}|Z)$", real["TimeCreated"].iloc[-1])
zone = zone.group(1) if zone else ""
rng = np.random.default_rng(1)
fake = pd.DataFrame({
    "TimeCreated": [f"{last_days[-1]}T23:{i // 2:02d}:{(i % 2) * 30:02d}.0000000{zone}" for i in range(120)],
    "LogName": "System", "EventID": rng.integers(1000, 1030, 120), "Level": "Warning",
    "Provider": [f"Unknown-Service-{k}" for k in rng.integers(0, 6, 120)]})
demo.to_csv(os.path.join(demo_dir, "own_last_two_days.csv"), index=False)
pd.concat([demo, fake]).to_csv(os.path.join(demo_dir, "demo_new_logs.csv"), index=False)

print("--- 1) the user's own last two days (should be quiet; they are the test days) ---")
detect_new_logs(FIRST_USER, os.path.join(demo_dir, "own_last_two_days.csv"))
print("\n--- 2) the same two days plus 120 fabricated events (should raise an alert) ---")
detect_new_logs(FIRST_USER, os.path.join(demo_dir, "demo_new_logs.csv"))

# ## Step 17 — Keeping the threshold up to date


def recalibrate(user, recent_path, tag=""):
    det = load_trained(model_path(user, tag))
    X, starts, times, df, feat = prepare_new_logs(recent_path, det.voc)
    if len(X) < MIN_VAL_WINDOWS:
        print(f"{user}: only {len(X)} windows in the recent logs; threshold left unchanged")
        return det.thr
    comps = score_components(det.models, X)
    cal = fit_calibration(comps)
    z = {k: standardize(comps[k], cal[k]) for k in ALL_COMPONENTS}
    val_smooth = smooth(combine_z(z, det.which))
    n_days = pd.Series(times).str[:10].nunique()
    thr, thr_info = choose_threshold(val_smooth, n_days)
    update_meta(user, tag, calibration=cal, threshold=float(thr), threshold_info=thr_info)
    print(f"{user}: threshold refreshed from recent normal logs -> {thr:.2f} ({thr_info})")
    return thr

# ## Step 18 — Handling a user change on the same machine


def state_path(user):
    return os.path.join(OUTPUT_ROOT, "state", user + ".json")

def read_learning_since(user):
    if not os.path.exists(state_path(user)):
        return None
    with open(state_path(user), encoding="utf-8") as f:
        return json.load(f).get("learning_since")

def write_learning_since(user, day):
    os.makedirs(os.path.dirname(state_path(user)), exist_ok=True)
    with open(state_path(user), "w", encoding="utf-8") as f:
        json.dump({"learning_since": day}, f)

def clear_learning(user):
    if os.path.exists(state_path(user)):
        os.remove(state_path(user))

def live_dir(user):
    return os.path.join(OUTPUT_ROOT, "live", user)

def daily_flag_share(det, new_path):
    X, starts, times, df, feat = prepare_new_logs(new_path, det.voc)
    if len(X) == 0:
        return pd.Series(dtype=float)
    out = det.score(X)
    day = df["day"].to_numpy()[starts + WINDOW_SIZE - 1]
    table = pd.DataFrame({"day": day, "flag": out["flags"].astype(float)}).groupby("day")["flag"].agg(["mean", "size"])
    return table[table["size"] >= MIN_DAY_WINDOWS]["mean"]

def detect_profile_shift(user, new_path, tag=""):
    det = load_trained(model_path(user, tag))
    share = daily_flag_share(det, new_path)
    streak, first = 0, None
    for day, value in share.items():
        if value >= SHIFT_FLAG_SHARE:
            first = day if streak == 0 else first
            streak += 1
            if streak >= CHANGE_STREAK_DAYS:
                return True, share, first
        else:
            streak, first = 0, None
    return False, share, None

def archive_profile(user, tag=""):
    dst = os.path.join(OUTPUT_ROOT, "archive", f"{user}_{time.strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(dst, exist_ok=True)
    for name, src in (("model", model_path(user, tag)), ("data", os.path.join(DATA_ROOT, user))):
        if os.path.isdir(src):
            shutil.move(src, os.path.join(dst, name))
    print(f"old profile and logs of {user} archived to {dst}")
    return dst

def learn_profile(user, since_day):
    collect_logs(user, since_day=since_day)
    days = list_days(os.path.join(DATA_ROOT, user))
    if len(days) < RESET_LEARN_DAYS:
        print(f"{user}: learning the new behaviour, {len(days)} of {RESET_LEARN_DAYS} days collected; no alerts until the new profile is trained.")
        return "learning"
    train_user(user)
    until = (datetime.now() + timedelta(days=OBSERVATION_DAYS)).strftime("%Y-%m-%d")
    update_meta(user, observe_until=until)
    clear_learning(user)
    print(f"{user}: new profile trained; alerts stay quiet until {until}.")
    return "retrained"

def reset_profile(user, since_day, tag=""):
    archive_profile(user, tag)
    write_learning_since(user, since_day)
    return learn_profile(user, since_day)

def monitor(user, new_path=None, tag="", send_email=False):
    if new_path is None:
        new_path = live_dir(user)
        collect_logs(user, days=CHECK_DAYS, out_dir=new_path)
    changed, share, first = detect_profile_shift(user, new_path, tag)
    if len(share):
        print("share of flagged windows per day:\n" + share.round(2).to_string())
    if changed:
        print(f"{user}: behaviour has stayed far from the usual pattern for {CHANGE_STREAK_DAYS} days in a row (since {first}).")
        print("this looks like a different person on the same account or machine, not a short incident.")
        if AUTO_RESET:
            print(f"starting a fresh profile from {first}; no alerts while it learns, then quiet for {OBSERVATION_DAYS} more days.")
            return reset_profile(user, first, tag)
        print("AUTO_RESET is off, so the old profile is kept.")
    return detect_new_logs(user, new_path, send_email=send_email, tag=tag)

# ## Step 19 — Run the guard on this machine


def run_guard(user=None, send_email=False):
    user = user or LOCAL_USER
    since = read_learning_since(user)
    if since is not None:
        return learn_profile(user, since)
    if not os.path.exists(os.path.join(model_path(user), "model.pt")):
        if not has_csv(os.path.join(DATA_ROOT, user)):
            collect_logs(user)
        train_user(user)
        return "trained"
    return monitor(user, send_email=send_email)

def watch(user=None, every_minutes=None, send_email=False):
    every = every_minutes or WATCH_MINUTES
    while True:
        print("=" * 60, time.strftime("%Y-%m-%d %H:%M:%S"))
        try:
            run_guard(user, send_email=send_email)
        except Exception as err:
            print("guard run failed:", err)
        time.sleep(every * 60)

if platform.system() == "Windows":
    run_guard()