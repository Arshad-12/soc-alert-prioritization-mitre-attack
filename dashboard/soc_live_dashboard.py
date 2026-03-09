# ─────────────────────────────────────────────────────────
#  Semantic Context-Aware SOC Alert Prioritization
#  Live Upload & Real-Time Processing Dashboard v2
#  (Flask-based upload for Linux/Firefox compatibility)
# ─────────────────────────────────────────────────────────

import os, io, time, base64, pickle, threading, warnings
import numpy as np
import pandas as pd
import faiss
from sentence_transformers import SentenceTransformer
import dash
from dash import dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from flask import request, jsonify
warnings.filterwarnings('ignore')

# ── Paths ─────────────────────────────────────────────────
DATA_DIR   = '/home/arshad/Network-project/data/'
UPLOAD_DIR = '/home/arshad/Network-project/uploads/'
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Load ML Assets ────────────────────────────────────────
print("⏳ Loading ML assets...")
with open(DATA_DIR + 'tactic_classifier.pkl', 'rb') as f:
    clf_data     = pickle.load(f)
clf          = clf_data['model']
le           = clf_data['encoder']
feature_cols = clf_data['features']

with open(DATA_DIR + 'mitre_techniques.pkl', 'rb') as f:
    techniques = pickle.load(f)

index                = faiss.read_index(DATA_DIR + 'mitre_faiss_l12.index')
technique_embeddings = np.load(DATA_DIR + 'mitre_embeddings_l12.npy')

print("⏳ Loading embedding model...")
emb_model = SentenceTransformer('sentence-transformers/all-MiniLM-L12-v2')
print("✅ All assets loaded!")

# ── Shared State ──────────────────────────────────────────
uploaded_df    = None
uploaded_fname = None

# ── Constants ─────────────────────────────────────────────
TIER_COLORS = {
    'CRITICAL':'#d32f2f', 'HIGH':'#f57c00',
    'MEDIUM':'#fbc02d',   'LOW':'#388e3c',
    'BENIGN':'#9e9e9e',
}
TIER_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','BENIGN']

REQUIRED_COLS = [
    'Destination Port','Flow Duration',
    'Total Fwd Packets','Total Backward Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean',
    'Packet Length Mean','Packet Length Std',
    'Flow Bytes/s','Flow Packets/s',
    'Fwd Packets/s','Bwd Packets/s',
    'Flow IAT Mean','Flow IAT Std',
    'SYN Flag Count','ACK Flag Count',
    'FIN Flag Count','RST Flag Count',
    'PSH Flag Count','URG Flag Count',
    'Init_Win_bytes_forward','Init_Win_bytes_backward',
    'Active Mean','Idle Mean',
    'Down/Up Ratio','Average Packet Size'
]

cvss_tactic_scores = {
    'impact':0.950,              'command-and-control':0.900,
    'exfiltration':0.867,        'lateral-movement':0.850,
    'privilege-escalation':0.800,'credential-access':0.750,
    'persistence':0.750,         'initial-access':0.700,
    'execution':0.650,           'defense-evasion':0.600,
    'collection':0.600,          'discovery':0.400,
    'reconnaissance':0.350,      'resource-development':0.300,
    'benign':0.0,                'None':0.0,
}
asset_criticality = {
    22:1.00,3389:1.00,23:0.95,445:0.95,
    1433:0.90,3306:0.90,5900:0.85,21:0.80,
    25:0.75,53:0.75,443:0.70,80:0.65,
    8080:0.60,110:0.55,143:0.55,
}
tactic_min_tier = {
    'command-and-control':'HIGH','impact':'HIGH',
    'lateral-movement':'HIGH',   'exfiltration':'HIGH',
    'credential-access':'MEDIUM','initial-access':'MEDIUM',
    'privilege-escalation':'MEDIUM','persistence':'MEDIUM',
    'execution':'MEDIUM',        'discovery':'LOW',
    'reconnaissance':'LOW',
}
tier_rank      = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'BENIGN':0}
tier_from_rank = {4:'CRITICAL',3:'HIGH',2:'MEDIUM',1:'LOW',0:'BENIGN'}

# ── Pipeline Functions ────────────────────────────────────
def get_parent_id(tid):
    return tid.split('.')[0] if isinstance(tid, str) and '.' in tid else tid

def get_asset_crit(port):
    try:    return asset_criticality.get(int(port), 0.50)
    except: return 0.50

def generate_alert_text(row):
    dst_port  = int(row.get('Destination Port',0))
    syn       = int(row.get('SYN Flag Count',0))
    ack       = int(row.get('ACK Flag Count',0))
    fin       = int(row.get('FIN Flag Count',0))
    rst       = int(row.get('RST Flag Count',0))
    psh       = int(row.get('PSH Flag Count',0))
    fwd_pkts  = int(row.get('Total Fwd Packets',0))
    bwd_pkts  = int(row.get('Total Backward Packets',0))
    pkt_rate  = float(row.get('Flow Packets/s',0))
    pkt_len   = float(row.get('Packet Length Mean',0))
    byte_rate = float(row.get('Flow Bytes/s',0))
    duration  = float(row.get('Flow Duration',0))/1e6
    iat_mean  = float(row.get('Flow IAT Mean',0))
    flow_pkts = fwd_pkts + bwd_pkts
    fwd_bwd   = fwd_pkts / (bwd_pkts+1)
    port_ctx  = {
        80:'HTTP web server',443:'HTTPS web server',
        22:'SSH remote access',21:'FTP file transfer',
        23:'Telnet service',3389:'RDP remote desktop',
        53:'DNS resolver',3306:'MySQL database',
        8080:'HTTP proxy',445:'SMB file sharing',
    }
    port_desc = port_ctx.get(dst_port, f'port {dst_port}')
    flags     = [n for f,n in [(syn,'SYN'),(ack,'ACK'),
                               (fin,'FIN'),(rst,'RST'),
                               (psh,'PSH')] if f]
    flag_str  = ', '.join(flags) if flags else 'no TCP flags'
    if pkt_len < 20 and flow_pkts <= 3 and pkt_rate > 1000:
        return (f"Network reconnaissance probing {port_desc}. "
                f"Tiny {pkt_len:.1f}B probes at {pkt_rate:.0f} pkt/s.")
    if dst_port in [21,22,23,3389,5900]:
        svc = {21:'FTP',22:'SSH',23:'Telnet',
               3389:'RDP',5900:'VNC'}.get(dst_port,'remote')
        return (f"Credential brute force against {svc}. "
                f"{fwd_pkts} fwd/{bwd_pkts} bwd pkts, {flag_str}.")
    if pkt_len > 400 and pkt_rate > 50 and fwd_bwd > 2:
        return (f"DDoS flood targeting {port_desc}. "
                f"{pkt_len:.0f}B pkts at {pkt_rate:.0f} pkt/s.")
    if pkt_rate > 200 and fwd_bwd > 3:
        return (f"DoS flood at {port_desc}. "
                f"{pkt_rate:.0f} pkt/s overwhelming target.")
    if iat_mean > 100000 and bwd_pkts > 0 and pkt_len < 200:
        return (f"Botnet C2 beaconing via {port_desc}. "
                f"Periodic {pkt_len:.1f}B packets every "
                f"{iat_mean/1000:.0f}ms.")
    if dst_port in [80,443,8080] and psh > 0:
        return (f"Web attack on {port_desc}. "
                f"{flow_pkts} requests, {pkt_len:.0f}B payloads.")
    return (f"Network flow to {port_desc} with {flag_str}. "
            f"{fwd_pkts} fwd/{bwd_pkts} bwd at {pkt_rate:.1f} pkt/s.")

def process_row(row):
    alert_text  = generate_alert_text(row)
    X           = pd.DataFrame([{c: row.get(c,0) for c in feature_cols}])\
                    .replace([np.inf,-np.inf],np.nan).fillna(0)
    pred_tactic = le.inverse_transform(clf.predict(X))[0]
    alert_emb   = emb_model.encode([alert_text], convert_to_numpy=True)
    faiss.normalize_L2(alert_emb)
    tac_idxs    = [j for j,t in enumerate(techniques)
                   if pred_tactic in t['tactics']]
    if len(tac_idxs) >= 3:
        sub_embs  = technique_embeddings[tac_idxs]
        sims      = (alert_emb @ sub_embs.T)[0]
        top3_loc  = np.argsort(sims)[::-1][:3]
        top3_idx  = [tac_idxs[k] for k in top3_loc]
        top3_sims = sims[top3_loc]
    else:
        s,idx     = index.search(alert_emb,3)
        top3_idx  = idx[0].tolist()
        top3_sims = s[0]
    tech1      = techniques[top3_idx[0]]
    conf1      = float(top3_sims[0])
    conf2      = float(top3_sims[1])
    conf3      = float(top3_sims[2])
    combined   = 0.6*conf1 + 0.3*conf2 + 0.1*conf3
    correction = (1.00 if combined>=0.80 else
                  0.85 if combined>=0.50 else
                  0.70 if combined>=0.30 else 0.50)
    sev        = cvss_tactic_scores.get(pred_tactic,0.30)
    crit       = get_asset_crit(row.get('Destination Port',0))
    base_score = 0.40*sev + 0.30*combined + 0.20*crit + 0.10*0.5
    risk_score = round(base_score * correction * 100, 2)
    if risk_score >= 58:   score_tier = 'CRITICAL'
    elif risk_score >= 50: score_tier = 'HIGH'
    elif risk_score >= 42: score_tier = 'MEDIUM'
    elif risk_score > 0:   score_tier = 'LOW'
    else:                  score_tier = 'BENIGN'
    tactic_tier = tactic_min_tier.get(pred_tactic,'LOW')
    final_rank  = max(tier_rank[score_tier],tier_rank[tactic_tier])
    return {
        'alert_text':  alert_text[:80]+'...',
        'pred_tactic': pred_tactic,
        'technique':   get_parent_id(tech1['technique_id']),
        'tech_name':   tech1['technique_name'],
        'confidence':  round(conf1,3),
        'risk_score':  risk_score,
        'risk_tier':   tier_from_rank[final_rank],
        'dst_port':    int(row.get('Destination Port',0)),
    }

# ── Dash App ──────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    title='SOC Live Feed'
)
server = app.server  # expose Flask server

# ── Flask upload endpoint ─────────────────────────────────
@server.route('/upload', methods=['POST'])
def upload_file():
    global uploaded_df, uploaded_fname
    if 'file' not in request.files:
        return jsonify({'status':'error','msg':'No file'}), 400
    f = request.files['file']
    if not f.filename.endswith('.csv'):
        return jsonify({'status':'error','msg':'CSV only'}), 400
    try:
        df = pd.read_csv(f)
        df.columns = df.columns.str.strip()
        missing = [c for c in REQUIRED_COLS if c not in df.columns]
        if missing:
            return jsonify({
                'status':'error',
                'msg':f"Missing: {', '.join(missing[:3])}"
            }), 400
        df           = df.replace([np.inf,-np.inf],np.nan).fillna(0)
        uploaded_df  = df.head(200)
        uploaded_fname = f.filename
        return jsonify({
            'status':'ok',
            'rows': len(uploaded_df),
            'filename': f.filename
        })
    except Exception as e:
        return jsonify({'status':'error','msg':str(e)}), 500

@server.route('/status', methods=['GET'])
def get_status():
    if uploaded_df is None:
        return jsonify({'status':'no_file'})
    return jsonify({
        'status':'ready',
        'rows':len(uploaded_df),
        'filename':uploaded_fname
    })

# ── Layout ────────────────────────────────────────────────
app.layout = dbc.Container([

    dcc.Store(id='processed-rows', storage_type='memory', data=[]),
    dcc.Store(id='row-pointer',    storage_type='memory', data=0),
    dcc.Store(id='is-running',     storage_type='memory', data=False),
    dcc.Store(id='file-ready',     storage_type='memory', data=False),

    dcc.Interval(id='interval',    interval=500,
                 n_intervals=0,    disabled=True),
    dcc.Interval(id='poll-upload', interval=1000,
                 n_intervals=0,    disabled=False),

    # Header
    dbc.Row([
        dbc.Col([
            html.H2("🛡️ SOC Live Alert Feed",
                    style={'color':'#fff','margin':'0',
                           'fontWeight':'bold'}),
            html.P("Upload network traffic CSV → Real-time MITRE ATT&CK mapping",
                   style={'color':'#aaa','margin':'0','fontSize':'13px'}),
        ], width=8),
        dbc.Col([
            html.Div([
                html.Span(id='live-indicator', children="⚪ IDLE",
                          style={'fontWeight':'bold','fontSize':'14px',
                                 'color':'#aaa'}),
                html.Br(),
                html.Span(id='progress-text', children="No file loaded",
                          style={'color':'#aaa','fontSize':'11px'}),
            ], style={'textAlign':'right'})
        ], width=4),
    ], style={'backgroundColor':'#12121f','padding':'16px 24px',
              'marginBottom':'16px','borderBottom':'1px solid #333',
              'borderRadius':'8px'}),

    # Upload area — plain HTML form (works on all browsers)
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("📁 Upload CSV File",
                            style={'color':'#aaa','fontSize':'12px',
                                   'marginBottom':'8px'}),
                    html.Div([
                        dcc.Upload(
                            id='file-input',
                            children=html.Div([
                                html.Span("📁 Click to select CSV file",
                                          style={'color':'#ddd',
                                                 'fontSize':'13px'}),
                            ]),
                            style={
                                'width':'100%','padding':'12px',
                                'borderWidth':'2px','borderStyle':'dashed',
                                'borderRadius':'6px','borderColor':'#555',
                                'backgroundColor':'#2a2a3e',
                                'cursor':'pointer','marginBottom':'8px',
                                'textAlign':'center',
                            },
                            accept='.csv',
                            multiple=False,
                        ),
                        dbc.Button(
                            '⬆️ Upload File', id='upload-btn',
                            color='primary', size='sm',
                            style={'marginTop':'4px'}
                        ),
                    ], id='upload-form'),
                    html.Div(id='upload-status',
                             style={'color':'#aaa','fontSize':'12px',
                                    'marginTop':'8px'}),
                ])
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'}),
        ], width=8),

        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("⚙️ Processing Speed",
                            style={'color':'#aaa','fontSize':'12px'}),
                    dcc.Slider(
                        id='speed-slider',
                        min=100, max=2000, step=100, value=500,
                        marks={100:'0.1s',500:'0.5s',
                               1000:'1s',2000:'2s'},
                    ),
                    html.Br(),
                    dbc.Row([
                        dbc.Col(dbc.Button(
                            "▶ Start", id='start-btn',
                            color='success', size='sm',
                            disabled=True, className='w-100'),
                        width=4),
                        dbc.Col(dbc.Button(
                            "⏸ Pause", id='pause-btn',
                            color='warning', size='sm',
                            disabled=True, className='w-100'),
                        width=4),
                        dbc.Col(dbc.Button(
                            "🔄 Reset", id='reset-btn',
                            color='danger', size='sm',
                            disabled=True, className='w-100'),
                        width=4),
                    ]),
                ])
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=4),
    ], className='mb-3'),

    # Stat cards
    dbc.Row([
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-processed', children='0',
                    style={'color':'#2196f3','margin':'0',
                           'fontWeight':'bold'}),
            html.P("Processed",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-critical', children='0',
                    style={'color':'#d32f2f','margin':'0',
                           'fontWeight':'bold'}),
            html.P("🔴 Critical",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-high', children='0',
                    style={'color':'#f57c00','margin':'0',
                           'fontWeight':'bold'}),
            html.P("🟠 High",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-medium', children='0',
                    style={'color':'#fbc02d','margin':'0',
                           'fontWeight':'bold'}),
            html.P("🟡 Medium",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-low', children='0',
                    style={'color':'#388e3c','margin':'0',
                           'fontWeight':'bold'}),
            html.P("🟢 Low",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4(id='stat-avg-score', children='0.0',
                    style={'color':'#9c27b0','margin':'0',
                           'fontWeight':'bold'}),
            html.P("Avg Risk",style={'color':'#aaa',
                   'margin':'0','fontSize':'11px'})
        ])),width=2),
    ], className='mb-3'),

    # Charts
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("📈 Live Risk Score Feed",
                               style={'color':'#fff',
                                      'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dcc.Graph(id='live-score-chart',
                              style={'height':'220px'})
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("🥧 Tier Distribution",
                               style={'color':'#fff',
                                      'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dcc.Graph(id='live-tier-pie',
                              style={'height':'220px'})
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=4),
    ], className='mb-3'),

    # Live table
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Span("🚨 Live Alert Feed  ",
                              style={'color':'#fff'}),
                    html.Span(id='table-status',
                              style={'color':'#aaa','fontSize':'12px'})
                ], style={'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dash_table.DataTable(
                        id='live-table',
                        columns=[
                            {'name':'#',          'id':'row_num'},
                            {'name':'Tactic',     'id':'pred_tactic'},
                            {'name':'Technique',  'id':'tech_name'},
                            {'name':'Score',      'id':'risk_score'},
                            {'name':'Tier',       'id':'risk_tier'},
                            {'name':'Conf',       'id':'confidence'},
                            {'name':'Port',       'id':'dst_port'},
                            {'name':'Alert',      'id':'alert_text'},
                        ],
                        data=[],
                        page_size=10,
                        sort_action='native',
                        style_table={'overflowX':'auto',
                                     'backgroundColor':'#1e1e2e'},
                        style_header={
                            'backgroundColor':'#12121f',
                            'color':'#fff','fontWeight':'bold',
                            'border':'1px solid #333','fontSize':'11px'
                        },
                        style_cell={
                            'backgroundColor':'#1e1e2e','color':'#ddd',
                            'border':'1px solid #2a2a3e','fontSize':'11px',
                            'padding':'6px','textAlign':'left',
                            'maxWidth':'200px','overflow':'hidden',
                            'textOverflow':'ellipsis',
                        },
                        style_data_conditional=[
                            {'if':{'filter_query':
                                   '{risk_tier} = "CRITICAL"'},
                             'backgroundColor':'#3d1a1a',
                             'color':'#ff6b6b','fontWeight':'bold'},
                            {'if':{'filter_query':
                                   '{risk_tier} = "HIGH"'},
                             'backgroundColor':'#3d2a1a',
                             'color':'#ffa94d'},
                            {'if':{'filter_query':
                                   '{risk_tier} = "MEDIUM"'},
                             'backgroundColor':'#3d3a1a',
                             'color':'#ffd43b'},
                            {'if':{'filter_query':
                                   '{risk_tier} = "LOW"'},
                             'backgroundColor':'#1a3d1a',
                             'color':'#69db7c'},
                        ],
                        sort_by=[{'column_id':'risk_score',
                                  'direction':'desc'}],
                    )
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=12),
    ]),

    # JS for file upload (handles Firefox)
    html.Script('''
        document.addEventListener("DOMContentLoaded", function() {
            function doUpload() {
                var input = document.getElementById("file-input");
                if (!input || !input.files || input.files.length === 0) {
                    alert("Please select a CSV file first.");
                    return;
                }
                var formData = new FormData();
                formData.append("file", input.files[0]);
                var status = document.getElementById("upload-status");
                if (status) status.innerText = "⏳ Uploading...";
                fetch("/upload", {method:"POST", body:formData})
                    .then(r => r.json())
                    .then(data => {
                        if (status) {
                            if (data.status === "ok") {
                                status.innerText = "✅ Loaded: "
                                    + data.filename
                                    + " (" + data.rows + " rows)";
                                status.style.color = "#4caf50";
                            } else {
                                status.innerText = "❌ " + data.msg;
                                status.style.color = "#f44336";
                            }
                        }
                    })
                    .catch(e => {
                        if (status) status.innerText = "❌ Upload failed";
                    });
            }
            document.addEventListener("click", function(e) {
                if (e.target && e.target.id === "upload-btn") {
                    doUpload();
                }
            });
        });
    '''),

], fluid=True,
   style={'backgroundColor':'#12121f',
          'minHeight':'100vh','padding':'16px'})


# ── Callbacks ─────────────────────────────────────────────

@app.callback(
    Output('interval','interval'),
    Input('speed-slider','value')
)
def update_speed(value):
    return value


@app.callback(
    Output('file-ready','data'),
    Output('start-btn','disabled'),
    Output('reset-btn','disabled'),
    Input('poll-upload','n_intervals'),
    State('file-ready','data'),
    prevent_initial_call=True
)
def poll_upload_status(n, already_ready):
    if uploaded_df is not None:
        return True, False, False
    return False, True, True


@app.callback(
    Output('interval','disabled'),
    Output('start-btn','disabled',  allow_duplicate=True),
    Output('pause-btn','disabled'),
    Output('row-pointer','data'),
    Output('processed-rows','data', allow_duplicate=True),
    Input('start-btn','n_clicks'),
    Input('pause-btn','n_clicks'),
    Input('reset-btn','n_clicks'),
    State('interval','disabled'),
    State('file-ready','data'),
    prevent_initial_call=True
)
def control_buttons(start, pause, reset, is_disabled, file_ready):
    from dash import ctx
    t = ctx.triggered_id
    if t == 'start-btn':
        return False, True, False, dash.no_update, dash.no_update
    elif t == 'pause-btn':
        return True, False, True, dash.no_update, dash.no_update
    elif t == 'reset-btn':
        return True, False if file_ready else True, \
               True, 0, []
    return (is_disabled, dash.no_update, dash.no_update,
            dash.no_update, dash.no_update)


@app.callback(
    Output('processed-rows','data'),
    Output('row-pointer','data',       allow_duplicate=True),
    Output('interval','disabled',      allow_duplicate=True),
    Output('live-indicator','children'),
    Output('live-indicator','style'),
    Output('progress-text','children'),
    Input('interval','n_intervals'),
    State('row-pointer','data'),
    State('processed-rows','data'),
    prevent_initial_call=True
)
def process_next_row(n, pointer, processed_rows):
    global uploaded_df
    if uploaded_df is None:
        return (processed_rows, pointer, True,
                "⚪ IDLE",
                {'color':'#aaa','fontWeight':'bold','fontSize':'14px'},
                "No file loaded")

    total = len(uploaded_df)
    if pointer >= total:
        return (processed_rows, pointer, True,
                "✅ COMPLETE",
                {'color':'#4caf50','fontWeight':'bold','fontSize':'14px'},
                f"Processed all {total} rows")
    try:
        row    = uploaded_df.iloc[pointer].to_dict()
        result = process_row(row)
        result['row_num'] = pointer + 1
        new_rows = [result] + (processed_rows or [])
        new_rows = new_rows[:200]
        progress = (f"Processing row {pointer+1} of {total} "
                    f"({(pointer+1)/total*100:.0f}%)")
        return (new_rows, pointer+1, False,
                "🔴 LIVE",
                {'color':'#f44336','fontWeight':'bold','fontSize':'14px'},
                progress)
    except Exception as e:
        return (processed_rows, pointer+1, False,
                "🔴 LIVE",
                {'color':'#f44336','fontWeight':'bold','fontSize':'14px'},
                f"Row {pointer+1} error: {str(e)[:40]}")


@app.callback(
    Output('live-table','data'),
    Output('stat-processed','children'),
    Output('stat-critical','children'),
    Output('stat-high','children'),
    Output('stat-medium','children'),
    Output('stat-low','children'),
    Output('stat-avg-score','children'),
    Output('live-score-chart','figure'),
    Output('live-tier-pie','figure'),
    Output('table-status','children'),
    Input('processed-rows','data'),
    prevent_initial_call=True
)
def update_ui(processed_rows):
    empty_fig = go.Figure()
    empty_fig.update_layout(
        paper_bgcolor='#1e1e2e', plot_bgcolor='#1e1e2e',
        font_color='#ddd', margin=dict(l=20,r=20,t=20,b=20))

    if not processed_rows:
        return ([],  '0','0','0','0','0','0.0',
                empty_fig, empty_fig, '')

    rows_df    = pd.DataFrame(processed_rows)
    n_total    = len(rows_df)
    n_critical = (rows_df['risk_tier']=='CRITICAL').sum()
    n_high     = (rows_df['risk_tier']=='HIGH').sum()
    n_medium   = (rows_df['risk_tier']=='MEDIUM').sum()
    n_low      = (rows_df['risk_tier']=='LOW').sum()
    avg_score  = rows_df['risk_score'].mean()

    display    = rows_df.head(50).iloc[::-1].reset_index(drop=True)
    fig_score  = go.Figure()
    for tier in TIER_ORDER:
        mask = display['risk_tier'] == tier
        if mask.any():
            fig_score.add_trace(go.Scatter(
                x=display[mask].index,
                y=display[mask]['risk_score'],
                mode='markers', name=tier,
                marker=dict(color=TIER_COLORS[tier],size=8)
            ))
    fig_score.update_layout(
        paper_bgcolor='#1e1e2e', plot_bgcolor='#1e1e2e',
        font_color='#ddd', margin=dict(l=40,r=20,t=10,b=30),
        legend=dict(orientation='h',y=1.15),
        xaxis=dict(gridcolor='#333',title='Recent Alerts'),
        yaxis=dict(gridcolor='#333',title='Risk Score',range=[0,100]),
    )
    fig_score.add_hline(y=58,line_dash='dash',
                        line_color='#d32f2f',opacity=0.5)
    fig_score.add_hline(y=50,line_dash='dash',
                        line_color='#f57c00',opacity=0.5)

    tier_counts = rows_df['risk_tier'].value_counts()
    fig_pie     = go.Figure(go.Pie(
        labels=tier_counts.index, values=tier_counts.values,
        marker_colors=[TIER_COLORS.get(t,'#999')
                       for t in tier_counts.index],
        hole=0.4, textinfo='percent+label', textfont_size=10,
    ))
    fig_pie.update_layout(
        paper_bgcolor='#1e1e2e', font_color='#ddd',
        margin=dict(l=10,r=10,t=10,b=10), showlegend=False)

    return (processed_rows[:100],
            str(n_total), str(n_critical), str(n_high),
            str(n_medium), str(n_low), f"{avg_score:.1f}",
            fig_score, fig_pie,
            f"Showing {min(n_total,100)} most recent alerts")

@app.callback(
    Output('upload-status','children'),
    Input('upload-btn','n_clicks'),
    State('file-input','contents'),
    State('file-input','filename'),
    prevent_initial_call=True
)
def handle_upload(n_clicks, contents, filename):
    global uploaded_df, uploaded_fname
    if not contents:
        return "❌ Please select a file first"
    try:
        content_type, content_string = contents.split(',')
        decoded      = base64.b64decode(content_string)
        df           = pd.read_csv(io.StringIO(decoded.decode('utf-8')))
        df.columns   = df.columns.str.strip()
        missing      = [c for c in REQUIRED_COLS if c not in df.columns]
        if missing:
            return f"❌ Missing columns: {', '.join(missing[:3])}"
        df           = df.replace([np.inf,-np.inf],np.nan).fillna(0)
        uploaded_df  = df.head(200)
        uploaded_fname = filename
        return f"✅ Loaded: {filename} ({len(uploaded_df)} rows) — Press ▶ Start!"
    except Exception as e:
        return f"❌ Error: {str(e)[:60]}"

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8051)
