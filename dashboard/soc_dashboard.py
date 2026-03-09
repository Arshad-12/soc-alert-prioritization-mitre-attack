# ─────────────────────────────────────────────────────────
#  Semantic Context-Aware SOC Alert Prioritization
#  MITRE ATT&CK Aligned Dashboard
# ─────────────────────────────────────────────────────────

import pandas as pd
import numpy as np
import dash
from dash import dcc, html, dash_table, Input, Output, callback
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

# ── Load Data ────────────────────────────────────────────
print("⏳ Loading risk-scored dataset...")
df = pd.read_csv('/home/arshad/Network-project/data/final_risk_scored.csv',
                 low_memory=False)

df['MITRE_Tactic']    = df['MITRE_Tactic'].fillna('None')
df['MITRE_Technique'] = df['MITRE_Technique'].fillna('None')
df['MITRE_Tech_Name'] = df['MITRE_Tech_Name'].fillna('None')
df['risk_score']      = df['risk_score'].fillna(0).round(2)

# Assign timestamps (simulate real-time SOC feed)
random.seed(42)
base_time = datetime(2024, 1, 15, 8, 0, 0)
timestamps = [base_time + timedelta(seconds=random.randint(0, 86400))
              for _ in range(len(df))]
df['timestamp'] = sorted(timestamps)
df['time_str']  = df['timestamp'].dt.strftime('%H:%M:%S')

# Tier colors
TIER_COLORS = {
    'CRITICAL': '#d32f2f',
    'HIGH':     '#f57c00',
    'MEDIUM':   '#fbc02d',
    'LOW':      '#388e3c',
    'BENIGN':   '#9e9e9e',
}

TIER_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN']

print(f"✅ Loaded {len(df):,} alerts")
print(f"✅ Starting dashboard...")

# ── App Layout ───────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    title='SOC Alert Dashboard'
)

# ── Helper: Stat Card ────────────────────────────────────
def stat_card(title, value, color, icon):
    return dbc.Card([
        dbc.CardBody([
            html.Div([
                html.Span(icon, style={'fontSize':'28px'}),
                html.Div([
                    html.H3(value, style={
                        'color': color, 'margin': '0',
                        'fontWeight': 'bold'
                    }),
                    html.P(title, style={
                        'color': '#aaa', 'margin': '0',
                        'fontSize': '12px'
                    }),
                ], style={'marginLeft': '12px'})
            ], style={'display':'flex','alignItems':'center'})
        ])
    ], style={
        'backgroundColor': '#1e1e2e',
        'border': f'1px solid {color}',
        'borderRadius': '8px',
    })

# ── Layout ───────────────────────────────────────────────
app.layout = dbc.Container([

    # Header
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H2("🛡️ SOC Alert Prioritization Dashboard",
                        style={'color':'#fff','margin':'0',
                               'fontWeight':'bold'}),
                html.P("Semantic Context-Aware MITRE ATT&CK Aligned System",
                       style={'color':'#aaa','margin':'0','fontSize':'13px'}),
            ]),
        ], width=8),
        dbc.Col([
            html.Div([
                html.Span("🟢 LIVE", style={
                    'color':'#4caf50','fontWeight':'bold',
                    'fontSize':'14px'
                }),
                html.Br(),
                html.Span(datetime.now().strftime('%Y-%m-%d'),
                          style={'color':'#aaa','fontSize':'12px'}),
            ], style={'textAlign':'right'})
        ], width=4),
    ], style={
        'backgroundColor':'#12121f',
        'padding':'16px 24px',
        'marginBottom':'16px',
        'borderBottom':'1px solid #333',
        'borderRadius':'8px'
    }),

    # Stat Cards
    dbc.Row([
        dbc.Col(stat_card(
            "Total Alerts",
            f"{len(df[df['Label']!='BENIGN']):,}",
            "#2196f3", "📋"
        ), width=2),
        dbc.Col(stat_card(
            "Critical",
            f"{len(df[df['risk_tier']=='CRITICAL']):,}",
            "#d32f2f", "🔴"
        ), width=2),
        dbc.Col(stat_card(
            "High",
            f"{len(df[df['risk_tier']=='HIGH']):,}",
            "#f57c00", "🟠"
        ), width=2),
        dbc.Col(stat_card(
            "Medium",
            f"{len(df[df['risk_tier']=='MEDIUM']):,}",
            "#fbc02d", "🟡"
        ), width=2),
        dbc.Col(stat_card(
            "Low",
            f"{len(df[df['risk_tier']=='LOW']):,}",
            "#388e3c", "🟢"
        ), width=2),
        dbc.Col(stat_card(
            "Avg Risk Score",
            f"{df[df['Label']!='BENIGN']['risk_score'].mean():.1f}",
            "#9c27b0", "📊"
        ), width=2),
    ], className="mb-3"),

    # Filters
    dbc.Row([
        dbc.Col([
            html.Label("Filter by Risk Tier",
                       style={'color':'#aaa','fontSize':'12px'}),
            dcc.Dropdown(
                id='tier-filter',
                options=[{'label': t, 'value': t} for t in TIER_ORDER],
                value=None, multi=True,
                placeholder="All Tiers",
                style={'backgroundColor':'#1e1e2e','color':'#000'}
            )
        ], width=3),
        dbc.Col([
            html.Label("Filter by Attack Type",
                       style={'color':'#aaa','fontSize':'12px'}),
            dcc.Dropdown(
                id='attack-filter',
                options=[{'label': l, 'value': l}
                         for l in sorted(df['Label'].unique())],
                value=None, multi=True,
                placeholder="All Attack Types",
                style={'backgroundColor':'#1e1e2e','color':'#000'}
            )
        ], width=4),
        dbc.Col([
            html.Label("Risk Score Range",
                       style={'color':'#aaa','fontSize':'12px'}),
            dcc.RangeSlider(
                id='score-slider',
                min=0, max=100, step=1,
                value=[0, 100],
                marks={0:'0', 25:'25', 50:'50',
                       75:'75', 100:'100'},
            )
        ], width=5),
    ], style={
        'backgroundColor':'#1e1e2e',
        'padding':'12px 16px',
        'borderRadius':'8px',
        'marginBottom':'16px'
    }),

    # Charts Row 1
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("📈 Alert Timeline",
                               style={'color':'#fff',
                                      'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dcc.Graph(id='timeline-chart', style={'height':'250px'})
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
                    dcc.Graph(id='tier-pie', style={'height':'250px'})
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=4),
    ], className="mb-3"),

    # Charts Row 2
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("🎯 Risk Score by Attack Type",
                               style={'color':'#fff',
                                      'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dcc.Graph(id='attack-bar', style={'height':'300px'})
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("🔬 MITRE ATT&CK Technique Distribution",
                               style={'color':'#fff',
                                      'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dcc.Graph(id='mitre-bar', style={'height':'300px'})
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e',
                      'border':'1px solid #333'})
        ], width=6),
    ], className="mb-3"),

    # Alert Table
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Span("📋 Prioritized Alert Feed  ",
                              style={'color':'#fff'}),
                    html.Span(id='table-count',
                              style={'color':'#aaa','fontSize':'12px'})
                ], style={'backgroundColor':'#1e1e2e'}),
                dbc.CardBody([
                    dash_table.DataTable(
                        id='alert-table',
                        columns=[
                            {'name': 'Time',        'id': 'time_str'},
                            {'name': 'Attack Type', 'id': 'Label'},
                            {'name': 'Risk Score',  'id': 'risk_score'},
                            {'name': 'Tier',        'id': 'risk_tier'},
                            {'name': 'MITRE Tactic','id': 'ml_pred_tactic'},
                            {'name': 'Technique',   'id': 'pred_tech_name_1'},
                            {'name': 'Confidence',  'id': 'pred_confidence_1'},
                            {'name': 'Dst Port',    'id': 'Destination Port'},
                        ],
                        page_size=15,
                        sort_action='native',
                        filter_action='native',
                        style_table={
                            'overflowX': 'auto',
                            'backgroundColor': '#1e1e2e'
                        },
                        style_header={
                            'backgroundColor': '#12121f',
                            'color': '#fff',
                            'fontWeight': 'bold',
                            'border': '1px solid #333',
                            'fontSize': '12px'
                        },
                        style_cell={
                            'backgroundColor': '#1e1e2e',
                            'color': '#ddd',
                            'border': '1px solid #2a2a3e',
                            'fontSize': '12px',
                            'padding': '8px',
                            'textAlign': 'left',
                            'maxWidth': '180px',
                            'overflow': 'hidden',
                            'textOverflow': 'ellipsis',
                        },
                        style_data_conditional=[
                            {
                                'if': {'filter_query': '{risk_tier} = "CRITICAL"'},
                                'backgroundColor': '#3d1a1a',
                                'color': '#ff6b6b',
                                'fontWeight': 'bold'
                            },
                            {
                                'if': {'filter_query': '{risk_tier} = "HIGH"'},
                                'backgroundColor': '#3d2a1a',
                                'color': '#ffa94d',
                            },
                            {
                                'if': {'filter_query': '{risk_tier} = "MEDIUM"'},
                                'backgroundColor': '#3d3a1a',
                                'color': '#ffd43b',
                            },
                            {
                                'if': {'filter_query': '{risk_tier} = "LOW"'},
                                'backgroundColor': '#1a3d1a',
                                'color': '#69db7c',
                            },
                        ],
                        sort_by=[{
                            'column_id': 'risk_score',
                            'direction': 'desc'
                        }],
                    )
                ], style={'padding':'8px','backgroundColor':'#1e1e2e'})
            ], style={'backgroundColor':'#1e1e2e','border':'1px solid #333'})
        ], width=12),
    ]),

], fluid=True, style={'backgroundColor':'#12121f','minHeight':'100vh',
                       'padding':'16px'})


# ── Callbacks ────────────────────────────────────────────
def filter_df(tiers, attacks, score_range):
    filtered = df.copy()
    if tiers:
        filtered = filtered[filtered['risk_tier'].isin(tiers)]
    if attacks:
        filtered = filtered[filtered['Label'].isin(attacks)]
    filtered = filtered[
        (filtered['risk_score'] >= score_range[0]) &
        (filtered['risk_score'] <= score_range[1])
    ]
    return filtered


@app.callback(
    Output('timeline-chart', 'figure'),
    Output('tier-pie',       'figure'),
    Output('attack-bar',     'figure'),
    Output('mitre-bar',      'figure'),
    Output('alert-table',    'data'),
    Output('table-count',    'children'),
    Input('tier-filter',     'value'),
    Input('attack-filter',   'value'),
    Input('score-slider',    'value'),
)
def update_dashboard(tiers, attacks, score_range):
    filtered = filter_df(tiers, attacks, score_range)
    attack_filtered = filtered[filtered['Label'] != 'BENIGN']

    # ── Timeline chart
    timeline = attack_filtered.copy()
    timeline['hour'] = timeline['timestamp'].dt.hour
    hourly   = timeline.groupby(['hour','risk_tier']).size().reset_index(
                    name='count')
    fig_timeline = px.bar(
        hourly, x='hour', y='count', color='risk_tier',
        color_discrete_map=TIER_COLORS,
        category_orders={'risk_tier': TIER_ORDER},
        labels={'hour':'Hour of Day','count':'Alert Count'},
    )
    fig_timeline.update_layout(
        paper_bgcolor='#1e1e2e', plot_bgcolor='#1e1e2e',
        font_color='#ddd', margin=dict(l=40,r=20,t=20,b=40),
        legend=dict(orientation='h', y=1.1),
        showlegend=True
    )
    fig_timeline.update_xaxes(gridcolor='#333')
    fig_timeline.update_yaxes(gridcolor='#333')

    # ── Tier pie
    tier_counts = filtered['risk_tier'].value_counts()
    fig_pie = go.Figure(go.Pie(
        labels=tier_counts.index,
        values=tier_counts.values,
        marker_colors=[TIER_COLORS.get(t,'#999')
                       for t in tier_counts.index],
        hole=0.4,
        textinfo='percent+label',
        textfont_size=11,
    ))
    fig_pie.update_layout(
        paper_bgcolor='#1e1e2e', font_color='#ddd',
        margin=dict(l=20,r=20,t=20,b=20),
        showlegend=False
    )

    # ── Attack bar
    avg_scores = attack_filtered.groupby('Label')['risk_score'].mean(
                    ).sort_values(ascending=True).reset_index()
    avg_scores['color'] = avg_scores['risk_score'].apply(
        lambda s: TIER_COLORS['CRITICAL'] if s >= 58
                  else TIER_COLORS['HIGH'] if s >= 50
                  else TIER_COLORS['MEDIUM'] if s >= 42
                  else TIER_COLORS['LOW']
    )
    fig_bar = go.Figure(go.Bar(
        x=avg_scores['risk_score'],
        y=avg_scores['Label'],
        orientation='h',
        marker_color=avg_scores['color'],
        text=avg_scores['risk_score'].round(1),
        textposition='outside',
        textfont=dict(color='#ddd', size=10),
    ))
    fig_bar.update_layout(
        paper_bgcolor='#1e1e2e', plot_bgcolor='#1e1e2e',
        font_color='#ddd', margin=dict(l=160,r=60,t=20,b=40),
        xaxis=dict(range=[0,80], gridcolor='#333'),
        yaxis=dict(gridcolor='#333'),
    )

    # ── MITRE technique bar
    tech_counts = attack_filtered['pred_tech_name_1'].value_counts().head(10)
    fig_mitre   = go.Figure(go.Bar(
        x=tech_counts.values,
        y=tech_counts.index,
        orientation='h',
        marker_color='#5c6bc0',
        text=tech_counts.values,
        textposition='outside',
        textfont=dict(color='#ddd', size=10),
    ))
    fig_mitre.update_layout(
        paper_bgcolor='#1e1e2e', plot_bgcolor='#1e1e2e',
        font_color='#ddd', margin=dict(l=180,r=60,t=20,b=40),
        xaxis=dict(gridcolor='#333'),
        yaxis=dict(gridcolor='#333'),
    )

    # ── Table data
    table_cols = ['time_str','Label','risk_score','risk_tier',
                  'ml_pred_tactic','pred_tech_name_1',
                  'pred_confidence_1','Destination Port']
    table_data  = attack_filtered[table_cols].sort_values(
                      'risk_score', ascending=False).head(500).to_dict('records')
    table_count = f"Showing top 500 of {len(attack_filtered):,} alerts"

    return (fig_timeline, fig_pie, fig_bar,
            fig_mitre, table_data, table_count)


# ── Run ──────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8050)
