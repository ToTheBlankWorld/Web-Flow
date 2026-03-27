"""
DNS Guardian - Architecture Diagram Generator
Generates a professional PNG architecture diagram
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import matplotlib.patheffects as pe
import numpy as np

# Create figure with dark background
fig, ax = plt.subplots(1, 1, figsize=(16, 11), facecolor='#0f172a')
ax.set_facecolor('#0f172a')
ax.set_xlim(0, 16)
ax.set_ylim(0, 11)
ax.axis('off')

# Color palette
COLORS = {
    'cyan': '#22d3ee',
    'purple': '#a855f7',
    'green': '#22c55e',
    'orange': '#f97316',
    'red': '#ef4444',
    'surface': '#1e293b',
    'surface_light': '#334155',
    'text': '#f1f5f9',
    'text_dim': '#94a3b8',
    'border': '#475569',
    'glow_cyan': '#06b6d4',
    'glow_purple': '#9333ea'
}

def draw_box(ax, x, y, width, height, color, title, subtitle=None, items=None):
    """Draw a styled box with title and optional items"""
    # Outer glow effect
    for i in range(3, 0, -1):
        glow = FancyBboxPatch((x-i*0.02, y-i*0.02), width+i*0.04, height+i*0.04, 
                              boxstyle="round,pad=0.02,rounding_size=0.15",
                              facecolor='none',
                              edgecolor=color, linewidth=0.5, alpha=0.1*i)
        ax.add_patch(glow)
    
    # Main box with rounded corners
    box = FancyBboxPatch((x, y), width, height, 
                          boxstyle="round,pad=0.02,rounding_size=0.15",
                          facecolor=COLORS['surface'],
                          edgecolor=color, linewidth=2.5,
                          alpha=0.95)
    ax.add_patch(box)
    
    # Title bar
    title_bar = FancyBboxPatch((x+0.05, y + height - 0.55), width-0.1, 0.45,
                                boxstyle="round,pad=0,rounding_size=0.1",
                                facecolor=color, alpha=0.15)
    ax.add_patch(title_bar)
    
    # Title
    title_y = y + height - 0.33
    ax.text(x + width/2, title_y, title, fontsize=13, color=COLORS['text'],
            fontweight='bold', va='center', ha='center')
    
    # Subtitle
    if subtitle:
        ax.text(x + width/2, y + height - 0.75, subtitle, fontsize=9, 
                color=color, va='center', ha='center', style='italic')
    
    # Items list
    if items:
        item_y = y + height - 1.15
        for item in items:
            ax.text(x + 0.3, item_y, f"> {item}", fontsize=9, 
                    color=COLORS['text_dim'], va='center', ha='left',
                    family='monospace')
            item_y -= 0.35

def draw_arrow(ax, start, end, color, label=None, curve=0):
    """Draw a styled arrow with optional label"""
    mid_x = (start[0] + end[0]) / 2
    mid_y = (start[1] + end[1]) / 2
    
    # Glow effect for arrow
    for i in range(2):
        arrow_glow = FancyArrowPatch(start, end,
                                arrowstyle='-|>',
                                mutation_scale=18,
                                color=color,
                                linewidth=4-i*2,
                                alpha=0.2+i*0.3,
                                connectionstyle=f'arc3,rad={curve}')
        ax.add_patch(arrow_glow)
    
    arrow = FancyArrowPatch(start, end,
                            arrowstyle='-|>',
                            mutation_scale=15,
                            color=color,
                            linewidth=2,
                            connectionstyle=f'arc3,rad={curve}')
    ax.add_patch(arrow)
    
    if label:
        # Add label with background
        ax.text(mid_x + 0.4, mid_y, label, fontsize=9, color=COLORS['text'],
                va='center', ha='left',
                bbox=dict(boxstyle='round,pad=0.35', facecolor=COLORS['surface'], 
                         edgecolor=color, alpha=0.95, linewidth=1.5))

# ============ TITLE ============
ax.text(8, 10.4, "DNS GUARDIAN", fontsize=28, 
        color=COLORS['cyan'], fontweight='bold', ha='center',
        family='sans-serif',
        path_effects=[pe.withStroke(linewidth=4, foreground='#0f172a')])
ax.text(8, 9.9, "System Architecture", fontsize=14, 
        color=COLORS['text_dim'], ha='center', style='italic')

# ============ LAYER 1: USER DASHBOARD ============
draw_box(ax, 1, 7.2, 14, 2.2, COLORS['cyan'], 
         'USER DASHBOARD', 
         'React 18 + TypeScript + Tailwind CSS + Vite')

# Dashboard components (smaller boxes inside)
components = [
    ('Overview\nStats & Metrics', 1.5),
    ('Threat\nAlerts', 4.6),
    ('Domain\nAnalysis', 7.7),
    ('GeoIP\nMap', 10.8)
]
for comp, cx in components:
    comp_box = FancyBboxPatch((cx, 7.45), 2.5, 1.0,
                               boxstyle="round,pad=0.02,rounding_size=0.1",
                               facecolor=COLORS['surface_light'],
                               edgecolor=COLORS['cyan'], linewidth=1.5, alpha=0.9)
    ax.add_patch(comp_box)
    ax.text(cx + 1.25, 7.95, comp, fontsize=9, color=COLORS['text'],
            va='center', ha='center', fontweight='medium', linespacing=1.3)

# ============ ARROW 1: WebSocket ============
draw_arrow(ax, (8, 7.2), (8, 5.85), COLORS['purple'], 'WebSocket\n(Real-time)')

# ============ LAYER 2: BACKEND SERVER ============
draw_box(ax, 1, 3.9, 14, 1.85, COLORS['purple'],
         'BACKEND SERVER',
         'FastAPI + Python 3.11')

# Detection Engine sub-box
engine_box = FancyBboxPatch((1.5, 4.1), 13, 1.1,
                             boxstyle="round,pad=0.02,rounding_size=0.1",
                             facecolor='#1a1a2e',
                             edgecolor=COLORS['purple'], linewidth=1.5, alpha=0.8)
ax.add_patch(engine_box)
ax.text(8, 4.95, 'THREAT DETECTION ENGINE', fontsize=11, color=COLORS['purple'],
        va='center', ha='center', fontweight='bold')

# Detection algorithms
algos = ['Cache Poisoning', 'Fast-Flux', 'DGA Detection', 'DNS Hijacking']
algo_x = 2.2
for i, algo in enumerate(algos):
    # Small indicator box
    indicator = FancyBboxPatch((algo_x-0.15, 4.28), 0.1, 0.1,
                                boxstyle="round,pad=0",
                                facecolor=COLORS['green'], alpha=0.8)
    ax.add_patch(indicator)
    ax.text(algo_x, 4.33, algo, fontsize=9, color=COLORS['text_dim'],
            va='center', ha='left')
    algo_x += 3.2

# ============ ARROW 2: File Watch ============
draw_arrow(ax, (8, 3.9), (8, 2.65), COLORS['orange'], 'File Watch\n(eve.json)')

# ============ LAYER 3: SURICATA IDS ============
draw_box(ax, 1, 1.0, 14, 1.55, COLORS['orange'],
         'SURICATA IDS',
         'Network Intrusion Detection System',
         items=['Captures DNS packets (UDP port 53)', 'Outputs structured JSON logs to eve.json'])

# ============ ARROW 3: Network ============
draw_arrow(ax, (8, 1.0), (8, 0.55), COLORS['green'])

# ============ LAYER 4: NETWORK TRAFFIC ============
network_box = FancyBboxPatch((3, 0.15), 10, 0.35,
                              boxstyle="round,pad=0.02,rounding_size=0.08",
                              facecolor=COLORS['surface'],
                              edgecolor=COLORS['green'], linewidth=2.5, alpha=0.95)
ax.add_patch(network_box)
ax.text(8, 0.33, 'NETWORK TRAFFIC  |  All DNS Queries (Port 53)', fontsize=11, 
        color=COLORS['green'], va='center', ha='center', fontweight='bold')

# ============ DATA FLOW INDICATOR ============
# Vertical arrow on the side
ax.annotate('', xy=(15.3, 1.5), xytext=(15.3, 8.5),
            arrowprops=dict(arrowstyle='->', color=COLORS['text_dim'], 
                          lw=1.5, ls='--'))
ax.text(15.5, 5, 'DATA\nFLOW', fontsize=9, color=COLORS['text_dim'],
        va='center', ha='left', rotation=0, fontweight='bold',
        linespacing=1.5)

# ============ LEGEND ============
legend_x = 1.2
legend_y = 0.55
ax.text(legend_x, legend_y, 'LEGEND:', fontsize=9, color=COLORS['text_dim'], fontweight='bold')
legend_items = [
    ('Frontend', COLORS['cyan']),
    ('Backend', COLORS['purple']),
    ('IDS Engine', COLORS['orange']),
    ('Network', COLORS['green'])
]
lx = legend_x + 1.3
for label, color in legend_items:
    circle = plt.Circle((lx, legend_y), 0.1, color=color, alpha=0.9)
    ax.add_patch(circle)
    ax.text(lx + 0.25, legend_y, label, fontsize=9, color=COLORS['text_dim'], va='center')
    lx += 2.0

# Save as PNG
output_path = r'd:\My Projects\WebFlow Detec\Web-Flow\architecture_diagram.png'
plt.savefig(output_path, dpi=200, bbox_inches='tight', 
            facecolor='#0f172a', edgecolor='none', pad_inches=0.3)
plt.close()

print(f"Architecture diagram saved to: {output_path}")
