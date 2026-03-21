#!/usr/bin/env python3
"""Generate placeholder figures for ref2.tex."""
import sys

def pipeline_fig():
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches

        fig, ax = plt.subplots(figsize=(6.5, 1.6))
        ax.set_xlim(0, 10); ax.set_ylim(0, 2); ax.axis('off')
        stages = ['Ingest', 'Frame', 'Cluster', 'Align', 'Classify', 'Grammar', 'Output']
        colors = ['#d5e8d4', '#dae8fc', '#dae8fc', '#dae8fc', '#dae8fc', '#ffe6cc', '#f8cecc']
        for i, (s, c) in enumerate(zip(stages, colors)):
            ax.add_patch(mpatches.FancyBboxPatch(
                (i * 1.4 + 0.08, 0.55), 1.15, 0.9,
                boxstyle='round,pad=0.05', fc=c, ec='#555', lw=0.8))
            ax.text(i * 1.4 + 0.655, 1.0, s, ha='center', va='center',
                    fontsize=7.5, fontweight='bold')
            if i < len(stages) - 1:
                ax.annotate('', xy=((i + 1) * 1.4 + 0.08, 1.0),
                            xytext=(i * 1.4 + 1.23, 1.0),
                            arrowprops=dict(arrowstyle='->', color='#333', lw=1.0))
        # label the C-library bracket
        ax.annotate('', xy=(5.6, 0.4), xytext=(0.08, 0.4),
                    arrowprops=dict(arrowstyle='-', color='gray'))
        ax.text(2.84, 0.25, 'C library (libref2)', ha='center', fontsize=6.5, color='gray')
        ax.annotate('', xy=(9.73, 0.4), xytext=(5.6, 0.4),
                    arrowprops=dict(arrowstyle='-', color='gray'))
        ax.text(7.7, 0.25, 'Rust application', ha='center', fontsize=6.5, color='gray')

        plt.tight_layout(pad=0.2)
        plt.savefig('pipeline.pdf', bbox_inches='tight')
        print('pipeline.pdf generated')
    except ImportError:
        _stub('pipeline.pdf')


def drift_fig():
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 2.0))
        pos = np.arange(10)
        true_kappa = [1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
        nw_kappa   = [1, 1, 1, 0.01, 1.0, 0.05, 0.03, 0, 0, 0]
        base_col = '#4a90d9'

        ax1.bar(pos, true_kappa, color=base_col, width=0.7)
        ax1.axhline(0.7, color='red', linestyle='--', linewidth=1.0, label='threshold (0.7)')
        ax1.set_title('(a) True conservation', fontsize=8)
        ax1.set_xlabel('Protocol byte position', fontsize=7)
        ax1.set_ylabel(r'$\kappa[p]$', fontsize=8)
        ax1.set_xticks(pos)
        ax1.tick_params(labelsize=6)
        ax1.legend(fontsize=6)

        bar_colors = [base_col] * 10
        bar_colors[3] = '#e07b39'   # missed flags (drift miss)
        bar_colors[4] = '#c0392b'   # spurious peak
        ax2.bar(pos, nw_kappa, color=bar_colors, width=0.7)
        ax2.axhline(0.7, color='red', linestyle='--', linewidth=1.0)
        ax2.set_title('(b) NW conservation after drift', fontsize=8)
        ax2.set_xlabel('Consensus position', fontsize=7)
        ax2.set_xticks(pos)
        ax2.tick_params(labelsize=6)
        from matplotlib.patches import Patch
        legend_els = [Patch(fc='#e07b39', label='drift miss (pos 3)'),
                      Patch(fc='#c0392b', label='spurious peak (pos 4)')]
        ax2.legend(handles=legend_els, fontsize=6)

        plt.tight_layout(pad=0.4)
        plt.savefig('drift.pdf', bbox_inches='tight')
        print('drift.pdf generated')
    except ImportError:
        _stub('drift.pdf')


def _stub(name):
    """Write a minimal valid PDF placeholder."""
    print(f'matplotlib not available; writing stub {name}')
    data = (
        b'%PDF-1.4\n'
        b'1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'
        b'2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n'
        b'3 0 obj<</Type/Page/MediaBox[0 0 432 144]/Parent 2 0 R>>endobj\n'
        b'xref\n0 4\n'
        b'0000000000 65535 f \n'
        b'0000000009 00000 n \n'
        b'0000000058 00000 n \n'
        b'0000000115 00000 n \n'
        b'trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n'
    )
    with open(name, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    pipeline_fig()
    drift_fig()
