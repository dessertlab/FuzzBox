import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import sys
import os
from matplotlib.ticker import ScalarFormatter
from matplotlib.lines import Line2D

# Get target directories from command-line argument
targets = ["fuzzing_depth/iot_firm/tendaAC15/", "fuzzing_depth/iot_firm/TEW651BR/", "fuzzing_depth/iot_firm/DCS-932L/"]

# Define a color map for distinguishing datasets
color_map = {
    "fuzzbox_edge": '#0092ff',
    "fuzzbox_block": '#0092ff',
    "baseline_edge": '#fc440f',
    "baseline_block": '#da2417'
}


fig, axs = plt.subplots(2, 3, figsize=(15, 10))

for i, target in enumerate(targets):
    basename = os.path.basename(target)
    file_path1 = os.path.join(target, "fuzzbox", "stats.csv")
    file_path2 = os.path.join(target, "baseline", "stats.csv")

    # Load data from the files
    fuzzbox_data = pd.read_csv(file_path1, delimiter=",")
    baseline_data = pd.read_csv(file_path2, delimiter=",")

    # Shift time to start from 0 and convert in seconds
    fuzzbox_data['TIME_SHIFTED'] = fuzzbox_data['TIME'] - fuzzbox_data['TIME'].iloc[0]
    baseline_data['TIME_SHIFTED'] = baseline_data['TIME'] - baseline_data['TIME'].iloc[0]
    fuzzbox_data['TIME_SECONDS'] = fuzzbox_data['TIME_SHIFTED']
    baseline_data['TIME_SECONDS'] = baseline_data['TIME_SHIFTED']

    # Calculate elapsed time
    elapsed_time_fuzzbox = fuzzbox_data['TIME'].iloc[-1] - fuzzbox_data['TIME'].iloc[0]
    elapsed_time_baseline = baseline_data['TIME'].iloc[-1] - baseline_data['TIME'].iloc[0]

    # Extract number of iterations
    iterations_fuzzbox = fuzzbox_data['ITERATIONS'].iloc[-1]
    iterations_baseline = baseline_data['ITERATIONS'].iloc[-1]

    # Plot Edge Coverage
    axs[0, i].plot(fuzzbox_data["TIME_SECONDS"], fuzzbox_data["EDGE_COVERAGE"], color=color_map["fuzzbox_edge"], label='fuzzbox')
    axs[0, i].plot(baseline_data["TIME_SECONDS"], baseline_data["EDGE_COVERAGE"], color=color_map["baseline_edge"], label='baseline')
    axs[0, i].grid(True)

    # Plot Block Coverage
    axs[1, i].plot(fuzzbox_data["TIME_SECONDS"], fuzzbox_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["fuzzbox_block"], label='fuzzbox')
    axs[1, i].plot(baseline_data["TIME_SECONDS"], baseline_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["baseline_block"], label='baseline')
    axs[1, i].set_xlabel("Time (seconds)")
    axs[1, i].grid(True)

    # Disable scientific notation for Block Coverage
    axs[0, i].yaxis.set_major_formatter(ScalarFormatter(useMathText=True))
    axs[0, i].yaxis.get_major_formatter().set_scientific(False)
    axs[0, i].yaxis.get_major_formatter().set_useOffset(False)
    axs[1, i].yaxis.set_major_formatter(ScalarFormatter(useMathText=True))
    axs[1, i].yaxis.get_major_formatter().set_scientific(False)
    axs[1, i].yaxis.get_major_formatter().set_useOffset(False)

axs[0, 0].set_ylabel("Edge Coverage")
axs[1, 0].set_ylabel("Basic Block Coverage")
axs[0, 0].set_title("Tenda AC15")
axs[0, 1].set_title("TEW-651BR")
axs[0, 2].set_title("DCS-932L")

legend_lines = [
    Line2D([0], [0], color=color_map["fuzzbox_edge"], linewidth=2, label='FuzzBox Edge Cov'),
    Line2D([0], [0], color=color_map["baseline_edge"], linewidth=2, label='Baseline Edge Cov'),
    Line2D([0], [0], linestyle='--', color=color_map["fuzzbox_block"], linewidth=2, label='FuzzBox Block Cov'),
    Line2D([0], [0], linestyle='--', color=color_map["baseline_block"], linewidth=2, label='Baseline Block Cov')
]

# Add legend to figure
fig.legend(handles=legend_lines, loc='upper center', ncol=4)
plt.tight_layout()

plt.show()

