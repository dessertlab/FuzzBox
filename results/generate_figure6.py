import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import sys
import os
from matplotlib.ticker import ScalarFormatter

# Get target directories from command-line argument
targets = ["fuzzing_depth/iot_firm/tendaAC15/", "fuzzing_depth/iot_firm/TEW651BR/", "fuzzing_depth/iot_firm/DCS-932L/"]

# Define a color map for distinguishing datasets
color_map = {
    "fuzzbox_edge": '#0092ff',
    "fuzzbox_block": '#0092ff',
    "baseline_edge": '#fc440f',
    "baseline_block": '#da2417'
}


fig, axs = plt.subplots(1, 3, figsize=(30, 15))

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
    fuzzbox_data['TIME_SECONDS'] = fuzzbox_data['TIME_SHIFTED'] / 1
    baseline_data['TIME_SECONDS'] = baseline_data['TIME_SHIFTED'] / 1

    # Calculate elapsed time
    elapsed_time_fuzzbox = fuzzbox_data['TIME'].iloc[-1] - fuzzbox_data['TIME'].iloc[0]
    elapsed_time_baseline = baseline_data['TIME'].iloc[-1] - baseline_data['TIME'].iloc[0]

    # Extract number of iterations
    iterations_fuzzbox = fuzzbox_data['ITERATIONS'].iloc[-1]
    iterations_baseline = baseline_data['ITERATIONS'].iloc[-1]

    axs[i].plot(fuzzbox_data["TIME_SECONDS"], fuzzbox_data["EDGE_COVERAGE"], color=color_map["fuzzbox_edge"], label='fuzzbox')
    axs[i].plot(baseline_data["TIME_SECONDS"], baseline_data["EDGE_COVERAGE"], color=color_map["baseline_edge"], label='baseline')
    axs[i].plot(fuzzbox_data["TIME_SECONDS"], fuzzbox_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["fuzzbox_block"], label='fuzzbox')
    axs[i].plot(baseline_data["TIME_SECONDS"], baseline_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["baseline_block"], label='baseline')


    axs[i].grid(True)
    axs[i].set_xlabel("Time (seconds)")

    # Disable scientific notation for the y-axis
    axs[i].yaxis.set_major_formatter(ScalarFormatter(useMathText=True))
    axs[i].yaxis.get_major_formatter().set_scientific(False)
    axs[i].yaxis.get_major_formatter().set_useOffset(False)

axs[0].set_title("TENDA AC15")
axs[1].set_title("TEW-651BR")
axs[2].set_title("DCS-932L")

axs[0].set_ylabel("Edge/Basic Block Coverage")

# Show plot
fig.legend(['FuzzBox Edge Cov', 'Baseline Edge Cov', 'FuzzBox Block Cov', 'Baseline Block Cov'], loc='upper center', ncol=4)
plt.tight_layout()

plt.show()

