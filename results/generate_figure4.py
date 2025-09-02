import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import sys
import os

# Get target directories from command-line argument
targets = ["fuzzing_depth/mils/json_easy/", "fuzzing_depth/mils/sendmail_easy/", "fuzzing_depth/mils/tinyexpr_easy/", "fuzzing_depth/mils/json_hard/", "fuzzing_depth/mils/sendmail_hard/", "fuzzing_depth/mils/tinyexpr_hard/"]

# Define a color map for distinguishing datasets
color_map = {
    "fuzzbox_edge": '#0092ff',
#    "fuzzbox_block": '#2986cc',
    "fuzzbox_block": '#0092ff',
    "baseline_edge": '#fc440f',
    "baseline_block": '#da2417'
}

# Plot graphs based on iterations for all six datasets
num_rows = 2
num_cols = 3
fig, axs = plt.subplots(nrows=num_rows, ncols=num_cols, figsize=(15, 6*2))
fig.subplots_adjust(hspace=0)


for i, target in enumerate(targets):

    basename = os.path.splitext(target)[0]
    basename = basename.replace('/', ' ')
    file_path1 = target+"/fuzzbox/stats.csv"
    file_path2 = target+"/baseline/stats.csv"

    # Load data from the files
    fuzzbox_data = pd.read_csv(file_path1, delimiter=",")
    baseline_data = pd.read_csv(file_path2, delimiter=",")

    # Convert timestamps
    fuzzbox_data = fuzzbox_data.drop(index=0).reset_index(drop=True)
    baseline_data = baseline_data.drop(index=0).reset_index(drop=True)
 
    # Shift the time values to the start of the time window
    fuzzbox_start_time = fuzzbox_data['TIME'][0]
    baseline_start_time = baseline_data['TIME'][0]
    fuzzbox_data['TIME'] = fuzzbox_data['TIME'].apply(lambda x: x - fuzzbox_start_time)
    baseline_data['TIME'] = baseline_data['TIME'].apply(lambda x: x - baseline_start_time)


    # Plot data using the defined color map. Griglia 2x3
    row_idx_edge = i // 3
    col_idx_edge = i % 3
    row_idx_block = i // 3
    col_idx_block = i % 3

    ax_edge = axs[row_idx_edge, col_idx_edge]
    ax_block = axs[row_idx_block, col_idx_block]

    ax_edge.plot(fuzzbox_data["TIME"], fuzzbox_data["EDGE_COVERAGE"], color=color_map["fuzzbox_edge"])
    ax_edge.plot(baseline_data["TIME"], baseline_data["EDGE_COVERAGE"], color=color_map["baseline_edge"]) 
    ax_block.plot(fuzzbox_data["TIME"], fuzzbox_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["fuzzbox_block"])
    ax_block.plot(baseline_data["TIME"], baseline_data["BLOCK_COVERAGE"], linestyle='--', color=color_map["baseline_block"])


    # Print title for each plot
    ax_edge.set_title(basename.split()[0].replace("_", " "))
    ax_edge.grid(True)
    ax_block.grid(True)

# Show plot
fig.legend(['FuzzBox Edge Cov', 'Baseline Edge Cov', 'FuzzBox BB Cov', 'Baseline BB Cov'], loc='upper center', ncol=4)
fig.text(0.04, 0.5, 'Edge / Basic Block Coverage', ha='center', va='center', rotation='vertical')
fig.text(0.5, 0.04, 'Time (seconds)', ha='center', va='center')

plt.show()
