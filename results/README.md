
#### Get coverage data for MILS targets, reported in the *"6.3 Fuzzing depth"* Section

1. **[Table 3]** Edge and Basic Block Coverage achieved can be found in the last line of the `stats_trunc.csv` file located in the `results/fuzzing_depth/mils/target_name/approach_name` directory.

2. **[Figure 4]** Edge and Basic Block growth curves, can be generated using the `/results/generate_figure4.py` script.

#### Get bug analysis data reported in the *"6.3 Fuzzing depth"* Section

3. **[Table 4]** The information about unique bugs found for each target can be extracted from the `/results/fuzzing_depth/mils/target_name/crash_x.txt` file in the respective target directories. 

#### Get efficiency data reported in *"6.4 Performance"* Section

4. **[Table 5]** Throughput metrics can be found in the `/results/performance/target_name/throughputrecap.txt` file in the respective target directory.

### Get coverage data for IoT targets, reported in the *"7.3 Fuzzing depth"* Section

5. **[Table 7]** Edge and Basic Block Coverage achieved can be found in the last line of the `stats.csv` file located in the `results/fuzzing_depth/iot_firm/target_name/approach_name` directory. 

6. **[Figure 6]** Edge and Basic Block growth curves, can be generated using the `/results/generate_figure4.py` script.

