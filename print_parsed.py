# Print files resulting from the AV labels experiment
# Marcus Botacin - TAMU - 2022
import sys
# filename will come in argv
# parse filename, it contains the parameters
name = sys.argv[1].split("_")
N_AVS = int(name[1])
N_SAMPLES = int(name[3])
N_RUNS = int(name[5].split(".")[0])
# here file was persed
# Then read the file to print the classification result for this experiment
f = open(sys.argv[1],'r').read().strip().split("\n")
ACC = float(f[0].split(":")[1])
# Print everything together
print("[AVS] %03d [SAMPLES] %06d [RUNS] %02d | %f" % (N_AVS,N_SAMPLES,N_RUNS, ACC))
