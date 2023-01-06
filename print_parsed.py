import sys
name = sys.argv[1].split("_")
N_AVS = int(name[1])
N_SAMPLES = int(name[3])
N_RUNS = int(name[5].split(".")[0])
f = open(sys.argv[1],'r').read().strip().split("\n")
ACC = float(f[0].split(":")[1])
print("[AVS] %03d [SAMPLES] %06d [RUNS] %02d | %f" % (N_AVS,N_SAMPLES,N_RUNS, ACC))
