import matplotlib.pyplot as plt
import pandas as pd

# Read CSV file
data = pd.read_csv('network-connection-artifacts.csv',encoding='utf-16',sep=',',header=0)

# Basic line plot
plt.figure(figsize=(10, 6))
plt.plot(data["Detected Date"][::-1], data["Image"][::-1], label='C2 beaconing')
plt.title('Network Connections')
plt.xlabel('Detected Time')
plt.ylabel('Processes')
plt.xticks(rotation=45, ha='right')  # 45 degree angle, right-aligned
plt.legend()
plt.grid(True)
plt.show()