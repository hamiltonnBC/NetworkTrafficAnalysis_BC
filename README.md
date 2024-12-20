[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/VyK8TT0G)
# 24FA-CSC450-P1
Fall 2024 CSC450 Computer Security Midterm Projects



# Network Traffic Analysis Project

This project analyzes network traffic captured from a virtual machine cluster to demonstrate network monitoring, security analysis, and anomaly detection. The project uses data generated through CMU's GHOSTS software combined with manual network interactions, capturing over 1 million packets.

## Structure

- `scripts/pcapng_processor.py`: Processes raw packet capture data, extracting key metrics and identifying potential security concerns
- `scripts/isolationForest.py`: Implements anomaly detection using the Isolation Forest algorithm on the processed packet data
- `app.py`: Web dashboard for visualizing the analysis results and anomalies

## Requirements

- Python 3.8+
- Required packages: scapy, pandas, scikit-learn, dash, pyshark

## Usage

1. Run the analysis:
   ```bash

   python app.py
   ```
2. Open your browser to `http://localhost:8050` to view the dashboard

## Data Collection

The packet capture was generated using:
- CMU's GHOSTS software for automated network behavior
- Manual file transfers via FTP
- Various VM interactions including Windows and Debian systems
- Wireshark for packet capture

This setup demonstrates real-world network traffic patterns while maintaining a controlled, legal testing environment.