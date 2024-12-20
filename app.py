from base64 import b64encode

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import pandas as pd
#import plotly.graph_objects as go
import plotly.graph_objs as go
import dash_html_components as html
import dash_core_components as dcc

import dash_bootstrap_components as dbc

def create_app():
    """
    Create and configure the Dash app with the prepared data.
    """
    app = dash.Dash(__name__, suppress_callback_exceptions=True)

    app.layout = html.Div([
        dcc.Location(id='url', refresh=False),
        html.H1('Network Traffic Analysis Dashboard'),
        dcc.Tabs([
            dcc.Tab(label='Overview', value='/overview'),
            dcc.Tab(label='Protocol Distribution', value='/protocol-distribution'),
            dcc.Tab(label='Security Concerns', value='/security-concerns'),
            #dcc.Tab(label='Traffic Patterns', value='/traffic-patterns'),
            dcc.Tab(label='IP & Port Analysis', value='/ip-port-analysis'),
            dcc.Tab(label='Anomaly Analysis', value='/anomaly-analysis'),
            dcc.Tab(label='Methodology', value='/methodology'),
            dcc.Tab(label='Conclusion', value='/conclusion'),
            dcc.Tab(label='Meet the Team & Sources', value='/team'),
        ], id='tabs', value='/overview'),

        html.Div(id='page-content')
    ])

    @app.callback(Output('page-content', 'children'), Input('tabs', 'value'))
    def display_page(tab):
        if tab == '/overview':
            return create_overview_layout()
        elif tab == '/protocol-distribution':
            return create_protocol_distribution_layout()
        elif tab == '/security-concerns':
            return create_security_concerns_layout()
        elif tab == '/traffic-patterns':
            return create_traffic_patterns_layout()
        elif tab == '/ip-port-analysis':
            return create_ip_port_analysis_layout()
        elif tab == '/methodology':
            return create_methodology_layout()
        elif tab == '/conclusion':
            return create_conclusion_layout()
        elif tab == '/anomaly-analysis':
            return create_anomaly_detection_layout()
        elif tab == '/team':
            return create_team_layout()
        else:
            return '404'

    return app


def create_overview_layout():
    """
    Create the layout for the Overview page with a Technologies Used section.
    """
    return html.Div([
        html.H2('Overview'),

        html.H2('Welcome to our Network Traffic Analysis Dashboard!'),
        html.P(
            "This project focuses on the capture and analysis of network traffic packets in a secure virtual environment. Using virtual machines and tools like QEMU alongside the CMU GHOSTS program, we simulate user activity to ethically collect and analyze packet data."),
        html.P(
            "Our analysis leverages Python libraries such as Scapy and Pandas to identify trends, outliers, and potential security vulnerabilities. We also employ the Isolation Forest machine learning algorithm for advanced anomaly detection. Key findings include the prevalence of insecure encryption protocols and the detection of cleartext passwords, highlighting the hidden risks in network communications."),
        html.P(
            "This dashboard visualizes our insights, empowering users to understand the complexities of their network traffic and the importance of robust online security practices."),

        # Use dcc.Graph to create a side-by-side layout
        dcc.Graph(
            figure={
                'data': [],
                'layout': {
                    'xaxis': {'visible': False},
                    'yaxis': {'visible': False},
                    'annotations': [
                        {
                            'x': 0,
                            'y': 1,
                            'xref': 'paper',
                            'yref': 'paper',
                            'text': '<b style="font-size: 20px;">Basic Statistics</b><br><br>' +
                                    f"<span style='font-size: 16px;'>" +
                                    f"Total packets analyzed: 1,122,966<br>" +
                                    f"Time range: 2024-10-03 08:19:00 to 2024-10-03 08:58:44<br>" +
                                    f"Duration: 0.66 hours<br>" +
                                    f"Unique IP sources: 834<br>" +
                                    f"Unique IP destinations: 835<br>" +
                                    f"Average packet size: 1,030.01 bytes<br>" +
                                    f"Median packet size: 722.00 bytes<br>" +
                                    f"Minimum packet size: 54 bytes<br>" +
                                    f"Maximum packet size: 65,226 bytes</span>",
                            'showarrow': False,
                            'align': 'left',
                            'valign': 'top',
                        },
                        {
                            'x': 1,
                            'y': 1,
                            'sizex': 5.7,
                            'sizey': 5.7,
                            'xref': 'paper',
                            'yref': 'paper',
                            'text': '<b style="font-size: 24px;">Technologies Used</b>',
                            'showarrow': False,
                            'align': 'center',
                            'valign': 'top',
                        },
                    ],
                    'images': [
                        {
                            'source': '/assets/technologies.png',
                            'xref': 'paper',
                            'yref': 'paper',
                            'x': 0.4,
                            'y': 0.9,
                            'sizex': 0.7,
                            'sizey': 0.7,
                            'sizing': 'contain',
                            'opacity': 1,
                            'layer': 'above'
                        }
                    ]
                }
            },
            style={'height': '1000px'}
        )
    ])



def create_protocol_distribution_layout():
    """
    Create the layout for the Network Layer and Protocol Distribution page.
    """
    network_data = {
        'Layer_Protocol': ['Ethernet Frames', 'IP Packets', 'TCP Segments', 'UDP Datagrams', 'QUIC Packets',
                           'ARP Messages','ICMP Messages'],
        'Count': [1122966, 1122168, 1013821, 107962, 71476, 699, 367],
        'Percentage': [100.00, 99.93, 90.28, 9.61, 6.36, 0.06, 0.03]
    }

    df = pd.DataFrame(network_data)

    # Create a horizontal bar chart
    fig = go.Figure(go.Bar(
        y=df['Layer_Protocol'],
        x=df['Percentage'],
        orientation='h',
        text=[f"{c:,} ({p:.2f}%)" for c, p in zip(df['Count'], df['Percentage'])],
        textposition='outside',
        marker_color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2']
    ))

    fig.update_layout(
        title='Network Layer and Protocol Distribution',
        xaxis_title='Percentage of Total Captured Units',
        yaxis_title='Layer / Protocol',
        xaxis=dict(tickformat='.2f', ticksuffix='%'),
        height=400,
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return html.Div([
        html.H2('Network Layer and Protocol Distribution'),
        dcc.Graph(id='network-distribution', figure=fig),
        html.P("This chart shows the distribution across different network layers and protocols:"),
        html.Ul([
            html.Li(
                "Data Link Layer: All captured units are Ethernet frames, forming the foundation of the captured network traffic."),
            html.Li(
                "Network Layer: IP packets constitute 99.93% of the captured units, with a small number of ARP messages."),
            html.Li(
                "Transport Layer: TCP segments dominate at 90.28%, while UDP datagrams account for 9.61% of the captured units."),
            html.Li(
                "Application Layer: QUIC, running over UDP, is present in 6.36% of the captured units, indicating significant usage of QUIC-based applications.")
        ]),
        html.P("Key Observations:"),
        html.Ul([
            html.Li(f"Total captured units: {network_data['Count'][0]:,}"),
            html.Li(f"TCP is the dominant transport protocol ({network_data['Percentage'][2]:.2f}% of captured units)"),
            html.Li(
                f"QUIC traffic makes up {network_data['Percentage'][5]:.2f}% of the analyzed units, suggesting notable usage of QUIC-based applications"),
            html.Li(f"ICMP messages are rare, appearing in only {network_data['Percentage'][6]:.2f}% of captured units")
        ])
    ])

def create_security_concerns_layout():
    """
    Create the layout for the Security Concerns page.
    """
    return html.Div([
        html.H2('Security Concerns'),
        html.H3('General Security Issues:'),
        html.P('WARNING: 6911 packets using insecure SSLv2 detected!'),
        html.P('WARNING: 19 FTP authentication packets detected in cleartext!'),
        html.H3('SSLv2 Usage (Deprecated and Insecure):'),
        html.Ul([
            html.Li("Total SSLv2 packets: 6911"),
            html.Li("Unique SSLv2 Sources: 35.241.42.239, 35.241.45.82, 23.61.35.51, 104.123.153.26, 34.120.158.37, 89.187.171.33, 3.166.118.127, 23.212.11.209, 23.63.73.161, 104.18.38.207, 23.203.40.207, 172.217.1.14, 23.10.215.136, 142.251.41.72, 146.75.79.42, 104.21.65.195, 52.228.161.161, 104.19.208.132, 13.227.37.20, 104.22.25.245, 141.193.213.10, 23.62.84.140, 146.75.76.155, 35.186.224.24, 146.75.78.137, 23.63.73.16, 54.145.40.241, 18.211.181.157, 104.18.41.124, 23.62.35.89, 13.107.21.237, 172.65.193.226, 13.227.37.50, 3.166.118.37, 34.36.49.68, 104.17.172.91, 3.166.118.70, 142.251.41.46, 104.18.39.182, 18.245.96.167, 128.2.42.52, 216.239.36.178, 173.213.239.197, 198.206.188.170, 104.18.25.242, 146.75.78.248, 54.230.202.129, 23.56.168.160, 13.227.37.118, 108.175.57.249, 108.181.102.67, 140.82.113.4, 18.160.181.108, 23.223.149.200, 137.75.88.9, 20.150.76.228, 34.102.204.67, 23.63.73.26, 54.230.202.102, 142.251.41.78, 3.166.118.104, 54.208.27.24, 66.235.200.147, 52.202.143.6, 23.10.212.142, 141.101.90.96, 13.227.37.123, 146.75.78.250, 172.64.146.132, 23.62.35.49, 23.223.182.207, 169.150.236.104, 104.18.38.196, 172.217.1.1, 23.10.221.135, 140.82.114.4, 34.117.228.201, 23.0.218.55, 142.251.32.74, 104.18.87.42, 23.35.69.27, 172.64.152.243, 172.217.165.14, 23.63.72.146, 13.227.37.109, 54.230.202.36, 104.17.208.240, 23.35.69.10, 23.62.35.75, 23.203.40.252, 151.101.129.91, 172.66.42.224, 35.247.107.124, 13.227.37.65, 192.225.159.74, 3.229.16.138, 18.160.102.94, 172.67.29.106, 172.67.146.19, 157.240.254.7, 2.17.81.212, 3.166.118.97, 146.75.77.91, 172.67.139.119, 54.230.202.71, 104.17.209.240, 104.17.246.203, 35.201.112.186, 18.160.102.66, 140.82.114.3, 54.230.202.107, 151.101.130.137, 172.65.236.181, 172.64.153.235, 34.149.87.45, 104.26.13.210, 146.75.77.10, 104.123.153.24, 34.110.220.139, 142.251.41.65, 3.5.10.158, 146.75.77.175, 23.215.126.34, 13.227.37.102, 18.160.181.72, 23.56.169.145, 184.72.187.149, 157.240.254.63, 192.168.122.1, 146.75.79.52, 54.81.166.120, 146.75.41.140, 23.185.0.3, 104.244.42.129, 104.17.175.91, 3.166.118.82, 54.197.134.208, 146.75.78.110, 44.229.121.16, 13.227.37.42, 104.18.42.61, 23.0.218.11, 135.148.13.31, 23.56.99.17, 23.35.69.24, 54.154.154.192, 54.158.208.10, 172.67.142.245, 169.62.184.199, 13.227.37.127, 52.185.73.156, 104.18.32.137, 40.77.56.174, 54.230.202.80, 147.135.70.55, 104.18.7.59, 151.101.194.137, 23.0.217.63, 172.64.147.209, 104.18.43.90, 104.16.109.254, 23.203.40.205, 54.196.227.84, 3.166.118.119, 3.166.118.4, 18.160.181.49, 104.123.153.8, 192.168.122.5, 140.82.112.3, 23.0.216.233, 104.18.10.207, 3.166.116.59, 104.18.94.41, 34.117.188.166, 23.56.99.56, 18.160.102.19, 199.60.103.30, 54.230.202.42, 157.240.254.174, 40.119.249.228, 34.117.121.53, 172.64.144.166, 172.65.240.166, 13.227.37.12, 173.194.24.167, 54.230.202.62, 146.75.78.251, 54.145.199.147, 104.18.144.126, 23.220.209.21, 52.204.201.84, 104.18.34.146, 185.199.109.154, 141.101.90.98, 104.123.153.25, 23.223.149.146, 18.160.181.101, 146.75.76.134, 142.93.135.252, 141.193.213.21, 34.36.165.17, 104.123.153.19, 23.63.73.27, 172.65.198.159, 209.85.165.202, 34.149.128.2, 34.107.254.252, 3.229.240.58, 152.199.6.208, 150.171.27.10, 54.159.173.10, 142.251.33.170, 2.17.95.228, 3.233.80.70, 54.230.202.97, 23.56.99.41, 146.75.78.217, 104.18.35.13, 23.63.73.201, 13.227.37.27, 13.227.37.99, 3.166.118.85, 34.49.229.81, 3.166.118.118, 141.193.213.20, 172.217.165.10, 192.168.122.88, 23.43.193.209, 146.75.78.133, 3.166.118.68, 185.199.108.133, 18.160.181.69, 18.160.102.112, 18.160.181.117, 104.18.176.126, 3.213.9.86, 45.55.41.223, 185.199.110.133, 18.160.102.125, 104.18.20.31, 107.154.104.27, 34.149.100.209, 142.251.41.67, 18.160.102.28, 104.18.21.56, 142.251.41.35, 151.101.192.193, 13.227.37.126, 52.216.209.129, 142.250.98.84, 104.16.90.50, 142.251.33.162, 104.16.118.116, 100.26.87.64, 52.159.127.243, 172.67.218.119, 204.79.197.237, 3.166.118.34, 18.160.181.31, 142.251.32.78, 13.107.246.51, 185.199.109.133, 104.123.153.18, 54.230.202.23, 3.5.12.86, 52.20.136.23, 104.18.20.56, 172.64.148.232, 23.62.81.113, 18.160.181.107, 172.217.1.6, 142.251.41.74, 3.166.118.67, 104.244.42.3, 152.130.96.221, 199.232.98.219, 3.166.118.22, 172.217.165.22, 54.230.202.82, 208.83.242.49, 104.17.25.14, 108.175.50.164, 185.199.111.133, 23.223.149.168, 4.154.131.236, 104.244.42.195, 172.67.68.37, 146.75.76.193, 52.210.37.163, 204.79.197.203, 44.193.142.207, 104.18.30.176, 104.17.24.14, 142.251.41.42, 208.93.105.116, 104.26.9.12, 40.126.29.10, 3.5.25.99, 20.163.45.186, 172.65.202.201, 23.223.149.201, 172.217.165.4, 104.18.35.240, 210.239.64.251, 151.101.66.137, 3.237.175.195, 23.63.73.72, 104.18.86.42, 54.230.202.28, 13.227.37.63, 104.18.65.57, 208.82.237.225, 23.10.213.75, 104.18.11.213, 23.10.192.28, 104.18.90.62, 152.131.100.98, 146.75.76.84"),
            html.Li("Unique SSLv2 Destinations: 104.18.32.137, 20.163.45.186, 23.203.40.207, 18.160.181.129, 192.168.122.5, 23.203.40.205, 192.168.122.71, 192.168.122.12, 192.168.122.88, 35.186.224.9, 146.75.76.193, 142.251.41.46, 35.186.247.156, 23.215.126.34, 4.154.131.237, 4.154.131.236"),
        ]),
        html.H3('Non-encrypted Traffic:'),
        html.P("Total non-encrypted packets: 125191 (11.15% of total)"),
    ])

def create_traffic_patterns_layout():
    """
    Create the layout for the Traffic Patterns page.
    """
    return html.Div([
        html.H2('Traffic Patterns'),
        html.P(f"Peak traffic hour: 2024-10-02 16:00:00"),
        html.P(f"Packets in peak hour: 8008"),
        html.P(f"Bytes in peak hour: 6421206 bytes")
    ])


def create_ip_port_analysis_layout():
    """
    Create the layout for the IP & Port Analysis page, including updated information and plots.
    """
    # Data for source IPs
    source_ips = [
        ("192.168.122.88", 141073, 12.56),
        ("192.168.122.71", 127026, 11.31),
        ("192.168.122.5", 121325, 10.80),
        ("192.168.122.12", 85586, 7.62),
        ("185.199.111.133", 84374, 7.51),
        ("209.85.165.202", 79702, 7.10),
        ("146.75.41.140", 45763, 4.08),
        ("142.251.32.78", 36946, 3.29),
        ("142.251.41.72", 22321, 1.99),
        ("192.168.122.1", 18338, 1.63)
    ]

    # Data for destination IPs
    dest_ips = [
        ("192.168.122.5", 217854, 19.40),
        ("192.168.122.88", 193005, 17.19),
        ("192.168.122.71", 165173, 14.71),
        ("192.168.122.12", 124118, 11.05),
        ("209.85.165.202", 55030, 4.90),
        ("185.199.111.133", 47149, 4.20),
        ("142.251.32.78", 29031, 2.59),
        ("146.75.41.140", 28975, 2.58),
        ("192.168.122.1", 18536, 1.65),
        ("34.117.121.53", 8555, 0.76)
    ]

    # Data for TCP ports (updated to use packet counts instead of percentages)
    tcp_ports = [
        (443, 926458),
        (41250, 131485),
        (38010, 71003),
        (37998, 63729),
        (59378, 61692),
        (42089, 49995),
        (51954, 49995),
        (50897, 38722),
        (80, 26087),
        (50695, 19552)
    ]

    def create_bar_plot(data, title, y_axis_title):
        """Create a bar plot for the given data."""
        return dcc.Graph(
            figure={
                'data': [
                    go.Bar(
                        x=[str(item[0]) for item in data],
                        y=[item[1] for item in data],
                        text=[f"{item[1]} packets" for item in data],
                        textposition='auto',
                        hoverinfo='text',
                        marker_color='rgb(55, 83, 109)'
                    )
                ],
                'layout': go.Layout(
                    title=title,
                    xaxis={'title': 'IP Address / Port'},
                    yaxis={'title': y_axis_title},
                    margin={'l': 40, 'b': 40, 't': 40, 'r': 10},
                    hovermode='closest'
                )
            }
        )

    return html.Div([
        html.H2('IP & Port Analysis'),

        html.H3('Top 10 Source IPs:'),
        html.Ul([html.Li(f"{ip}: {packets} packets ({percentage:.2f}%)") for ip, packets, percentage in source_ips]),
        create_bar_plot([(ip, percentage) for ip, _, percentage in source_ips], 'Top 10 Source IPs', 'Percentage (%)'),

        html.H3('Top 10 Destination IPs:'),
        html.Ul([html.Li(f"{ip}: {packets} packets ({percentage:.2f}%)") for ip, packets, percentage in dest_ips]),
        create_bar_plot([(ip, percentage) for ip, _, percentage in dest_ips], 'Top 10 Destination IPs',
                        'Percentage (%)'),

        html.H3('Top 10 TCP Ports:'),
        html.Ul([html.Li(f"{port}: {packets} packets") for port, packets in tcp_ports]),
        #create_bar_plot(tcp_ports, 'Top 10 TCP Ports', 'Number of Packets')
    ])

def create_methodology_layout():
    """
    Create the layout for the Methodology page with a single column layout.
    """
    return html.Div([
        html.H2('Methodology'),
        html.H3('Data Collection Approach'),
        html.P([
            "Our approach focused on creating a realistic and controlled network environment ",
            "to capture diverse packet data. Instead of using pre-existing packet captures, ",
            "we opted to generate our own data to ensure relevance and maintain legal compliance."
        ]),
        html.H4('Virtual Environment Setup'),
        html.Ul([
            html.Li([
                html.Strong("Host Configuration: "),
                "We set up a GNU/Linux machine with libvirt, QEMU, virt-manager, and virsh for managing virtual machines."
            ]),
            html.Li([
                html.Strong("Virtual Machines: "),
                "Using CMU's GHOSTS program, we created:"
            ]),
            html.Ul([
                html.Li("Two 'NPC' machines: One Windows and one Debian GNU/Linux"),
                html.Li("A manually controlled Debian machine with FileZilla"),
                html.Li("An FTP server running vsFTP"),
                html.Li("A machine streaming YouTube videos")
            ]),
            html.Li([
                html.Strong("Management: "),
                "SSH was extensively used for VM management and file transfers."
            ])
        ]),
        html.H4('Data Generation'),
        html.P([
            "To generate a substantial and varied packet capture:"
        ]),
        html.Ul([
            html.Li("GHOSTS automated actions on the 'NPC' machines"),
            html.Li("We performed large unencrypted file transfers between the FTP server and the FileZilla client"),
            html.Li("Wireshark was connected to the virtual network adapter to capture packets")
        ]),
        html.P([
            "This setup yielded approximately 1.1 million packets (1.1 GB) in about 40 minutes."
        ]),
        html.H3('Tools and Technologies Used'),
        html.Ul([
            html.Li("Scapy: For packet manipulation and analysis"),
            html.Li("CMU GHOSTS: For automating virtual machine behavior"),
            html.Li("Virtual machine technologies:"),
            html.Ul([
                html.Li("QEMU: For hardware virtualization"),
                html.Li("Virt-manager: For VM management through a GUI"),
                html.Li("Virsh: For command-line VM management"),
                html.Li("GNU/Linux & Debian: As host and guest operating systems"),
                html.Li("vsFTP: For FTP server functionality"),
                html.Li("SSH: For secure remote management and file transfers")
            ])
        ]),
        html.H3('Python Script Methodology'),
        html.P([
            "Our Python script processes the PCAPNG file to analyze packets for various network ",
            "characteristics and potential security issues. The core of our analysis is the ",
            "process_pcapng function."
        ]),
        html.H4('process_pcapng Function'),
        html.P("This function performs the following tasks:"),
        html.Ul([
            html.Li("Reads the PCAPNG file and processes each packet"),
            html.Li("Analyzes various protocol layers (Ethernet, IP, TCP, UDP, ICMP, ARP)"),
            html.Li("Tracks packet counts, sizes, and other statistics for each protocol"),
            html.Li("Analyzes TCP flags and ports"),
            html.Li("Detects HTTP methods"),
            html.Li("Identifies QUIC packets using pyshark"),
            html.Li("Detects TLS usage and analyzes cipher suites"),
            html.Li("Identifies deprecated SSLv2 usage"),
            html.Li("Detects non-encrypted packets"),
            html.Li("Calculates various statistics and prepares a comprehensive summary")
        ]),
        html.H3('Key Supporting Functions'),
        html.H4('is_likely_encrypted Function'),
        html.P([
            "This function determines if a given network packet is likely to contain encrypted data. ",
            "It uses multiple heuristics to assess the likelihood of encryption:"
        ]),
        html.Ul([
            html.Li("Checks if the packet is using ports commonly associated with encrypted protocols"),
            html.Li("Looks for the presence of TLS/SSL layers"),
            html.Li("Searches for specific strings that might indicate encryption")
        ]),
        html.P([
            "The function considers common encrypted ports (443, 465, 993, 995, 8443) for both TCP and UDP protocols. ",
            "It also checks for TLS layers and specific strings indicative of TLS/SSL handshakes. ",
            "This approach provides a reasonable estimate of encryption, though it may not be 100% accurate in all cases."
        ]),

        html.H4('safe_get_ciphers Function'),
        html.P([
            "This function safely extracts cipher suites from a TLS ClientHello message in a network packet. ",
            "It's designed to handle potential errors, returning an empty list if cipher suites can't be extracted."
        ]),
        html.P([
            "The function performs the following steps:"
        ]),
        html.Ol([
            html.Li("Checks if the packet has a TLS layer"),
            html.Li("If present, it examines the TLS layer for messages"),
            html.Li("Identifies TLS ClientHello messages"),
            html.Li("Extracts and returns the cipher suites offered by the client")
        ]),
        html.P([
            "This function allows us to identify ",
            "the encryption methods proposed by clients during the TLS handshake process."
        ]),
        html.Ul([
            html.Li("is_likely_encrypted is used to identify non-encrypted packets"),
            html.Li("safe_get_ciphers is used to analyze TLS cipher suites, helping detect weak or unknown ciphers")
        ]),
        html.P([
            "By incorporating these functions, our analysis provides deeper insights into the security aspects of the network traffic, ",
            "including encryption usage and the strength of TLS implementations."
        ]),
        html.H3('Security Analysis Methodology'),
        html.H4('analyze_security_issues Function'),
        html.P([
            "This function performs a comprehensive analysis of network packets to identify potential security issues. ",
            "It focuses on several key areas of concern:"
        ]),
        html.Ul([
            html.Li("Use of deprecated and insecure SSLv2 protocol"),
            html.Li("Use of weak TLS ciphers"),
            html.Li("Use of unknown TLS ciphers"),
            html.Li("FTP authentication in cleartext")
        ]),
        html.P("The function processes the packets as follows:"),
        html.Ol([
            html.Li("Checks for the presence of SSLv2 packets"),
            html.Li("Identifies packets using weak TLS ciphers"),
            html.Li("Detects packets using unknown TLS ciphers"),
            html.Li("Searches for FTP authentication packets transmitted in cleartext")
        ]),
        html.H5("FTP Authentication Detection"),
        html.P([
            "The function specifically looks for FTP authentication packets, which are known ",
            "to transmit credentials in cleartext.  "
        ]),
        html.P("The FTP authentication detection process includes:"),
        html.Ul([
            html.Li("Using a regular expression to identify 'USER' and 'PASS' commands in packet payloads"),
            html.Li("Focusing on packets using the FTP control port (21)"),
            html.Li("Reporting details of up to 5 detected FTP authentication packets")
        ]),
        html.H5("Risk Assessment"),
        html.P([
            "The function also calculates percentages for a more detailed risk assessment, ",
            "providing a summary of the analyzed packets including:"
        ]),
        html.Ul([
            html.Li("Percentage of packets using SSLv2"),
            html.Li("Percentage of packets using weak ciphers"),
            html.Li("Percentage of packets using unknown ciphers"),
            html.Li("Number of FTP authentication packets detected")
        ]),
        html.P([
            "By incorporating this detailed security analysis, our methodology provides an assessment ",
            "of potential vulnerabilities and risks present in the captured network traffic"
        ]),
        html.H4('Key Steps in the Analysis'),
        html.Ol([
            html.Li("Read the PCAPNG file using Scapy's rdpcap function"),
            html.Li("Initialize various counters and data structures"),
            html.Li("Process each packet, extracting relevant information:"),
            html.Ul([
                html.Li("Analyze Ethernet, IP, TCP, UDP, ICMP, and ARP layers"),
                html.Li("Track protocol usage, IP sources/destinations, ports, and TCP flags"),
                html.Li("Detect HTTP methods in TCP payloads"),
                html.Li("Use pyshark to identify QUIC packets"),
                html.Li("Analyze TLS information, checking for weak or unknown ciphers"),
                html.Li("Identify deprecated SSLv2 usage"),
                html.Li("Detect non-encrypted packets")
            ]),
            html.Li("Create a pandas DataFrame with timestamped packet data"),
            html.Li("Calculate statistics such as QUIC packet percentage"),
            html.Li("Prepare a comprehensive summary of the analysis")
        ]),
        html.H4('Output'),
        html.P("The function returns a tuple containing:"),
        html.Ul([
            html.Li("A dictionary summarizing various aspects of the packet capture"),
            html.Li("A pandas DataFrame with processed data for each timestamp"),
            html.Li("List of all packets from the PCAPNG file"),
            html.Li("List of non-encrypted packets"),
            html.Li("List of SSLv2 packets"),
            html.Li("List of packets using weak ciphers"),
            html.Li("List of packets using unknown ciphers")
        ]),
        html.H4('Key Metrics and Analyses'),
        html.P("The function provides insights into:"),
        html.Ul([
            html.Li("Total packet count and unique IP sources/destinations"),
            html.Li("Protocol distribution"),
            html.Li("Top TCP and UDP ports"),
            html.Li("TCP flag distribution"),
            html.Li("Top IP sources and destinations"),
            html.Li("Packet size statistics"),
            html.Li("ARP operations and ICMP types"),
            html.Li("HTTP method usage"),
            html.Li("QUIC protocol usage percentage"),
            html.Li("Non-encrypted, SSLv2, and weak/unknown cipher packet counts")
        ]),
        html.H4('Preparing Data for Anomaly Detection'),
        html.P("""
            After initial analysis, we prepared our data for anomaly detection using the Isolation Forest algorithm. 
            Isolation Forest is an unsupervised machine learning algorithm that detects anomalies by isolating outliers 
            in the data. It's particularly effective for high-dimensional datasets and doesn't require labeled data.
        """),
        html.P("Our prepare_data_for_isolation_forest function does the following:"),
        html.Ol([
            html.Li("Aggregates data by minute to analyze trends over time."),
            html.Li("Calculates total packets and bytes for each time interval."),
            html.Li("Computes protocol ratios (TCP, UDP, ICMP, ARP) to identify unusual protocol usage."),
            html.Li("Determines the ratio of encrypted traffic to detect potential security issues."),
            html.Li("Calculates average bytes per packet to spot unusually large or small packets."),
            html.Li("Incorporates time-based features (hour, day of week) to account for normal traffic patterns."),
            html.Li("Adds features from the summary statistics, including:"),
            html.Ul([
                html.Li("QUIC protocol usage ratio"),
                html.Li("Non-encrypted, SSLv2, and weak/unknown cipher packet ratios"),
                html.Li("Packet size statistics (mean, median, min, max)"),
                html.Li("Top protocol ratios")
            ]),
            html.Li("Handles missing data and normalizes features for consistent scaling.")
        ]),
        html.P("""
            This comprehensive feature set allows the Isolation Forest algorithm to detect anomalies 
            across various aspects of network behavior, enhancing our ability to identify potential 
            security issues or unusual network activities.
        """),
        html.Li([
            html.Strong("Anomaly Detection: "),
            "We employ the Isolation Forest algorithm. ",
            "We set a contamination factor of 0.1, assuming approximately 10% of our data points could be anomalous."
        ]),
        html.Li([
            html.Strong("Analysis of Results: "),
            "We calculate summary statistics, comparing mean values of features for normal vs. anomalous data points. ",
            "This helps identify which features contribute most to the detection of anomalies."
        ])
    ])

def create_team_layout():
    return html.Div([
        dbc.Row([
            # Team Members Column
            dbc.Col([
                html.H2('Meet the Team', style={'fontSize': '36px', 'marginBottom': '30px'}),
                html.H3('Team Members', style={'fontSize': '28px', 'marginBottom': '20px'}),
                html.Ul([
                    html.Li([
                        html.Span('Orion Musselman - Project Manager & Network Analyst', style={'fontSize': '20px'}),
                        html.Br(),
                        html.Span('Email: ', style={'fontWeight': 'bold'}),
                        html.Span('musselmano@berea.edu', style={'fontSize': '18px'}),
                        html.Br(),
                        html.Span('GitHub: ', style={'fontWeight': 'bold'}),
                        html.A('KeinR', href='https://github.com/KeinR', target='_blank', style={'fontSize': '18px'})
                    ], style={'marginBottom': '20px'}),
                    html.Li([
                        html.Span('Nicholas Hamilton - Data Analyst & Python Developer', style={'fontSize': '20px'}),
                        html.Br(),
                        html.Span('Email: ', style={'fontWeight': 'bold'}),
                        html.Span('hamiltonn428@gmail.com', style={'fontSize': '18px'}),
                        html.Br(),
                        html.Span('Website: ', style={'fontWeight': 'bold'}),
                        html.A('nicholastreyhamilton.me', href='https://nicholastreyhamilton.me', target='_blank',
                               style={'fontSize': '18px'}),
                        html.Br(),
                        html.Span('GitHub: ', style={'fontWeight': 'bold'}),
                        html.A('HamiltonnBC', href='https://github.com/HamiltonnBC', target='_blank',
                               style={'fontSize': '18px'})
                    ], style={'marginBottom': '20px'})
                ], style={'listStyleType': 'none', 'padding': '0'}),
            ], width=4),

            # Sources Column
            dbc.Col([
                html.H2('Sources', style={'fontSize': '36px', 'marginBottom': '30px'}),
                html.Div([
                    html.P(html.A("10 minutes to pandas", href="https://pandas.pydata.org/docs/user_guide/10min.html",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Analyzing packet captures with python",
                                  href="https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Castillo, D. (2023, March 17). "),
                            html.A("Develop data visualization interfaces in python with dash",
                                   href="https://realpython.com/python-dash/", target="_blank")],
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Dash in 20 minutes", href="https://dash.plotly.com/tutorial", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Emagined security: Cybersecurity Solutions", href="https://www.emagined.com/",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Ferdous, T. (2023, August 1). "),
                            html.A("A practical guide to regular expressions – learn regex with real life examples",
                                   href="https://www.freecodecamp.org/news/practical-regex-guide-with-real-life-examples/",
                                   target="_blank")], style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("How to extract an SSL/TLS message using Scapy and python?",
                                  href="https://stackoverflow.com/questions/51423507/how-to-extract-an-ssl-tls-message-using-scapy-and-python",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Intect, T. (2024, August 8). "), html.A("Python for Network Traffic Analysis",
                                                                               href="https://medium.com/@info_82002/python-for-network-traffic-analysis-2386b8d6144e",
                                                                               target="_blank")],
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Jaiswal, S. (2020, June 10). "),
                            html.A("Python regular expression tutorial with Re Library examples",
                                   href="https://www.datacamp.com/community/tutorials/python-regular-expression-tutorial",
                                   target="_blank")], style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Jun, C. M. (2024, March 18). "),
                            html.A("Viewing a list of TLS/SSL ciphers offered by clients",
                                   href="https://www.baeldung.com/linux/list-tls-ssl-ciphers-clients",
                                   target="_blank")], style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A(
                        "KimiNewt/pyshark: Python wrapper for tshark, allowing python packet parsing using Wireshark dissectors",
                        href="https://github.com/KimiNewt/pyshark/", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Pandas.dataframe.resample",
                                  href="https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Scapy.layers.tls.handshake",
                                  href="https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.handshake.html",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Security/Cipher Suites", href="https://wiki.mozilla.org/Security/Cipher_Suites",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Standards", href="https://standards-oui.ieee.org/oui/oui.txt", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Transport Layer Security (TLS) parameters",
                                  href="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Network packet analysis with Scapy: A beginner's guide",
                                  href="https://codewithgolu.com/python/network-packet-analysis-with-scapy-a-beginner-s-guide/",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("Welcome to Scapy's documentation!",
                                  href="https://scapy.readthedocs.io/en/latest/index.html", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("What cryptographic algorithms are not considered secure?",
                                  href="https://security.stackexchange.com/questions/78/what-cryptographic-algorithms-are-not-considered-secure",
                                  target="_blank"), style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P([html.Span("Willems, K. (2022, December 12). "),
                            html.A("Pandas tutorial: DataFrames in python",
                                   href="https://www.datacamp.com/tutorial/pandas-tutorial-dataframe-python",
                                   target="_blank")], style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A(
                        "PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT: DETAILED SPECIFICATIONS",
                        href="https://www.ietf.org/rfc/rfc1002.txt", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("YouTube", href="https://www.youtube.com/watch?v=Hc9_-ncr4nU", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'}),
                    html.P(html.A("YouTube", href="https://www.youtube.com/watch?v=hSPmj7mK6ng", target="_blank"),
                           style={'fontSize': '16px', 'marginBottom': '10px'})
                ], style={'height': '500px', 'overflowY': 'scroll'})
            ], width=4),

            # PDF Column
            dbc.Col([
                html.Iframe(
                    src='assets/450midtermSources.pdf',
                    style={
                        'width': '100%',
                        'height': '500px',  # Adjust this value to make it smaller or larger
                        'border': 'none',
                        'marginTop': '66px'  # Align with the "Sources" heading
                    }
                )
            ], width=6)
        ])
    ], style={'padding': '20px'})

def create_conclusion_layout():
    """
    Create the layout for the Security Recommendations and Conclusion page.
    """
    return html.Div([
        html.H2('Security Recommendations and Conclusion'),

        html.H3('General Security Issues:'),
        html.Ul([
            html.Li("Use of Deprecated Protocols: 6,911 packets using the insecure SSLv2 protocol were detected."),
            html.Li("Cleartext Data Transmission: 19 FTP authentication packets were detected in cleartext."),
            html.Li(
                "Weak Encryption Algorithms: Instances of weak encryption algorithms such as DES, RC4, MD5, SHA-1, and RSA with small key sizes were identified.")
        ]),

        html.H3('Recommendations for Students:'),
        html.Ul([
            html.Li(
                "Use a VPN: When connecting to public or university Wi-Fi networks, use a reputable VPN service for added encryption."),
            html.Li(
                "Keep Systems Updated: Ensure your operating system and applications are up-to-date with the latest security patches."),
            html.Li(
                "Consider Open-Source Alternatives: If technically inclined, consider using open-source operating systems like Linux distributions for greater transparency and control over system security.")
        ]),

        html.H3('Recommendations for Network Administrators:'),
        html.Ul([
            html.Li(
                "Disable Insecure Protocols: Immediately disable SSLv2 and other deprecated protocols across all systems and applications."),
            html.Li(
                "Enforce Encryption: Implement policies to ensure all sensitive data, especially authentication credentials, are transmitted using strong encryption."),
            html.Li(
                "Update Encryption Algorithms: Replace weak encryption algorithms with modern, secure alternatives such as AES, ChaCha20, SHA-256, and RSA with at least 2048-bit keys."),
            html.Li(
                "Regular Security Audits: Conduct frequent security audits of network traffic, system configurations, and application settings to identify and address potential vulnerabilities.")
        ])
    ])


def create_anomaly_detection_layout():
    """
    Create the layout for the Anomaly Detection page in the Dash application.
    """
    # Load the CSV data
    df = pd.read_csv('assets/anomaly_summary.csv')

    # Create a table from the CSV data
    table = dbc.Table.from_dataframe(df, striped=True, bordered=True, hover=True)

    # Function to encode images
    def encode_image(image_file):

        with open(image_file, 'rb') as f:
            encoded = b64encode(f.read()).decode('ascii')
        return f'data:image/png;base64,{encoded}'

    # Encode images
    correlation_heatmap = encode_image('assets/correlation_heatmap.png')
    anomalies_scatter = encode_image('assets/anomalies_scatter_plot.png')
    anomaly_scores = encode_image('assets/anomaly_scores_distribution.png')

    return html.Div([
        html.H2('Anomaly Detection', className='mb-4'),

        dbc.Card([
            dbc.CardHeader(html.H3("Isolation Forest Algorithm", className="card-title")),
            dbc.CardBody([
                html.P([
                    "The Isolation Forest algorithm is an unsupervised machine learning technique used for anomaly detection. ",
                    "It operates on the principle that anomalies are rare and different, making them easier to isolate in a dataset ",
                    "compared to normal points. The algorithm creates a forest of random decision trees (isolation trees) and ",
                    "measures how quickly each data point can be isolated. Anomalies typically require fewer splits to be isolated, ",
                    "resulting in shorter path lengths through the trees."
                ]),
                html.P("Key advantages of the Isolation Forest algorithm include:"),
                html.Ul([
                    html.Li("Efficiency in handling high-dimensional datasets"),
                    html.Li("Ability to detect anomalies without requiring a labeled training set"),
                    html.Li("Robustness against irrelevant features"),
                    html.Li("Scalability for large datasets")
                ])
            ])
        ], className='mb-4'),

        dbc.Card([
            dbc.CardHeader(html.H3("Anomaly Detection Results", className="card-title")),
            dbc.CardBody([
                html.H4("Summary Statistics"),
                table,
                html.P("This table shows the mean values for normal and anomalous data points, as well as the difference between them for each feature."),
                html.H4("Visualizations"),
                html.Div([
                    html.Img(src=correlation_heatmap, style={'width': '100%', 'max-width': '800px'}),
                    html.P("This heatmap shows the correlation between different features in the dataset. Stronger correlations (positive or negative) are represented by darker colors."),
                ], className='mb-4'),
                html.Div([
                    html.Img(src=anomalies_scatter, style={'width': '100%', 'max-width': '800px'}),
                    html.P("This scatter plot shows the distribution of normal (blue) and anomalous (red) data points based on the two most important features."),
                ], className='mb-4'),
                html.Div([
                    html.Img(src=anomaly_scores, style={'width': '100%', 'max-width': '800px'}),
                    html.P("This histogram shows the distribution of anomaly scores. Normal data points are shown in blue, while anomalous points are in red."),
                ], className='mb-4'),
            ])
        ], className='mb-4'),

        dbc.Card([
            dbc.CardHeader(html.H3("Explanation of Results", className="card-title")),
            dbc.CardBody([
                html.P([
                    "The Isolation Forest algorithm has been applied to our network traffic data to identify potential anomalies. ",
                    "Here's how to interpret the results:"
                ]),
                html.Ul([
                    html.Li("Data points classified as anomalies are those that were easiest to isolate in the random trees."),
                    html.Li("The anomaly score represents how different a data point is from the norm. Lower (more negative) scores indicate stronger anomalies."),
                    html.Li("Visualizations show anomalies as outliers or clusters separate from the main body of data.")
                ]),
                html.P([
                    "Based on the summary statistics, we can observe that:"
                ]),
                html.Ul([
                    html.Li("Anomalous data points tend to have significantly higher total packets and total bytes compared to normal data."),
                    html.Li("The bytes per packet for anomalous data is also considerably higher than normal."),
                    html.Li("Anomalous data shows a lower TCP ratio but higher ICMP and ARP ratios compared to normal data."),
                    html.Li("The UDP ratio shows a slight decrease in anomalous data compared to normal data.")
                ]),
                html.P([
                    "These differences suggest that the anomalies detected might be related to unusual network behavior, ",
                    "such as potential DDoS attacks (high packet and byte counts), unusual protocol usage, or network scanning activities. ",
                    "However, further investigation is needed to confirm the nature and potential impact of these anomalies on network security or performance."
                ]),
                html.P([
                    "It's important to note that not all detected anomalies necessarily represent threats or issues. ",
                    "They are points of interest that warrant further investigation to understand their nature and potential impact on network security or performance."
                ])
            ])
        ])
    ])

def main():
    """
    Main function to run the Dash app.
    """
    app = create_app()
    app.run_server(debug=True)

if __name__ == '__main__':
    main()