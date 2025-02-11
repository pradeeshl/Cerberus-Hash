from flask import Flask, request, render_template
import os
from pcap_parser import parse_pcap
from yara_scanner import scan_with_yara
import scapy.all as scapy  # Import scapy to count packets

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_packets_in_pcap(filepath):
    """Returns total number of packets in the PCAP file"""
    packets = scapy.rdpcap(filepath)
    return len(packets)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file and allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            packets = parse_pcap(filepath)
            malware_matches = scan_with_yara(packets)
            
            # Count total packets
            total_packets = count_packets_in_pcap(filepath)

            return render_template('results.html', matches=malware_matches, filename=filename, total_packets=total_packets)
    
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
